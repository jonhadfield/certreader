package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.design/x/clipboard"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"
)

// ContentType indicates whether content is a certificate or CSR
type ContentType int

const (
	ContentTypeCertificate ContentType = iota
	ContentTypeCSR
	ContentTypeMixed
)

// Location represents a source of certificates or CSRs
type Location struct {
	TLSVersion   uint16 // only applicable for network certificates
	Path         string
	Error        error
	ContentType  ContentType
	Certificates Certificates
	CSRs         CSRs
	// OCSPStaple is the raw OCSP response the TLS server stapled to the
	// handshake, if any. Only applicable for network certificates.
	OCSPStaple []byte
	// ServerName is the name verification should use, when it was overridden
	// rather than taken from the address.
	ServerName string
	// Revocation is the outcome of a revocation check, populated only when one
	// was requested.
	Revocation *RevocationStatus
	// Verification is the outcome of checking against the system trust store,
	// populated only when one was requested.
	Verification *VerificationResult
}

func (l Location) Name() string {
	return nameFormat(l.Path, l.TLSVersion)
}

// TLSVersionName is the negotiated TLS version as a plain name, empty for
// locations that did not involve a handshake. Unlike the display formatting it
// carries no commentary, so it is safe for machines to compare.
func (l Location) TLSVersionName() string {
	switch l.TLSVersion {
	case 0:
		return ""
	//nolint:staticcheck // deprecated, but a server may still offer it and the point is to say so
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", l.TLSVersion)
	}
}

func (l Location) IsCSR() bool {
	return l.ContentType == ContentTypeCSR
}

func (l Location) IsCertificate() bool {
	return l.ContentType == ContentTypeCertificate
}

func (l Location) IsMixed() bool {
	return l.ContentType == ContentTypeMixed
}

type Locations []Location

func (l Locations) RemoveExpired() Locations {
	var out Locations
	for i := range l {
		out = append(out, l[i].RemoveExpired())
	}
	return out
}

func (l Locations) RemoveDuplicates() Locations {
	var out Locations
	for i := range l {
		out = append(out, l[i].RemoveDuplicates())
	}
	return out
}

func (l Locations) SubjectLike(subject string) Locations {
	var out Locations
	for i := range l {
		out = append(out, l[i].SubjectLike(subject))
	}
	return out
}

func (l Locations) IssuerLike(issuer string) Locations {
	var out Locations
	for i := range l {
		out = append(out, l[i].IssuerLike(issuer))
	}
	return out
}

func (l Locations) SortByExpiry() Locations {
	var out Locations
	for i := range l {
		out = append(out, l[i].SortByExpiry())
	}

	// sort locations by the certificate that expires first, which is the
	// earliest date the location needs attention
	slices.SortStableFunc(out, func(a, b Location) int {
		aTime, aOK := a.earliestExpiry()
		bTime, bOK := b.earliestExpiry()
		switch {
		case !aOK && !bOK:
			return 0
		case !aOK:
			return 1
		case !bOK:
			return -1
		}
		return aTime.Compare(bTime)
	})
	return out
}

// earliestExpiry reports the earliest expiry among the location's
// certificates, and whether any of them had one to read. A location holding
// nothing but blocks that failed to parse has no expiry, and neither does an
// empty one.
func (l Location) earliestExpiry() (time.Time, bool) {
	var (
		earliest time.Time
		found    bool
	)
	for i := range l.Certificates {
		expiry, ok := l.Certificates[i].expiry()
		if !ok {
			continue
		}
		if !found || expiry.Before(earliest) {
			earliest, found = expiry, true
		}
	}
	return earliest, found
}

func (l Location) RemoveExpired() Location {
	l.Certificates = l.Certificates.RemoveExpired()
	return l
}

func (l Location) RemoveDuplicates() Location {
	l.Certificates = l.Certificates.RemoveDuplicates()
	return l
}

func (l Location) SubjectLike(subject string) Location {
	l.Certificates = l.Certificates.SubjectLike(subject)
	return l
}

func (l Location) IssuerLike(issuer string) Location {
	l.Certificates = l.Certificates.IssuerLike(issuer)
	return l
}

func (l Location) SortByExpiry() Location {
	l.Certificates = l.Certificates.SortByExpiry()
	return l
}

// Chains returns the trusted chains that can be built for this location. It is
// the display half of verification: the same chain building Verify judges,
// without the hostname check or the diagnosis.
func (l Location) Chains() ([]Certificates, error) {
	return l.buildChains()
}

// HasOCSPStaple reports whether the server stapled an OCSP response to the
// handshake. It is always false for non-network locations.
func (l Location) HasOCSPStaple() bool {
	return len(l.OCSPStaple) > 0
}

// StapledOCSP parses the OCSP response the server stapled to the handshake,
// verifying it against the issuer certificate when one was presented. It
// returns ErrNoOCSPStaple when nothing was stapled.
func (l Location) StapledOCSP() (*StapledOCSP, error) {
	leaf, issuer := l.leafAndIssuer()
	return ParseStapledOCSP(l.OCSPStaple, leaf, issuer)
}

// leafAndIssuer returns the end-entity certificate a staple would cover and the
// presented certificate that signed it. Either may be nil, because filtering
// flags can remove certificates from the location before it is printed.
func (l Location) leafAndIssuer() (leaf, issuer *x509.Certificate) {
	for i := range l.Certificates {
		candidate := l.Certificates[i].x509Certificate
		if candidate == nil || l.Certificates[i].Error() != nil {
			continue
		}
		if l.Certificates[i].Type() == "end-entity" {
			leaf = candidate
			break
		}
	}
	if leaf == nil {
		return nil, nil
	}

	for i := range l.Certificates {
		candidate := l.Certificates[i].x509Certificate
		if candidate == nil || candidate.Equal(leaf) {
			continue
		}
		if leaf.CheckSignatureFrom(candidate) == nil {
			return leaf, candidate
		}
	}
	return leaf, nil
}

// NetworkOptions configures how a network location is read. The zero value is
// usable and applies the defaults.
type NetworkOptions struct {
	// ServerName overrides the name verified against the certificate, and sent
	// as SNI, which is otherwise taken from the address.
	ServerName string
	// InsecureSkipVerify accepts a certificate that does not verify.
	InsecureSkipVerify bool
	// StartTLS upgrades a plaintext connection rather than handshaking
	// immediately.
	StartTLS StartTLSProtocol
	// Timeout bounds the connection, and for a starttls protocol the
	// negotiation and handshake together. Zero selects the default.
	Timeout time.Duration
	// Logger traces the connection, at debug level. Nil discards it.
	Logger *slog.Logger
}

// log is the caller's logger, or one that keeps nothing.
func (o NetworkOptions) log() *slog.Logger {
	if o.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return o.Logger
}

func (o NetworkOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return tlsDialTimeout
}

// LoadFromNetwork loads certificates from a network address. When the options
// name a starttls protocol the connection begins in plaintext and is upgraded,
// rather than handshaking immediately.
func LoadFromNetwork(addr string, opts NetworkOptions) Location {

	config := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify,
		ServerName:         opts.ServerName,
	}

	started := time.Now()
	opts.log().Debug("connecting",
		slog.String("address", addr),
		slog.String("starttls", string(opts.StartTLS)),
		slog.Duration("timeout", opts.timeout()),
		slog.String("server_name", config.ServerName))

	var conn *tls.Conn
	var err error
	if opts.StartTLS == StartTLSNone {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: opts.timeout()}, "tcp", addr, config)
	} else {
		conn, err = dialStartTLS(addr, config, opts.StartTLS, opts.timeout())
	}
	if err != nil {
		opts.log().Debug("connection failed", slog.String("address", addr), slog.Duration("after", time.Since(started)), slog.Any("err", err))
		return Location{Path: addr, Error: err}
	}

	connectionState := conn.ConnectionState()
	x509Certificates := connectionState.PeerCertificates

	opts.log().Debug("connected",
		slog.String("address", addr),
		slog.Duration("after", time.Since(started)),
		slog.String("tls", tlsFormat(connectionState.Version)),
		slog.Int("certificates", len(x509Certificates)),
		slog.Bool("stapled_ocsp", len(connectionState.OCSPResponse) > 0))

	return Location{
		TLSVersion:   conn.ConnectionState().Version,
		Path:         addr,
		ContentType:  ContentTypeCertificate,
		Certificates: FromX509Certificates(x509Certificates),
		OCSPStaple:   connectionState.OCSPResponse,
		ServerName:   opts.ServerName,
	}
}

// dialStartTLS connects in plaintext, asks the server to begin TLS, and then
// completes the handshake over the same connection.
func dialStartTLS(addr string, config *tls.Config, protocol StartTLSProtocol, timeout time.Duration) (*tls.Conn, error) {

	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	// one budget for the negotiation and the handshake, so a server that
	// answers slowly cannot hang the whole run
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = raw.Close()
		return nil, err
	}

	if err := negotiateStartTLS(raw, protocol); err != nil {
		_ = raw.Close()
		return nil, err
	}

	// tls.Dial infers this from the address, tls.Client does not
	if config.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			config.ServerName = host
		}
	}

	conn := tls.Client(raw, config)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// LoadFromFile loads certificates or CSRs from a file with auto-detection
func LoadFromFile(fileName string, password string) Location {
	b, err := os.ReadFile(fileName)
	if err != nil {
		return Location{Path: fileName, Error: err}
	}
	return loadContent(fileName, b, password)
}

// LoadFromStdin loads certificates or CSRs from stdin with auto-detection
func LoadFromStdin(password string) Location {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return Location{Path: "stdin", Error: err}
	}
	return loadContent("stdin", content, password)
}

// LoadFromClipboard loads certificates or CSRs from clipboard with auto-detection
func LoadFromClipboard(password string) Location {
	if err := clipboard.Init(); err != nil {
		return Location{Path: "clipboard", Error: err}
	}

	content := clipboard.Read(clipboard.FmtText)
	if content == nil {
		return Location{Path: "clipboard", Error: errors.New("clipboard is empty")}
	}
	return loadContent("clipboard", content, password)
}

// loadContent auto-detects and loads either certificates or CSRs
func loadContent(source string, data []byte, password string) Location {
	trimmed := bytes.TrimSpace(data)

	// Check if it's a CSR first by looking for CSR PEM block type
	if bytes.Contains(trimmed, []byte("BEGIN CERTIFICATE REQUEST")) ||
		bytes.Contains(trimmed, []byte("BEGIN NEW CERTIFICATE REQUEST")) {
		csrs, csrErr := FromCSRBytes(trimmed)
		if csrErr == nil && len(csrs) > 0 {
			return Location{
				Path:        source,
				ContentType: ContentTypeCSR,
				CSRs:        csrs,
			}
		}
	}

	// Try to load as certificates
	certificates, certErr := FromBytes(trimmed, password)
	if certErr == nil && len(certificates) > 0 {
		return Location{
			Path:         source,
			ContentType:  ContentTypeCertificate,
			Certificates: certificates,
		}
	}

	// Fallback: try CSRs if certificates failed and we didn't check CSRs yet
	csrs, csrErr := FromCSRBytes(trimmed)
	if csrErr == nil && len(csrs) > 0 {
		return Location{
			Path:        source,
			ContentType: ContentTypeCSR,
			CSRs:        csrs,
		}
	}

	// Handle password errors specially
	var passwordErr *PasswordRequiredError
	if errors.As(certErr, &passwordErr) {
		pwdSource := PasswordSourceFile
		switch source {
		case "stdin":
			pwdSource = PasswordSourceStdin
		case "clipboard":
			pwdSource = PasswordSourceClipboard
		}
		passwordErr.SetSource(pwdSource)
		return Location{Path: source, Error: passwordErr}
	}

	// If both failed, return certificate error as it's more common
	if certErr != nil {
		return Location{Path: source, Error: certErr}
	}

	return Location{Path: source, Error: csrErr}
}

const tlsDialTimeout = 5 * time.Second

func nameFormat(name string, tlsVersion uint16) string {

	if tlsVersion == 0 {
		return name
	}
	return fmt.Sprintf("%s %s", name, tlsFormat(tlsVersion))
}

func tlsFormat(tlsVersion uint16) string {

	switch tlsVersion {
	case 0:
		return ""
	//nolint:staticcheck // deprecated, but a server may still offer it and the point is to say so
	case tls.VersionSSL30:
		return "SSLv3 - Deprecated!"
	case tls.VersionTLS10:
		return "TLS 1.0 - Deprecated!"
	case tls.VersionTLS11:
		return "TLS 1.1 - Deprecated!"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS Version %d (unknown)", tlsVersion)
	}
}
