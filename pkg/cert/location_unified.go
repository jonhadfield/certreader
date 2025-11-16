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
}

func (l Location) Name() string {
	return nameFormat(l.Path, l.TLSVersion)
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

	// sort locations by first certificate (they have been already sorted)
	slices.SortFunc(out, func(a, b Location) int {
		if len(a.Certificates) == 0 && len(b.Certificates) == 0 {
			return 0
		}
		if len(a.Certificates) == 0 {
			return 1
		}
		if len(b.Certificates) == 0 {
			return -1
		}
		return a.Certificates[0].x509Certificate.NotAfter.Compare(b.Certificates[0].x509Certificate.NotAfter)
	})
	return out
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

func (l Location) Chains() ([]Certificates, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	// we are not verifying time and dns, because we want to work with -insecure flag as well
	// just to see what local chains are used for verification
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range l.Certificates {
		// do not just use index (index 0 leaf/end-entity, rest intermediate) like connection,
		// because we can deal with certs from a bundle file
		if cert.Type() == "intermediate" {
			opts.Intermediates.AddCert(cert.x509Certificate)
		}
	}

	var verifiedChains []Certificates
	for _, cert := range l.Certificates {
		if cert.Type() == "end-entity" {
			chains, err := cert.x509Certificate.Verify(opts)
			if err != nil {
				return nil, err
			}
			for _, chain := range chains {
				verifiedChains = append(verifiedChains, FromX509Certificates(chain))
			}
		}
	}
	return verifiedChains, nil
}

// LoadFromNetwork loads certificates from a network address
func LoadFromNetwork(addr string, serverName string, tlsSkipVerify bool) Location {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: tlsDialTimeout}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: tlsSkipVerify,
		ServerName:         serverName,
	})
	if err != nil {
		slog.Error(fmt.Sprintf("load certificate from network %s: %v", addr, err.Error()))
		return Location{Path: addr, Error: err}
	}

	connectionState := conn.ConnectionState()
	x509Certificates := connectionState.PeerCertificates

	return Location{
		TLSVersion:   conn.ConnectionState().Version,
		Path:         addr,
		ContentType:  ContentTypeCertificate,
		Certificates: FromX509Certificates(x509Certificates),
	}
}

// LoadFromFile loads certificates or CSRs from a file with auto-detection
func LoadFromFile(fileName string, password string) Location {
	b, err := os.ReadFile(fileName)
	if err != nil {
		slog.Error(fmt.Sprintf("load from file %s: %v", fileName, err.Error()))
		return Location{Path: fileName, Error: err}
	}
	return loadContent(fileName, b, password)
}

// LoadFromStdin loads certificates or CSRs from stdin with auto-detection
func LoadFromStdin(password string) Location {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		slog.Error(fmt.Sprintf("load from stdin: %v", err.Error()))
		return Location{Path: "stdin", Error: err}
	}
	return loadContent("stdin", content, password)
}

// LoadFromClipboard loads certificates or CSRs from clipboard with auto-detection
func LoadFromClipboard(password string) Location {
	if err := clipboard.Init(); err != nil {
		slog.Error(fmt.Sprintf("load from clipboard: %v", err.Error()))
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
		slog.Error(fmt.Sprintf("parse %s: %v", source, certErr.Error()))
		return Location{Path: source, Error: certErr}
	}

	return Location{Path: source, Error: csrErr}
}
