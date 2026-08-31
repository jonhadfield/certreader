// Package cert reads certificates, certificate requests and the chains a
// server presents, from files, network addresses and stdin, and reports what
// they say: how they are put together, whether they verify, whether they have
// been revoked, and what about them is worth drawing attention to.
package cert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const certificateBlockType = "CERTIFICATE"

var (
	errNoPEMBlock          = errors.New("cannot find any PEM block")
	errNoCertificate       = errors.New("no certificate")
	errNoCertificateReq    = errors.New("no certificate request")
	ErrPFXPasswordRequired = errors.New("pkcs12: password required")
)

type PasswordSource int

const (
	PasswordSourceUnknown PasswordSource = iota
	PasswordSourceFile
	PasswordSourceClipboard
	PasswordSourceStdin
)

type PasswordRequiredError struct {
	data     []byte
	provided bool
	source   PasswordSource
}

func newPasswordRequiredError(data []byte, provided bool) *PasswordRequiredError {
	return &PasswordRequiredError{
		data:     append([]byte(nil), data...),
		provided: provided,
	}
}

func (e *PasswordRequiredError) Error() string {
	if e == nil {
		return ErrPFXPasswordRequired.Error()
	}
	if e.provided {
		return "pkcs12: password incorrect (retry or use --pfx-password)"
	}
	return "pkcs12: password required (supply via --pfx-password)"
}

func (e *PasswordRequiredError) Unwrap() error { return ErrPFXPasswordRequired }

func (e *PasswordRequiredError) Data() []byte {
	if e == nil {
		return nil
	}
	return e.data
}

func (e *PasswordRequiredError) Provided() bool {
	if e == nil {
		return false
	}
	return e.provided
}

func (e *PasswordRequiredError) Source() PasswordSource {
	if e == nil {
		return PasswordSourceUnknown
	}
	return e.source
}

func (e *PasswordRequiredError) SetSource(source PasswordSource) {
	if e == nil || source == PasswordSourceUnknown {
		return
	}
	if e.source == PasswordSourceUnknown {
		e.source = source
	}
}

var (
	// order is important!
	keyUsages = []string{
		"Digital Signature",
		"Content Commitment",
		"Key Encipherment",
		"Data Encipherment",
		"Key Agreement",
		"Cert Sign",
		"CRL Sign",
		"Encipher Only",
		"Decipher Only",
	}
	// order is important!
	extKeyUsages = []string{
		"Any",
		"Server Auth",
		"Client Auth",
		"Code Signing",
		"Email Protection",
		"IPSEC End System",
		"IPSEC Tunnel",
		"IPSEC User",
		"Time Stamping",
		"OCSP Signing",
		"Microsoft Server Gated Crypto",
		"Netscape Server Gated Crypto",
		"Microsoft Commercial Code Signing",
		"Microsoft Kernel Code Signing",
	}
)

type Certificates []Certificate

func (c Certificates) RemoveExpired() Certificates {
	var out Certificates
	for i := range c {
		if !c[i].IsExpired() {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) RemoveDuplicates() Certificates {
	var out Certificates
	savedSet := map[string]struct{}{}
	for i := range c {
		stringPem := string(c[i].ToPEM())
		if _, ok := savedSet[stringPem]; !ok {
			savedSet[stringPem] = struct{}{}
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) SubjectLike(subject string) Certificates {
	var out Certificates
	for i := range c {
		if strings.Contains(c[i].SubjectString(), subject) {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) IssuerLike(issuer string) Certificates {
	var out Certificates
	for i := range c {
		// A block that did not parse has no issuer, so it cannot match, and
		// filtering drops it as it does any other certificate that does not
		// match. SubjectLike already behaves this way: the error text it
		// compares against rarely contains what is being searched for.
		if c[i].Error() != nil {
			continue
		}
		if strings.Contains(c[i].x509Certificate.Issuer.String(), issuer) {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) SortByExpiry() Certificates {
	slices.SortStableFunc(c, compareExpiry)
	return c
}

// compareExpiry orders certificates by expiry date, putting those whose expiry
// cannot be read after those whose can.
func compareExpiry(a, b Certificate) int {
	aTime, aOK := a.expiry()
	bTime, bOK := b.expiry()
	switch {
	case !aOK && !bOK:
		return 0
	case !aOK:
		return 1
	case !bOK:
		return -1
	}
	return aTime.Compare(bTime)
}

type Certificate struct {
	// position of certificate in the chain, starts with 1
	position        int
	x509Certificate *x509.Certificate
	err             error
}

func FromX509Certificates(cs []*x509.Certificate) Certificates {

	var certificates Certificates
	for i, c := range cs {
		certificates = append(certificates, Certificate{position: i + 1, x509Certificate: c})
	}
	return certificates
}

// FromBytes converts raw certificate bytes to certificate, if the supplied data is cert bundle (or chain)
// all the certificates will be returned. Supports PEM, DER, and PKCS12 formats.
func FromBytes(data []byte, password string) (Certificates, error) {

	// PEM is text, so surrounding whitespace is insignificant. DER and PKCS12
	// are binary and must be passed through untouched: their last byte is as
	// likely as any other to be 0x0a or 0x20, and trimming it truncates the
	// file into a parse error.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errNoPEMBlock
	}

	// Try PEM first
	certificates, err := fromPEMBytes(trimmed)
	if err == nil {
		return certificates, nil
	}
	if !errors.Is(err, errNoPEMBlock) {
		return nil, err
	}

	// Try DER format
	certificates, err = fromDERBytes(data)
	if err == nil {
		return certificates, nil
	}

	// Try PKCS12
	return fromPKCS12Bytes(data, password)
}

func fromPEMBytes(data []byte) (Certificates, error) {

	var (
		block        *pem.Block
		certificates Certificates
		idx          int
	)
	for {
		idx++
		block, data = pem.Decode(data)
		if block == nil {
			if len(certificates) == 0 {
				return nil, errNoPEMBlock
			}
			return certificates, nil
		}
		certificates = append(certificates, fromPemBlock(idx, block))
		if len(data) == 0 {
			return certificates, nil
		}
	}
}

func fromDERBytes(data []byte) (Certificates, error) {
	// Try to parse as DER-encoded certificate
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("invalid DER certificate: %w", err)
	}

	return Certificates{
		Certificate{position: 1, x509Certificate: certificate},
	}, nil
}

func fromPKCS12Bytes(data []byte, password string) (Certificates, error) {
	retryData := append([]byte(nil), data...)
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, newPasswordRequiredError(retryData, password != "")
		}
		return decodePKCS12TrustStore(retryData, password, err)
	}

	var x509Certs []*x509.Certificate
	if certificate != nil {
		x509Certs = append(x509Certs, certificate)
	}
	x509Certs = append(x509Certs, caCerts...)
	if len(x509Certs) == 0 {
		return decodePKCS12TrustStore(retryData, password, errors.New("pkcs12: no certificates found"))
	}

	_ = privateKey // keep to document that private keys are intentionally ignored
	return FromX509Certificates(x509Certs), nil
}

func decodePKCS12TrustStore(data []byte, password string, originalErr error) (Certificates, error) {
	certs, err := pkcs12.DecodeTrustStore(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, newPasswordRequiredError(data, password != "")
		}
		return nil, originalErr
	}
	if len(certs) == 0 {
		return nil, errors.New("pkcs12: no certificates found")
	}
	return FromX509Certificates(certs), nil
}

func fromPemBlock(position int, block *pem.Block) Certificate {

	if block.Type != certificateBlockType {
		return Certificate{position: position, err: fmt.Errorf("cannot parse %s block", block.Type)}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{position: position, err: err}
	}
	return Certificate{position: position, x509Certificate: certificate}
}

// expiry reports when the certificate expires, and whether there is a date to
// report at all. A block that did not parse has no expiry, and reaching for
// one dereferences a certificate that was never built.
func (c Certificate) expiry() (time.Time, bool) {
	if c.Error() != nil {
		return time.Time{}, false
	}
	return c.x509Certificate.NotAfter, true
}

func (c Certificate) IsExpired() bool {

	if c.Error() != nil {
		return false
	}
	return time.Now().After(c.x509Certificate.NotAfter)
}

func (c Certificate) ToPEM() []byte {

	if c.Error() != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  certificateBlockType,
		Bytes: c.x509Certificate.Raw,
	})
}

// CommonName is the subject's common name, empty when it has none. It is
// enough to tell certificates apart without printing a whole distinguished
// name, which for an EV certificate runs to several hundred characters.
func (c Certificate) CommonName() string {
	return c.x509Certificate.Subject.CommonName
}

func (c Certificate) SubjectString() string {

	if err := c.Error(); err != nil {
		return err.Error()
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.x509Certificate.RawSubject, &subject); err != nil {
		return fmt.Sprintf("ERROR: asn1 unmarshal subject: %v", err)
	}
	return subject.String()
}

// Error reports why the certificate is unusable, and is the guard callers rely
// on before reading any other accessor: those dereference the parsed
// certificate, so a value holding neither a certificate nor a parse error has
// to report one here rather than panic later.
func (c Certificate) Error() error {
	if c.err != nil {
		return fmt.Errorf("ERROR: block at position %d: %w", c.position, c.err)
	}
	if c.x509Certificate == nil {
		return fmt.Errorf("ERROR: block at position %d: %w", c.position, errNoCertificate)
	}
	return nil
}

func (c Certificate) DNSNames() []string {
	if c.x509Certificate == nil {
		// this is called with -expiry flag as well, this call does not check if there is cert error
		// so we need to check for nil
		return nil
	}
	return c.x509Certificate.DNSNames
}

func (c Certificate) IPAddresses() []string {
	var ips []string
	for _, ip := range c.x509Certificate.IPAddresses {
		ips = append(ips, ip.String())
	}
	return ips
}

// Position is where the certificate appeared in its source, starting at 1. For
// a network location that is chain order, the end-entity certificate first.
func (c Certificate) Position() int {
	return c.position
}

func (c Certificate) Version() int {
	return c.x509Certificate.Version
}

func (c Certificate) SerialNumber() string {
	return formatSerialNumber(c.x509Certificate.SerialNumber)
}

func (c Certificate) SignatureAlgorithm() string {
	return c.x509Certificate.SignatureAlgorithm.String()
}

func (c Certificate) Issuer() string {
	return c.x509Certificate.Issuer.String()
}

func (c Certificate) NotBefore() time.Time {
	return c.x509Certificate.NotBefore
}

func (c Certificate) NotAfter() time.Time {
	return c.x509Certificate.NotAfter
}

func (c Certificate) AuthorityKeyId() string {
	if c.x509Certificate.AuthorityKeyId != nil {
		return formatHexArray(c.x509Certificate.AuthorityKeyId)
	}
	return ""
}

func (c Certificate) SubjectKeyId() string {
	if c.x509Certificate.SubjectKeyId != nil {
		return formatHexArray(c.x509Certificate.SubjectKeyId)
	}
	return ""
}

func (c Certificate) PublicKeyAlgorithm() string {
	return c.x509Certificate.PublicKeyAlgorithm.String()
}

func (c Certificate) Signature() string {
	return formatHexArray(c.x509Certificate.Signature)
}

func (c Certificate) IsCA() bool {
	return c.x509Certificate.IsCA
}

func (c Certificate) KeyUsage() []string {
	var out []string
	for i, v := range keyUsages {
		bitmask := 1 << i
		if (int(c.x509Certificate.KeyUsage) & bitmask) == 0 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// ExtKeyUsage extended key usage string representation
func (c Certificate) ExtKeyUsage() []string {

	var extendedKeyUsageString []string
	for _, v := range c.x509Certificate.ExtKeyUsage {
		extendedKeyUsageString = append(extendedKeyUsageString, extKeyUsages[v])
	}
	return extendedKeyUsageString
}

func (c Certificate) Type() string {
	if c.x509Certificate.AuthorityKeyId == nil || bytes.Equal(c.x509Certificate.AuthorityKeyId, c.x509Certificate.SubjectKeyId) {
		return "root"
	}

	if c.x509Certificate.IsCA {
		return "intermediate"
	}
	return "end-entity"
}
func (c Certificate) Extensions() []Extension {
	var out []Extension
	for _, v := range c.x509Certificate.Extensions {
		name, value, err := parseExtension(v)
		if err != nil {
			// the extension is reported in place of its value, which is where
			// a reader is looking; announcing it as well says it twice
			value = []string{err.Error()}
		}
		out = append(out, Extension{
			Name:     name,
			Oid:      v.Id.String(),
			Critical: v.Critical,
			Values:   value,
		})
	}
	return out
}

// formatSerialNumber renders a serial as the colon separated hex openssl and
// the browsers show.
//
// A serial of zero encodes as a single zero byte, but big.Int.Bytes returns
// nothing at all for it, so the number that names the certificate came out as
// an empty field. RFC 5280 requires a positive serial and eight of the roots
// in a system trust store have one anyway, among them Go Daddy's and
// Starfield's.
//
// A negative serial is out of spec too, and Bytes drops the sign, so it is
// written back on rather than quietly rendering a different number. Go refuses
// to parse a certificate with one, so this only arises for a serial that
// reached here another way, such as from a revocation response.
func formatSerialNumber(serial *big.Int) string {
	if serial == nil {
		return ""
	}

	digits := formatHexArray(serial.Bytes())
	if digits == "" {
		digits = "00"
	}
	if serial.Sign() < 0 {
		return "-" + digits
	}
	return digits
}

func formatHexArray(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}
