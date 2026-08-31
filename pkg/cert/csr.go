package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

const csrBlockType = "CERTIFICATE REQUEST"

type CSRs []CSR

type CSR struct {
	position int
	x509CSR  *x509.CertificateRequest
	err      error
}

// FromCSRBytes converts raw CSR bytes to CSR structures. Supports PEM and DER formats.
func FromCSRBytes(data []byte) (CSRs, error) {
	// Try PEM first
	csrs, err := fromCSRPEMBytes(data)
	if err == nil {
		return csrs, nil
	}
	if !errors.Is(err, errNoPEMBlock) {
		return nil, err
	}

	// Try DER format
	return fromCSRDERBytes(data)
}

func fromCSRPEMBytes(data []byte) (CSRs, error) {
	var (
		block *pem.Block
		csrs  CSRs
		idx   int
	)

	for {
		idx++
		block, data = pem.Decode(data)
		if block == nil {
			if len(csrs) == 0 {
				return nil, errNoPEMBlock
			}
			return csrs, nil
		}
		csrs = append(csrs, fromCSRPemBlock(idx, block))
		if len(data) == 0 {
			return csrs, nil
		}
	}
}

func fromCSRDERBytes(data []byte) (CSRs, error) {
	// Try to parse as DER-encoded CSR
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, fmt.Errorf("invalid DER CSR: %w", err)
	}

	return CSRs{
		CSR{position: 1, x509CSR: csr},
	}, nil
}

func fromCSRPemBlock(position int, block *pem.Block) CSR {
	if block.Type != csrBlockType && block.Type != "NEW CERTIFICATE REQUEST" {
		return CSR{position: position, err: fmt.Errorf("cannot parse %s block", block.Type)}
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return CSR{position: position, err: err}
	}

	return CSR{position: position, x509CSR: csr}
}

func (c CSR) ToPEM() []byte {
	if c.Error() != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  csrBlockType,
		Bytes: c.x509CSR.Raw,
	})
}

func (c CSR) SubjectString() string {
	if err := c.Error(); err != nil {
		return err.Error()
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.x509CSR.RawSubject, &subject); err != nil {
		return fmt.Sprintf("ERROR: asn1 unmarshal subject: %v", err)
	}
	return subject.String()
}

// Error reports why the request is unusable. As with Certificate.Error, callers
// use this as the guard before reading accessors that dereference the parsed
// request.
func (c CSR) Error() error {
	if c.err != nil {
		return fmt.Errorf("ERROR: block at position %d: %v", c.position, c.err)
	}
	if c.x509CSR == nil {
		return fmt.Errorf("ERROR: block at position %d: %v", c.position, errNoCertificateReq)
	}
	return nil
}

func (c CSR) DNSNames() []string {
	if c.x509CSR == nil {
		return nil
	}
	return c.x509CSR.DNSNames
}

func (c CSR) IPAddresses() []string {
	var ips []string
	for _, ip := range c.x509CSR.IPAddresses {
		ips = append(ips, fmt.Sprintf("%s", ip))
	}
	return ips
}

func (c CSR) EmailAddresses() []string {
	if c.x509CSR == nil {
		return nil
	}
	return c.x509CSR.EmailAddresses
}

func (c CSR) URIs() []string {
	var uris []string
	for _, uri := range c.x509CSR.URIs {
		uris = append(uris, uri.String())
	}
	return uris
}

// Version is the version as it is encoded, which PKCS#10 numbers from zero: a
// v1 request encodes as 0. It is the raw field, kept for anything that needs
// the encoding rather than the number.
func (c CSR) Version() int {
	return c.x509CSR.Version
}

// VersionNumber is the version people write, counting from one, which is what
// a certificate's Version already reports. Printing the encoded value under
// the same label as a certificate's meant a request looked like version 0 next
// to a certificate's 3, when both are the current version of their format.
func (c CSR) VersionNumber() int {
	return c.x509CSR.Version + 1
}

func (c CSR) SignatureAlgorithm() string {
	return c.x509CSR.SignatureAlgorithm.String()
}

func (c CSR) PublicKeyAlgorithm() string {
	return c.x509CSR.PublicKeyAlgorithm.String()
}

func (c CSR) Signature() string {
	return formatHexArray(c.x509CSR.Signature)
}

func (c CSR) Extensions() []Extension {
	var out []Extension
	for _, v := range c.x509CSR.Extensions {
		name, value, err := parseExtension(v)
		if err != nil {
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
