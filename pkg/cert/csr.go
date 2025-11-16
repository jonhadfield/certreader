package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const csrBlockType = "CERTIFICATE REQUEST"

type CSRs []CSR

type CSR struct {
	position int
	x509CSR  *x509.CertificateRequest
	err      error
}

// FromX509CertificateRequests converts x509.CertificateRequest slice to CSRs
func FromX509CertificateRequests(csrs []*x509.CertificateRequest) CSRs {
	var requests CSRs
	for i, c := range csrs {
		requests = append(requests, CSR{position: i + 1, x509CSR: c})
	}
	return requests
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
	if c.err != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  csrBlockType,
		Bytes: c.x509CSR.Raw,
	})
}

func (c CSR) SubjectString() string {
	if c.err != nil {
		return fmt.Sprintf("ERROR: block at position %d: %v", c.position, c.err)
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.x509CSR.RawSubject, &subject); err != nil {
		return fmt.Sprintf("ERROR: asn1 unmarshal subject: %v", err)
	}
	return subject.String()
}

func (c CSR) Error() error {
	if c.err != nil {
		return fmt.Errorf("ERROR: block at position %d: %v", c.position, c.err)
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

func (c CSR) Version() int {
	return c.x509CSR.Version
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

func formatCSRHexArray(b []byte) string {
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
