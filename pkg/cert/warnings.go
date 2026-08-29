package cert

import (
	"crypto/dsa" //nolint:staticcheck // deprecated, but certificates still carry these keys
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// Warning is something about a certificate worth drawing attention to: a
// broken algorithm, a key too small to rely on, or a shape browsers reject.
type Warning struct {
	// Code is a stable identifier, so a script can act on a particular warning
	// without matching on prose.
	Code string
	// Message explains the warning in a sentence.
	Message string
}

// Warning codes. These are interface: add to them rather than renaming.
const (
	WarningWeakSignature = "weak-signature-algorithm"
	WarningSmallKey      = "small-key"
	WarningLongValidity  = "long-validity"
	WarningNoSubjectAlt  = "missing-subject-alt-name"
)

const (
	// minRSABits is the smallest RSA modulus still considered sound.
	minRSABits = 2048
	// minECDSABits rules out P-224.
	minECDSABits = 256
	// maxServerValidityDays is the CA/Browser Forum limit for TLS server
	// certificates. It does not apply to CAs, which are long lived by design.
	maxServerValidityDays = 398
)

// serverValidityLimitFrom is when the 398 day limit began to apply. Certificates
// issued before it were legitimately longer lived, so flagging them would be
// reporting history rather than a problem.
var serverValidityLimitFrom = time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)

// Warnings reports weaknesses in the certificate. It is quiet about properties
// that are only weak in context: a root's self signature is not relied upon,
// since a root is trusted by being in a trust store rather than by its
// signature, and a CA is expected to outlive the certificates it issues.
func (c Certificate) Warnings() []Warning {

	if c.Error() != nil {
		return nil
	}

	var out []Warning
	certificate := c.x509Certificate

	if c.Type() != "root" {
		if name, weak := weakSignatureAlgorithm(certificate.SignatureAlgorithm); weak {
			out = append(out, Warning{
				Code:    WarningWeakSignature,
				Message: fmt.Sprintf("signed with %s, which is no longer considered sound", name),
			})
		}
	}

	if warning, ok := smallKeyWarning(certificate.PublicKey); ok {
		out = append(out, warning)
	}

	if c.Type() == "end-entity" && isServerCertificate(certificate) {
		days := int(certificate.NotAfter.Sub(certificate.NotBefore).Hours() / 24)
		if days > maxServerValidityDays && !certificate.NotBefore.Before(serverValidityLimitFrom) {
			out = append(out, Warning{
				Code:    WarningLongValidity,
				Message: fmt.Sprintf("valid for %d days, beyond the %d day maximum for server certificates", days, maxServerValidityDays),
			})
		}
		if len(certificate.DNSNames) == 0 && len(certificate.IPAddresses) == 0 {
			out = append(out, Warning{
				Code:    WarningNoSubjectAlt,
				Message: "no subject alternative name, which browsers require and will not read from the common name",
			})
		}
	}
	return out
}

// weakSignatureAlgorithm names the algorithms whose hash is broken or retired.
func weakSignatureAlgorithm(in x509.SignatureAlgorithm) (string, bool) {
	switch in {
	case x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return in.String(), true
	default:
		return in.String(), false
	}
}

func smallKeyWarning(key any) (Warning, bool) {

	switch typed := key.(type) {
	case *rsa.PublicKey:
		if bits := typed.N.BitLen(); bits < minRSABits {
			return Warning{
				Code:    WarningSmallKey,
				Message: fmt.Sprintf("%d bit rsa key, below the %d bit minimum", bits, minRSABits),
			}, true
		}
	case *ecdsa.PublicKey:
		if bits := typed.Curve.Params().BitSize; bits < minECDSABits {
			return Warning{
				Code:    WarningSmallKey,
				Message: fmt.Sprintf("%d bit ecdsa key, below the %d bit minimum", bits, minECDSABits),
			}, true
		}
	case *dsa.PublicKey:
		return Warning{
			Code:    WarningSmallKey,
			Message: "dsa key, an algorithm no longer issued or accepted",
		}, true
	}
	return Warning{}, false
}

// isServerCertificate reports whether the certificate is offered for TLS
// server authentication, which is what the validity and name rules govern. A
// certificate with no extended key usage is unrestricted, so it counts.
func isServerCertificate(certificate *x509.Certificate) bool {

	if len(certificate.ExtKeyUsage) == 0 && len(certificate.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
