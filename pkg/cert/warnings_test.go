package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// warningCertificate builds a certificate from a template, signed by a separate
// CA unless selfSigned is set, so that end-entity and root cases can both be
// exercised.
func warningCertificate(t *testing.T, template *x509.Certificate, key any, selfSigned bool) Certificate {
	t.Helper()

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if key == nil {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		key = generated
	}

	// crypto.PublicKey is a defined type rather than an alias for any, so the
	// method set only matches through crypto.Signer
	public := key.(crypto.Signer).Public()

	parent := template
	signer := key
	if !selfSigned {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "warning test CA"},
			SubjectKeyId:          []byte{9, 9, 9, 9},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
		require.NoError(t, err)
		parent, err = x509.ParseCertificate(caDER)
		require.NoError(t, err)
		signer = caKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return Certificate{position: 1, x509Certificate: parsed}
}

func warningCodes(warnings []Warning) []string {
	var out []string
	for _, warning := range warnings {
		out = append(out, warning.Code)
	}
	return out
}

func TestWarnings(t *testing.T) {

	t.Run("given a healthy modern certificate then there is nothing to say", func(t *testing.T) {
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "good.example.com"},
			DNSNames:    []string{"good.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, nil, false)

		assert.Empty(t, certificate.Warnings())
	})

	t.Run("given a small rsa key then it is reported", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)

		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "small.example.com"},
			DNSNames:    []string{"small.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, key, false)

		assert.Contains(t, warningCodes(certificate.Warnings()), WarningSmallKey)
	})

	t.Run("given a p224 key then it is reported", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "p224.example.com"},
			DNSNames:    []string{"p224.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, key, false)

		assert.Contains(t, warningCodes(certificate.Warnings()), WarningSmallKey)
	})

	t.Run("given a long lived server certificate then it is reported", func(t *testing.T) {
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "long.example.com"},
			DNSNames:    []string{"long.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(500 * 24 * time.Hour),
		}, nil, false)

		assert.Contains(t, warningCodes(certificate.Warnings()), WarningLongValidity)
	})

	t.Run("given a server certificate with no subject alternative name then it is reported", func(t *testing.T) {
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "nosan.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, nil, false)

		assert.Contains(t, warningCodes(certificate.Warnings()), WarningNoSubjectAlt)
	})
}

func TestWarningsAvoidsFalsePositives(t *testing.T) {

	t.Run("given a long lived CA then its validity is not reported", func(t *testing.T) {
		// a CA is expected to outlive what it issues, so the server limit does
		// not apply to it
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:               pkix.Name{CommonName: "long lived CA"},
			SubjectKeyId:          []byte{1, 2, 3},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, nil, false)

		codes := warningCodes(certificate.Warnings())
		assert.NotContains(t, codes, WarningLongValidity)
		assert.NotContains(t, codes, WarningNoSubjectAlt, "a CA has no business having a dns name")
	})

	t.Run("given a self signed root then its own signature is not reported", func(t *testing.T) {
		// a root is trusted by being in a trust store, not by its signature, so
		// flagging every sha-1 era root would be noise
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		certificate := warningCertificate(t, &x509.Certificate{
			Subject:               pkix.Name{CommonName: "old root"},
			SubjectKeyId:          []byte{4, 5, 6},
			SignatureAlgorithm:    x509.SHA1WithRSA,
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, key, true)

		require.Equal(t, "root", certificate.Type())
		assert.NotContains(t, warningCodes(certificate.Warnings()), WarningWeakSignature)
	})

	t.Run("given a sha-1 signed leaf then it is reported", func(t *testing.T) {
		// the same broken hash on something whose signature is relied upon.
		// The algorithm has to match the signing key, and the test CA is ecdsa
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:            pkix.Name{CommonName: "sha1.example.com"},
			DNSNames:           []string{"sha1.example.com"},
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			SignatureAlgorithm: x509.ECDSAWithSHA1,
		}, nil, false)

		assert.Contains(t, warningCodes(certificate.Warnings()), WarningWeakSignature)
	})

	t.Run("given a long lived certificate issued before the limit then it is not reported", func(t *testing.T) {
		// certificates issued before september 2020 were legitimately longer
		// lived, so flagging them reports history rather than a problem
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "historic.example.com"},
			DNSNames:    []string{"historic.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			NotBefore:   time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		}, nil, false)

		assert.NotContains(t, warningCodes(certificate.Warnings()), WarningLongValidity)
	})

	t.Run("given a client certificate then the server rules do not apply", func(t *testing.T) {
		certificate := warningCertificate(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "a person"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(3 * 365 * 24 * time.Hour),
		}, nil, false)

		codes := warningCodes(certificate.Warnings())
		assert.NotContains(t, codes, WarningLongValidity)
		assert.NotContains(t, codes, WarningNoSubjectAlt)
	})

	t.Run("given a certificate that failed to parse then nothing is reported", func(t *testing.T) {
		assert.Nil(t, Certificate{position: 1, err: errNoPEMBlock}.Warnings())
	})

	t.Run("given the real fixtures then nothing is reported", func(t *testing.T) {
		// the shipped certificates are all sound, so any warning here is a
		// false positive rather than a finding
		for _, file := range []string{"cert.pem", "bundle.pem", "sct.pem"} {
			for _, certificate := range loadTestCertificates(t, file) {
				assert.Empty(t, certificate.Warnings(), "%s: %s", file, certificate.SubjectString())
			}
		}
	})
}

func Test_isServerCertificate(t *testing.T) {

	assert.True(t, isServerCertificate(&x509.Certificate{}), "no usage means unrestricted")
	assert.True(t, isServerCertificate(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}))
	assert.True(t, isServerCertificate(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}))
	assert.False(t, isServerCertificate(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}))
	assert.False(t, isServerCertificate(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
	}))
}

func Test_weakSignatureAlgorithm(t *testing.T) {

	for _, algorithm := range []x509.SignatureAlgorithm{
		x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
	} {
		_, weak := weakSignatureAlgorithm(algorithm)
		assert.True(t, weak, algorithm.String())
	}

	for _, algorithm := range []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.PureEd25519,
	} {
		_, weak := weakSignatureAlgorithm(algorithm)
		assert.False(t, weak, algorithm.String())
	}
}
