package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fileLocation(t *testing.T, file string) Location {
	t.Helper()

	location := LoadFromFile("testdata/"+file, "")
	require.Nil(t, location.Error)
	return location
}

func TestCompare(t *testing.T) {
	t.Run("given the same file twice, then everything matches", func(t *testing.T) {
		comparison, err := Locations{fileLocation(t, "cert.pem"), fileLocation(t, "cert.pem")}.Compare()
		require.NoError(t, err)

		assert.True(t, comparison.Same())
		assert.True(t, comparison.SameCertificate)
		assert.True(t, comparison.SameKey)
		assert.True(t, comparison.SameChain)
		assert.Equal(t, "the same certificate and the same chain", comparison.Summary())
	})

	t.Run("given different certificates, then nothing matches", func(t *testing.T) {
		comparison, err := Locations{fileLocation(t, "cert.pem"), fileLocation(t, "sct.pem")}.Compare()
		require.NoError(t, err)

		assert.False(t, comparison.Same())
		assert.False(t, comparison.SameKey)
		assert.NotEqual(t, comparison.LeftFingerprint, comparison.RightFingerprint)
		assert.Contains(t, comparison.Summary(), "different keys")
	})

	t.Run("given the same certificate with more of the chain, then the certificate still matches", func(t *testing.T) {
		// A leaf is deployed and served with the intermediates a client needs.
		// That is normal, so it is reported and not counted as a difference.
		// sct.pem is the end-entity; cert.pem is a root, standing in for the
		// rest of what a server would send with it
		one := fileLocation(t, "sct.pem")
		two := fileLocation(t, "sct.pem")
		two.Certificates = append(two.Certificates, fileLocation(t, "cert.pem").Certificates...)

		comparison, err := Locations{one, two}.Compare()
		require.NoError(t, err)

		assert.True(t, comparison.Same(), "the certificate is what a check is asking about")
		assert.False(t, comparison.SameChain)
		assert.Equal(t, 1, comparison.LeftCount)
		assert.Equal(t, 2, comparison.RightCount)
		assert.Equal(t, "the same certificate, sent with a different chain", comparison.Summary())
	})

	t.Run("given a reissue that kept the key, then the key says so", func(t *testing.T) {
		// The distinction the two fingerprints exist for: a certificate can be
		// replaced without the key changing, and that is not a rotation.
		first, second := reissued(t)

		comparison, err := Locations{servedChain(first), servedChain(second)}.Compare()
		require.NoError(t, err)

		assert.False(t, comparison.SameCertificate)
		assert.True(t, comparison.SameKey)
		assert.Contains(t, comparison.Summary(), "reissue")
	})

	t.Run("given anything but two locations, then it says so", func(t *testing.T) {
		_, err := Locations{fileLocation(t, "cert.pem")}.Compare()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "given 1")
	})

	t.Run("given a location that could not be read, then it names it", func(t *testing.T) {
		broken := Location{Path: "missing.pem", Error: errNoPEMBlock}

		_, err := Locations{fileLocation(t, "cert.pem"), broken}.Compare()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing.pem")
	})
}

// reissued builds two certificates for the same name and the same key, as a
// renewal that did not rotate the key produces.
func reissued(t *testing.T) (first, second *x509.Certificate) {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "reissue test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issue := func(serial int64) *x509.Certificate {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "reissue.example.com"},
			DNSNames:              []string{"reissue.example.com"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, leafKey.Public(), issuerKey)
		require.NoError(t, err)
		certificate, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return certificate
	}

	return issue(2), issue(3)
}
