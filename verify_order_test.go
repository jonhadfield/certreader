package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// servedTwice is a location shaped like a host that sent its intermediate
// twice, which is the shape the duplicate warning is about.
func servedTwice(t *testing.T) cert.Locations {
	t.Helper()

	root, rootKey := selfSignedCA(t, "Order Test Root")
	intermediate, intermediateKey := signedCA(t, "Order Test Intermediate", root, rootKey)
	leaf := signedLeaf(t, "order.example.com", intermediate, intermediateKey)

	return cert.Locations{{
		Path:         "order.example.com:443",
		TLSVersion:   0x0304,
		ContentType:  cert.ContentTypeCertificate,
		Certificates: cert.FromX509Certificates([]*x509.Certificate{leaf, intermediate, intermediate}),
	}}
}

func chainMessages(location cert.Location) []string {
	var out []string
	if location.Verification == nil {
		return out
	}
	for _, warning := range location.Verification.ChainWarnings {
		out = append(out, warning.Message)
	}
	return out
}

func TestVerifyHappensBeforeFiltering(t *testing.T) {
	t.Run("given -verify alone, then the duplicate is reported", func(t *testing.T) {
		locations := verifyThenFilter(servedTwice(t), Flags{Verify: true})

		require.Len(t, locations, 1)
		assert.Contains(t, chainMessages(locations[0])[0], "sent more than once")
		assert.Len(t, locations[0].Certificates, 3, "nothing was asked to be removed")
	})

	t.Run("given -verify with -no-duplicate, then it is still reported and still removed", func(t *testing.T) {
		// Filtering used to run first, so the duplicate was gone before
		// anything could report it: the check could not fire for the person
		// who had asked to be shown the chain without duplicates.
		locations := verifyThenFilter(servedTwice(t), Flags{Verify: true, NoDuplicate: true})

		require.Len(t, locations, 1)
		require.NotEmpty(t, chainMessages(locations[0]))
		assert.Contains(t, chainMessages(locations[0])[0], "sent more than once")

		// the filter still does what it was asked to do
		assert.Len(t, locations[0].Certificates, 2)
	})

	t.Run("given -verify with -no-duplicate, then a check on warnings fails", func(t *testing.T) {
		locations := verifyThenFilter(servedTwice(t), Flags{Verify: true, NoDuplicate: true})

		assert.Equal(t, exitCheckFailed, exitStatus(locations, Flags{Verify: true, NoDuplicate: true, FailOnWarning: true}))
	})

	t.Run("given filters without -verify, then they still filter", func(t *testing.T) {
		locations := verifyThenFilter(servedTwice(t), Flags{NoDuplicate: true})

		require.Len(t, locations, 1)
		assert.Nil(t, locations[0].Verification)
		assert.Len(t, locations[0].Certificates, 2)
	})
}

func selfSignedCA(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return finish(t, template, template, &key.PublicKey, key), key
}

func signedCA(t *testing.T, commonName string, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return finish(t, template, parent, &key.PublicKey, parentKey), key
}

func signedLeaf(t *testing.T, commonName string, parent *x509.Certificate, parentKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return finish(t, template, parent, &key.PublicKey, parentKey)
}

func finish(t *testing.T, template, parent *x509.Certificate, public *rsa.PublicKey, signer *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}
