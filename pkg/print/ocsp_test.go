package print

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

var stapleTestSerial atomic.Int64

type stapleTestChain struct {
	issuer    *x509.Certificate
	issuerKey crypto.Signer
	leaf      *x509.Certificate
}

func newStapleTestChain(t *testing.T) stapleTestChain {
	t.Helper()

	serial := stapleTestSerial.Add(1)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "certreader print test CA"},
		SubjectKeyId:          []byte{1, 2, 3, 4},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x0102030000 + serial),
		Subject:      pkix.Name{CommonName: "certreader.test"},
		SubjectKeyId: []byte{5, 6, 7, 8},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return stapleTestChain{issuer: issuer, issuerKey: issuerKey, leaf: leaf}
}

func (c stapleTestChain) response(t *testing.T, template ocsp.Response) []byte {
	t.Helper()

	if template.SerialNumber == nil {
		template.SerialNumber = c.leaf.SerialNumber
	}
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate = time.Now().Add(-time.Hour)
	}
	if template.NextUpdate.IsZero() {
		template.NextUpdate = time.Now().Add(time.Hour)
	}
	raw, err := ocsp.CreateResponse(c.issuer, c.issuer, template, c.issuerKey)
	require.NoError(t, err)
	return raw
}

func (c stapleTestChain) location(staple []byte, withIssuer bool) cert.Location {
	certs := []*x509.Certificate{c.leaf}
	if withIssuer {
		certs = append(certs, c.issuer)
	}
	return cert.Location{
		Path:         "certreader.test:443",
		ContentType:  cert.ContentTypeCertificate,
		Certificates: cert.FromX509Certificates(certs),
		OCSPStaple:   staple,
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = oldStdout
	output, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(output)
}

func Test_printStapledOCSP(t *testing.T) {

	t.Run("given a good staple then status and metadata are printed", func(t *testing.T) {
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)

		output := captureStdout(t, func() { printStapledOCSP(location) })

		assert.Contains(t, output, "OCSP Staple")
		assert.Contains(t, output, "Status")
		assert.Contains(t, output, "good")
		assert.Contains(t, output, "Serial Number")
		assert.Contains(t, output, "Produced At")
		assert.Contains(t, output, "This Update")
		assert.Contains(t, output, "Next Update")
		assert.Contains(t, output, "verified against issuer")
		assert.NotContains(t, output, "Revoked At")
		assert.NotContains(t, output, "[stale]")
	})

	t.Run("given a revoked staple then the reason and time are printed", func(t *testing.T) {
		chain := newStapleTestChain(t)
		staple := chain.response(t, ocsp.Response{
			Status:           ocsp.Revoked,
			RevokedAt:        time.Now().Add(-2 * time.Hour),
			RevocationReason: ocsp.KeyCompromise,
		})

		output := captureStdout(t, func() { printStapledOCSP(chain.location(staple, true)) })

		assert.Contains(t, output, "revoked")
		assert.Contains(t, output, "Revoked At")
		assert.Contains(t, output, "key compromise")
	})

	t.Run("given a stale staple then it is marked", func(t *testing.T) {
		chain := newStapleTestChain(t)
		staple := chain.response(t, ocsp.Response{
			Status:     ocsp.Good,
			ThisUpdate: time.Now().Add(-48 * time.Hour),
			NextUpdate: time.Now().Add(-24 * time.Hour),
		})

		output := captureStdout(t, func() { printStapledOCSP(chain.location(staple, true)) })

		assert.Contains(t, output, "[stale]")
	})

	t.Run("given no issuer then the staple is reported as unverified", func(t *testing.T) {
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), false)

		output := captureStdout(t, func() { printStapledOCSP(location) })

		assert.Contains(t, output, "not verified (issuer certificate unavailable)")
	})

	t.Run("given no staple then nothing is printed", func(t *testing.T) {
		chain := newStapleTestChain(t)

		output := captureStdout(t, func() { printStapledOCSP(chain.location(nil, true)) })

		assert.Empty(t, output)
	})

	t.Run("given a malformed staple then the error is printed", func(t *testing.T) {
		chain := newStapleTestChain(t)

		output := captureStdout(t, func() { printStapledOCSP(chain.location([]byte("garbage"), true)) })

		assert.Contains(t, output, "OCSP Staple")
		assert.Contains(t, output, "parse OCSP response")
	})
}

func TestLocationsUnifiedPrintsStaple(t *testing.T) {
	chain := newStapleTestChain(t)
	location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)

	output := captureStdout(t, func() {
		LocationsUnified(cert.Locations{location}, false, false, false, false)
	})

	assert.Contains(t, output, "certreader.test:443")
	assert.Contains(t, output, "OCSP Staple")
	assert.Contains(t, output, "good")
}

func Test_signatureStatus(t *testing.T) {
	assert.Equal(t, "verified against issuer", signatureStatus(true))
	assert.Equal(t, "not verified (issuer certificate unavailable)", signatureStatus(false))
}

func TestOCSPStatus(t *testing.T) {
	// colors are disabled when stdout is not a terminal, so the label survives intact
	assert.Contains(t, OCSPStatus("good"), "good")
	assert.Contains(t, OCSPStatus("revoked"), "revoked")
	assert.Contains(t, OCSPStatus("unknown"), "unknown")
	assert.Contains(t, OCSPStatus("unrecognised (9)"), "unrecognised (9)")
}
