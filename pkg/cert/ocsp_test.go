package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// ocspTestSerial hands out a distinct serial per generated chain so responses
// built for one chain never accidentally match another chain's certificate.
var ocspTestSerial atomic.Int64

type ocspTestChain struct {
	issuer    *x509.Certificate
	issuerKey crypto.Signer
	leaf      *x509.Certificate
}

// newOCSPTestChain builds a throwaway CA and end-entity certificate so that
// stapled responses can be created and verified without network access.
func newOCSPTestChain(t *testing.T) ocspTestChain {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial := ocspTestSerial.Add(1)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "certreader test CA"},
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
		DNSNames:     []string{"certreader.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return ocspTestChain{issuer: issuer, issuerKey: issuerKey, leaf: leaf}
}

func (c ocspTestChain) response(t *testing.T, template ocsp.Response) []byte {
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

func TestParseStapledOCSP(t *testing.T) {

	t.Run("given a good response when parsed with the issuer then it is verified", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{Status: ocsp.Good})

		staple, err := ParseStapledOCSP(raw, chain.leaf, chain.issuer)
		require.NoError(t, err)

		assert.Equal(t, "good", staple.Status)
		assert.Equal(t, formatHexArray(chain.leaf.SerialNumber.Bytes()), staple.SerialNumber)
		assert.True(t, staple.SignatureVerified)
		assert.False(t, staple.IsRevoked())
		assert.False(t, staple.IsStale())
		assert.True(t, staple.RevokedAt.IsZero())
		assert.Empty(t, staple.RevocationReason)
		assert.False(t, staple.ThisUpdate.IsZero())
		assert.False(t, staple.NextUpdate.IsZero())
	})

	t.Run("given a revoked response then reason and time are reported", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
		raw := chain.response(t, ocsp.Response{
			Status:           ocsp.Revoked,
			RevokedAt:        revokedAt,
			RevocationReason: ocsp.KeyCompromise,
		})

		staple, err := ParseStapledOCSP(raw, chain.leaf, chain.issuer)
		require.NoError(t, err)

		assert.Equal(t, "revoked", staple.Status)
		assert.True(t, staple.IsRevoked())
		assert.Equal(t, "key compromise", staple.RevocationReason)
		assert.Equal(t, revokedAt, staple.RevokedAt.UTC())
	})

	t.Run("given an unknown response then status is unknown", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{Status: ocsp.Unknown})

		staple, err := ParseStapledOCSP(raw, chain.leaf, chain.issuer)
		require.NoError(t, err)

		assert.Equal(t, "unknown", staple.Status)
		assert.False(t, staple.IsRevoked())
	})

	t.Run("given no issuer then the response is parsed but not verified", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{Status: ocsp.Good})

		staple, err := ParseStapledOCSP(raw, chain.leaf, nil)
		require.NoError(t, err)

		assert.Equal(t, "good", staple.Status)
		assert.False(t, staple.SignatureVerified)
	})

	t.Run("given the wrong issuer then verification fails", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		other := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{Status: ocsp.Good})

		_, err := ParseStapledOCSP(raw, chain.leaf, other.issuer)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse stapled OCSP response")
	})

	t.Run("given a response for another certificate then it is rejected", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		other := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{Status: ocsp.Good})

		_, err := ParseStapledOCSP(raw, other.leaf, chain.issuer)
		require.Error(t, err)
	})

	t.Run("given an expired response then it is reported as stale", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		raw := chain.response(t, ocsp.Response{
			Status:     ocsp.Good,
			ThisUpdate: time.Now().Add(-48 * time.Hour),
			NextUpdate: time.Now().Add(-24 * time.Hour),
		})

		staple, err := ParseStapledOCSP(raw, chain.leaf, chain.issuer)
		require.NoError(t, err)
		assert.True(t, staple.IsStale())
	})

	t.Run("given no staple then a sentinel error is returned", func(t *testing.T) {
		_, err := ParseStapledOCSP(nil, nil, nil)
		require.ErrorIs(t, err, ErrNoOCSPStaple)

		_, err = ParseStapledOCSP([]byte{}, nil, nil)
		require.ErrorIs(t, err, ErrNoOCSPStaple)
	})

	t.Run("given malformed bytes then a parse error is returned", func(t *testing.T) {
		_, err := ParseStapledOCSP([]byte("not an ocsp response"), nil, nil)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNoOCSPStaple)
	})
}

func TestStapledOCSPNilSafety(t *testing.T) {
	var staple *StapledOCSP
	assert.False(t, staple.IsRevoked())
	assert.False(t, staple.IsStale())

	assert.False(t, (&StapledOCSP{Status: "good"}).IsStale(), "no NextUpdate means never stale")
}

func Test_ocspStatus(t *testing.T) {
	tests := []struct {
		in       int
		expected string
	}{
		{ocsp.Good, "good"},
		{ocsp.Revoked, "revoked"},
		{ocsp.Unknown, "unknown"},
		{ocsp.ServerFailed, "unrecognised (3)"},
		{99, "unrecognised (99)"},
	}
	for _, test := range tests {
		assert.Equal(t, test.expected, ocspStatus(test.in))
	}
}

func Test_ocspRevocationReason(t *testing.T) {
	tests := []struct {
		in       int
		expected string
	}{
		{ocsp.Unspecified, "unspecified"},
		{ocsp.KeyCompromise, "key compromise"},
		{ocsp.CACompromise, "CA compromise"},
		{ocsp.AffiliationChanged, "affiliation changed"},
		{ocsp.Superseded, "superseded"},
		{ocsp.CessationOfOperation, "cessation of operation"},
		{ocsp.CertificateHold, "certificate hold"},
		{ocsp.RemoveFromCRL, "remove from CRL"},
		{ocsp.PrivilegeWithdrawn, "privilege withdrawn"},
		{ocsp.AACompromise, "AA compromise"},
		{7, "unrecognised (7)"},
	}
	for _, test := range tests {
		assert.Equal(t, test.expected, ocspRevocationReason(test.in))
	}
}

func TestLocationStapledOCSP(t *testing.T) {

	t.Run("given a location with chain and staple then it is verified", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		location := Location{
			Path:         "certreader.test:443",
			ContentType:  ContentTypeCertificate,
			Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf, chain.issuer}),
			OCSPStaple:   chain.response(t, ocsp.Response{Status: ocsp.Good}),
		}

		require.True(t, location.HasOCSPStaple())
		staple, err := location.StapledOCSP()
		require.NoError(t, err)
		assert.Equal(t, "good", staple.Status)
		assert.True(t, staple.SignatureVerified)
	})

	t.Run("given a location without the issuer then the staple is unverified", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		location := Location{
			Path:         "certreader.test:443",
			ContentType:  ContentTypeCertificate,
			Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf}),
			OCSPStaple:   chain.response(t, ocsp.Response{Status: ocsp.Good}),
		}

		staple, err := location.StapledOCSP()
		require.NoError(t, err)
		assert.False(t, staple.SignatureVerified)
	})

	t.Run("given a location without a staple then it reports none", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		location := Location{
			Path:         "cert.pem",
			ContentType:  ContentTypeCertificate,
			Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf}),
		}

		assert.False(t, location.HasOCSPStaple())
		_, err := location.StapledOCSP()
		require.ErrorIs(t, err, ErrNoOCSPStaple)
	})
}

func Test_leafAndIssuer(t *testing.T) {

	t.Run("given a full chain then leaf and issuer are found regardless of order", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		location := Location{
			Certificates: FromX509Certificates([]*x509.Certificate{chain.issuer, chain.leaf}),
		}

		leaf, issuer := location.leafAndIssuer()
		require.NotNil(t, leaf)
		require.NotNil(t, issuer)
		assert.True(t, leaf.Equal(chain.leaf))
		assert.True(t, issuer.Equal(chain.issuer))
	})

	t.Run("given an unrelated issuer then no issuer is returned", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		other := newOCSPTestChain(t)
		location := Location{
			Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf, other.issuer}),
		}

		leaf, issuer := location.leafAndIssuer()
		require.NotNil(t, leaf)
		assert.Nil(t, issuer)
	})

	t.Run("given no end-entity certificate then nothing is returned", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		location := Location{
			Certificates: FromX509Certificates([]*x509.Certificate{chain.issuer}),
		}

		leaf, issuer := location.leafAndIssuer()
		assert.Nil(t, leaf)
		assert.Nil(t, issuer)
	})

	t.Run("given a certificate that failed to parse then it is skipped", func(t *testing.T) {
		location := Location{
			Certificates: Certificates{{position: 1, err: errNoPEMBlock}},
		}

		leaf, issuer := location.leafAndIssuer()
		assert.Nil(t, leaf)
		assert.Nil(t, issuer)
	})
}
