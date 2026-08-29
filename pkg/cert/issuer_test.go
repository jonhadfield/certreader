package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func withIssuerURL(url string) func(*x509.Certificate) {
	return func(c *x509.Certificate) { c.IssuingCertificateURL = []string{url} }
}

func TestFetchIssuer(t *testing.T) {

	t.Run("given a der issuer then it is fetched and ocsp proceeds", func(t *testing.T) {
		issuerServer := newStubServer(t)
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL), withOCSPServer(responder.URL))

		issuerServer.serveBytes("application/pkix-cert", chain.issuer.Raw)
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		// the caller has only the leaf, as when reading a single pem file
		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.Equal(t, RevocationSourceOCSP, status.Source)
		assert.Equal(t, "good", status.Status)
		assert.True(t, status.SignatureVerified, "the fetched issuer authenticates the response")
		assert.Equal(t, issuerServer.URL, status.IssuerFetchedFrom)
		assert.Empty(t, status.Attempts)
	})

	t.Run("given a pem issuer then it is fetched", func(t *testing.T) {
		issuerServer := newStubServer(t)
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL), withCRLPoint(crlPoint.URL))

		issuerServer.serveBytes("application/x-pem-file",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.issuer.Raw}))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.Equal(t, "good", status.Status)
		assert.True(t, status.SignatureVerified)
		assert.Equal(t, issuerServer.URL, status.IssuerFetchedFrom)
	})

	t.Run("given a certificate that did not sign this one then it is refused", func(t *testing.T) {
		issuerServer := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL))
		other := newOCSPTestChain(t)

		// a plain http fetch is trivially spoofed, so the result has to be checked
		issuerServer.serveBytes("application/pkix-cert", other.issuer.Raw)

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.True(t, status.IsUnknown())
		assert.Empty(t, status.IssuerFetchedFrom)
		require.NotEmpty(t, status.Attempts)
		assert.Equal(t, RevocationSourceIssuer, status.Attempts[0].Source)
		assert.Contains(t, status.Attempts[0].Err.Error(), "did not sign this one")
	})

	t.Run("given a pkcs7 bundle then it is named rather than reported as asn1 noise", func(t *testing.T) {
		issuerServer := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL))

		// a der sequence carrying the signedData oid, which is what a .p7c is
		bundle := append([]byte{0x30, 0x0d}, pkcs7SignedDataOID...)
		issuerServer.serveBytes("application/pkcs7-mime", bundle)

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		require.NotEmpty(t, status.Attempts)
		assert.Contains(t, status.Attempts[0].Err.Error(), "pkcs#7")
	})

	t.Run("given the fetch fails then the reason is recorded", func(t *testing.T) {
		issuerServer := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL))
		issuerServer.serveStatus(http.StatusNotFound)

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		require.NotEmpty(t, status.Attempts)
		assert.Equal(t, RevocationSourceIssuer, status.Attempts[0].Source)
		assert.Contains(t, status.Attempts[0].Err.Error(), "404")
	})

	t.Run("given several urls then the first that works is used", func(t *testing.T) {
		broken := newStubServer(t)
		working := newStubServer(t)
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, func(c *x509.Certificate) {
			c.IssuingCertificateURL = []string{"ldap://ignored.example.com", broken.URL, working.URL}
		}, withOCSPServer(responder.URL))

		broken.serveStatus(http.StatusInternalServerError)
		working.serveBytes("application/pkix-cert", chain.issuer.Raw)
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.Equal(t, "good", status.Status)
		assert.Equal(t, working.URL, status.IssuerFetchedFrom)
	})

	t.Run("given the issuer is already present then nothing is fetched", func(t *testing.T) {
		issuerServer := newStubServer(t)
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL), withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, "good", status.Status)
		assert.Empty(t, status.IssuerFetchedFrom)
		assert.Equal(t, int64(0), issuerServer.calls.Load(), "the issuer was already to hand")
	})

	t.Run("given the fetch is disabled then it is not attempted", func(t *testing.T) {
		issuerServer := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL))

		checker := &RevocationChecker{SkipIssuerFetch: true}
		status := checker.Check(context.Background(), chain.leaf, nil, nil)

		assert.Equal(t, int64(0), issuerServer.calls.Load())
		assert.Contains(t, status.Attempts[0].Err.Error(), "disabled")
	})

	t.Run("given the same url twice then it is fetched once", func(t *testing.T) {
		issuerServer := newStubServer(t)
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL), withCRLPoint(crlPoint.URL))
		issuerServer.serveBytes("application/pkix-cert", chain.issuer.Raw)
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		checker := NewRevocationChecker()
		for i := 0; i < 3; i++ {
			status := checker.Check(context.Background(), chain.leaf, nil, nil)
			require.Equal(t, "good", status.Status)
		}

		assert.Equal(t, int64(1), issuerServer.calls.Load(), "the issuer is cached across locations")
	})
}

func Test_parseIssuerCertificate(t *testing.T) {
	chain := newOCSPTestChain(t)

	t.Run("given der then it is parsed", func(t *testing.T) {
		out, err := parseIssuerCertificate(chain.issuer.Raw)
		require.NoError(t, err)
		assert.True(t, out.Equal(chain.issuer))
	})

	t.Run("given pem then it is parsed", func(t *testing.T) {
		out, err := parseIssuerCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.issuer.Raw}))
		require.NoError(t, err)
		assert.True(t, out.Equal(chain.issuer))
	})

	t.Run("given rubbish then it is rejected", func(t *testing.T) {
		_, err := parseIssuerCertificate([]byte("not a certificate"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "der or pem")
	})
}
