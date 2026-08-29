package cert

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// stubServer stands in for an OCSP responder or CRL distribution point and
// counts the requests it receives, so tests can assert that no request was made.
type stubServer struct {
	*httptest.Server
	handler atomic.Value
	calls   atomic.Int64
}

func newStubServer(t *testing.T) *stubServer {
	t.Helper()

	server := &stubServer{}
	server.serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.calls.Add(1)
		server.handler.Load().(func(http.ResponseWriter, *http.Request))(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *stubServer) serve(handler func(http.ResponseWriter, *http.Request)) {
	s.handler.Store(handler)
}

func (s *stubServer) serveBytes(contentType string, body []byte) {
	s.serve(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	})
}

func (s *stubServer) serveStatus(status int) {
	s.serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
}

func withOCSPServer(url string) func(*x509.Certificate) {
	return func(c *x509.Certificate) { c.OCSPServer = []string{url} }
}

func withCRLPoint(url string) func(*x509.Certificate) {
	return func(c *x509.Certificate) { c.CRLDistributionPoints = []string{url} }
}

// crl builds a revocation list signed by the chain's CA.
func (c ocspTestChain) crl(t *testing.T, nextUpdate time.Time, entries ...x509.RevocationListEntry) []byte {
	t.Helper()

	template := &x509.RevocationList{
		Number: big.NewInt(1),
		// derived so that a list expiring in the past is still well formed
		ThisUpdate:                nextUpdate.Add(-24 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, c.issuer, c.issuerKey)
	require.NoError(t, err)
	return der
}

func (c ocspTestChain) revokedEntry(reason int) x509.RevocationListEntry {
	return x509.RevocationListEntry{
		SerialNumber:   c.leaf.SerialNumber,
		RevocationTime: time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second),
		ReasonCode:     reason,
	}
}

func TestRevocationCheckerOCSP(t *testing.T) {

	t.Run("given a responder that answers good then the verdict comes from OCSP", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, RevocationSourceOCSP, status.Source)
		assert.Equal(t, responder.URL, status.URL)
		assert.Equal(t, "good", status.Status)
		assert.True(t, status.SignatureVerified)
		assert.False(t, status.IsRevoked())
		assert.False(t, status.IsUnknown())
		assert.Empty(t, status.Attempts)
		assert.Equal(t, int64(1), responder.calls.Load())
	})

	t.Run("given a responder that answers revoked then the reason is reported", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		revokedAt := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{
			Status:           ocsp.Revoked,
			RevokedAt:        revokedAt,
			RevocationReason: ocsp.CessationOfOperation,
		}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsRevoked())
		assert.Equal(t, "cessation of operation", status.RevocationReason)
		assert.Equal(t, revokedAt, status.RevokedAt.UTC())
	})

	t.Run("given no issuer and nowhere to fetch one then OCSP is skipped", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.True(t, status.IsUnknown())
		assert.Equal(t, int64(0), responder.calls.Load(), "no request should be attempted")
		require.Len(t, status.Attempts, 3)

		// the fetch is tried first, because everything else depends on it
		assert.Equal(t, RevocationSourceIssuer, status.Attempts[0].Source)
		assert.Contains(t, status.Attempts[0].Err.Error(), "names no issuer url")
		assert.Contains(t, status.Attempts[1].Err.Error(), "issuer certificate unavailable")
		assert.Empty(t, status.IssuerFetchedFrom)
	})

	t.Run("given a certificate naming no responder then the attempt is recorded", func(t *testing.T) {
		chain := newOCSPTestChain(t)

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsUnknown())
		require.Len(t, status.Attempts, 2)
		assert.Equal(t, RevocationSourceOCSP, status.Attempts[0].Source)
		assert.Contains(t, status.Attempts[0].Err.Error(), "names no OCSP responder")
		assert.Equal(t, RevocationSourceCRL, status.Attempts[1].Source)
		assert.Contains(t, status.Attempts[1].Err.Error(), "names no CRL distribution point")
	})
}

func TestRevocationCheckerCRLFallback(t *testing.T) {

	t.Run("given a failing responder then the CRL answers instead", func(t *testing.T) {
		responder := newStubServer(t)
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL), withCRLPoint(crlPoint.URL))
		responder.serveStatus(http.StatusInternalServerError)
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, RevocationSourceCRL, status.Source)
		assert.Equal(t, "good", status.Status)
		assert.True(t, status.SignatureVerified)
		require.Len(t, status.Attempts, 1)
		assert.Equal(t, RevocationSourceOCSP, status.Attempts[0].Source)
		assert.Contains(t, status.Attempts[0].Err.Error(), "500")
	})

	t.Run("given the serial is listed then it is reported revoked", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		entry := chain.revokedEntry(ocsp.KeyCompromise)
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour), entry))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, RevocationSourceCRL, status.Source)
		assert.True(t, status.IsRevoked())
		assert.Equal(t, "key compromise", status.RevocationReason)
		assert.Equal(t, entry.RevocationTime, status.RevokedAt.UTC())
	})

	t.Run("given another certificate is listed then this one is good", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		other := x509.RevocationListEntry{
			SerialNumber:   big.NewInt(999999),
			RevocationTime: time.Now().Add(-time.Hour),
		}
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour), other))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, "good", status.Status)
	})

	t.Run("given a PEM encoded CRL then it is parsed", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		der := chain.crl(t, time.Now().Add(24*time.Hour), chain.revokedEntry(ocsp.Superseded))
		crlPoint.serveBytes("application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsRevoked())
		assert.Equal(t, "superseded", status.RevocationReason)
	})

	t.Run("given a CRL signed by another CA then it is rejected", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		other := newOCSPTestChain(t)
		crlPoint.serveBytes("application/pkix-crl", other.crl(t, time.Now().Add(24*time.Hour)))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsUnknown())
		require.NotEmpty(t, status.Attempts)
		assert.Contains(t, status.Attempts[len(status.Attempts)-1].Err.Error(), "bad CRL signature")
	})

	t.Run("given no issuer then a CRL verdict is reported unverified", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour), chain.revokedEntry(ocsp.Unspecified)))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, nil, nil)

		assert.True(t, status.IsRevoked())
		assert.False(t, status.SignatureVerified)
	})

	t.Run("given a stale CRL then the verdict is marked stale", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(-24*time.Hour)))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, "good", status.Status)
		assert.True(t, status.IsStale())
	})
}

func TestRevocationCheckerStaple(t *testing.T) {

	t.Run("given a fresh staple then no request is made", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		staple := chain.response(t, ocsp.Response{Status: ocsp.Good})

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, staple)

		assert.Equal(t, RevocationSourceStaple, status.Source)
		assert.Equal(t, "good", status.Status)
		assert.Empty(t, status.URL)
		assert.Equal(t, int64(0), responder.calls.Load(), "a usable staple should avoid the network")
	})

	t.Run("given a stale staple then the responder is queried", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))
		stale := chain.response(t, ocsp.Response{
			Status:     ocsp.Good,
			ThisUpdate: time.Now().Add(-48 * time.Hour),
			NextUpdate: time.Now().Add(-24 * time.Hour),
		})

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, stale)

		assert.Equal(t, RevocationSourceOCSP, status.Source)
		assert.Equal(t, int64(1), responder.calls.Load())
		require.Len(t, status.Attempts, 1)
		assert.Contains(t, status.Attempts[0].Err.Error(), "expired at")
	})

	t.Run("given a malformed staple then the responder is queried", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, []byte("garbage"))

		assert.Equal(t, RevocationSourceOCSP, status.Source)
		require.Len(t, status.Attempts, 1)
		assert.Equal(t, RevocationSourceStaple, status.Attempts[0].Source)
	})

	t.Run("given SkipStaple then a live query is made anyway", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))
		staple := chain.response(t, ocsp.Response{Status: ocsp.Good})

		checker := &RevocationChecker{SkipStaple: true}
		status := checker.Check(context.Background(), chain.leaf, chain.issuer, staple)

		assert.Equal(t, RevocationSourceOCSP, status.Source)
		assert.Equal(t, int64(1), responder.calls.Load())
	})
}

func TestRevocationCheckerLimits(t *testing.T) {

	t.Run("given an oversized response then it is refused", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		checker := &RevocationChecker{MaxResponseSize: 8}
		status := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsUnknown())
		require.NotEmpty(t, status.Attempts)
		assert.Contains(t, status.Attempts[len(status.Attempts)-1].Err.Error(), "larger than 8 bytes")
	})

	t.Run("given an empty response then it is refused", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", nil)

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsUnknown())
		assert.Contains(t, status.Attempts[len(status.Attempts)-1].Err.Error(), "empty response")
	})

	t.Run("given a non-HTTP distribution point then it is skipped", func(t *testing.T) {
		chain := newOCSPTestChain(t, withCRLPoint("ldap://ldap.example.com/cn=CRL"))

		status := NewRevocationChecker().Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.True(t, status.IsUnknown())
		assert.Contains(t, status.Attempts[len(status.Attempts)-1].Err.Error(), `unsupported url scheme "ldap"`)
	})

	t.Run("given a cancelled context then the request fails rather than hanging", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		status := NewRevocationChecker().Check(ctx, chain.leaf, chain.issuer, nil)
		assert.True(t, status.IsUnknown())
	})

	t.Run("given no certificate then it reports unknown", func(t *testing.T) {
		status := NewRevocationChecker().Check(context.Background(), nil, nil, nil)

		assert.True(t, status.IsUnknown())
		require.Len(t, status.Attempts, 1)
		assert.Contains(t, status.Attempts[0].Err.Error(), "no end-entity certificate")
	})
}

func TestLocationsCheckRevocation(t *testing.T) {

	t.Run("given certificate locations then each is checked", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

		locations := Locations{
			{
				Path:         "one.test:443",
				ContentType:  ContentTypeCertificate,
				Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf, chain.issuer}),
			},
			{
				Path:         "two.test:443",
				ContentType:  ContentTypeCertificate,
				Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf, chain.issuer}),
			},
		}

		out := locations.CheckRevocation(context.Background(), nil)

		require.Len(t, out, 2)
		for _, location := range out {
			require.NotNil(t, location.Revocation)
			assert.Equal(t, "good", location.Revocation.Status)
		}
		assert.Equal(t, int64(2), responder.calls.Load())
	})

	t.Run("given locations that cannot be checked then they are left untouched", func(t *testing.T) {
		locations := Locations{
			{Path: "broken.pem", Error: errNoPEMBlock},
			{Path: "request.csr", ContentType: ContentTypeCSR},
			{Path: "empty.pem", ContentType: ContentTypeCertificate},
		}

		out := locations.CheckRevocation(context.Background(), nil)

		require.Len(t, out, 3)
		for _, location := range out {
			assert.Nil(t, location.Revocation)
		}
	})

	t.Run("given the original locations then they are not mutated", func(t *testing.T) {
		chain := newOCSPTestChain(t)
		locations := Locations{
			{
				Path:         "one.test:443",
				ContentType:  ContentTypeCertificate,
				Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf}),
			},
		}

		out := locations.CheckRevocation(context.Background(), nil)

		assert.Nil(t, locations[0].Revocation)
		assert.NotNil(t, out[0].Revocation)
	})
}

func Test_parseCRL(t *testing.T) {
	chain := newOCSPTestChain(t)
	der := chain.crl(t, time.Now().Add(24*time.Hour))

	t.Run("given DER then it is parsed", func(t *testing.T) {
		list, err := parseCRL(der)
		require.NoError(t, err)
		assert.NotNil(t, list)
	})

	t.Run("given PEM then it is parsed", func(t *testing.T) {
		list, err := parseCRL(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
		require.NoError(t, err)
		assert.NotNil(t, list)
	})

	t.Run("given a PEM block holding rubbish then the inner error is returned", func(t *testing.T) {
		_, err := parseCRL(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("nonsense")}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CRL")
	})

	t.Run("given rubbish then an error is returned", func(t *testing.T) {
		_, err := parseCRL([]byte("not a crl"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CRL")
	})
}

func Test_validateHTTPURL(t *testing.T) {
	tests := []struct {
		in    string
		valid bool
	}{
		{"http://crl.example.com/a.crl", true},
		{"https://ocsp.example.com", true},
		{"ldap://ldap.example.com/cn=CRL", false},
		{"ftp://example.com/a.crl", false},
		{"http://", false},
		{"", false},
		{"://nonsense", false},
	}
	for _, test := range tests {
		err := validateHTTPURL(test.in)
		if test.valid {
			assert.NoError(t, err, test.in)
			continue
		}
		assert.Error(t, err, test.in)
	}
}

func TestRevocationStatusHelpers(t *testing.T) {
	var status *RevocationStatus
	assert.False(t, status.IsRevoked())
	assert.False(t, status.IsStale())
	assert.True(t, status.IsUnknown(), "a missing status is not a good status")

	assert.False(t, (&RevocationStatus{Status: "good"}).IsStale(), "no NextUpdate means never stale")
	assert.True(t, (&RevocationStatus{Status: "good", NextUpdate: time.Now().Add(-time.Hour)}).IsStale())
}

func TestRevocationAttemptString(t *testing.T) {
	withURL := RevocationAttempt{Source: RevocationSourceCRL, URL: "http://crl.example.com", Err: assertError{}}
	assert.Equal(t, "CRL http://crl.example.com: boom", withURL.String())

	withoutURL := RevocationAttempt{Source: RevocationSourceStaple, Err: assertError{}}
	assert.Equal(t, "stapled OCSP: boom", withoutURL.String())

	withoutSource := RevocationAttempt{Err: assertError{}}
	assert.Equal(t, "boom", withoutSource.String(), "no leading separator when there is no source")

	assert.Equal(t, "no reason given", RevocationAttempt{}.String())
}

type assertError struct{}

func (assertError) Error() string { return "boom" }

func TestRevocationCheckerRequestTimeout(t *testing.T) {

	t.Run("given no request timeout then the default applies", func(t *testing.T) {
		checker := NewRevocationChecker()
		assert.Equal(t, defaultRevocationRequestTimeout, checker.client().Timeout)
	})

	t.Run("given a request timeout then it is used", func(t *testing.T) {
		checker := &RevocationChecker{RequestTimeout: 45 * time.Second}
		assert.Equal(t, 45*time.Second, checker.client().Timeout)
	})

	t.Run("given a supplied client then its own timeout is left alone", func(t *testing.T) {
		own := &http.Client{Timeout: time.Minute}
		checker := &RevocationChecker{HTTPClient: own, RequestTimeout: time.Second}
		assert.Equal(t, time.Minute, checker.client().Timeout)
	})

	t.Run("given a short timeout then a silent responder is given up on", func(t *testing.T) {
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		responder.serve(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Second)
		})

		checker := &RevocationChecker{RequestTimeout: 300 * time.Millisecond}
		started := time.Now()
		status := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)
		elapsed := time.Since(started)

		assert.True(t, status.IsUnknown())
		assert.Less(t, elapsed, 3*time.Second, "the configured timeout must bound the wait")
	})
}
