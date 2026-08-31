package cert

import (
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// traced returns a logger writing into a buffer, as the command hands one in.
func traced() (*slog.Logger, *bytes.Buffer) {
	var out bytes.Buffer
	return slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})), &out
}

func TestRevocationCheckerTracesWhatItTried(t *testing.T) {
	chain := newOCSPTestChain(t)

	t.Run("given a logger, then what was tried is said", func(t *testing.T) {
		logger, out := traced()
		checker := &RevocationChecker{Logger: logger, SkipIssuerFetch: true}

		checker.Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Contains(t, out.String(), "checking revocation")
		assert.Contains(t, out.String(), chain.leaf.Subject.CommonName)
	})

	t.Run("given no logger, then the package says nothing and does not reach for the global one", func(t *testing.T) {
		// The package does not decide whether the caller wants to hear about
		// this. A nil logger is the caller saying no.
		original := slog.Default()
		var global bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&global, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(original) })

		checker := &RevocationChecker{SkipIssuerFetch: true}
		checker.Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Empty(t, global.String())
	})
}

func TestNetworkTracing(t *testing.T) {
	t.Run("given a logger, then the connection is described", func(t *testing.T) {
		logger, out := traced()

		// nothing listening, so this fails: the attempt is what is traced
		location := LoadFromNetwork("127.0.0.1:1", NetworkOptions{Logger: logger})
		require.Error(t, location.Error)

		assert.Contains(t, out.String(), "connecting")
		assert.Contains(t, out.String(), "connection failed")
		assert.Contains(t, out.String(), "127.0.0.1:1")
	})

	t.Run("given no logger, then nothing is written anywhere", func(t *testing.T) {
		original := slog.Default()
		var global bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&global, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(original) })

		location := LoadFromNetwork("127.0.0.1:1", NetworkOptions{})
		require.Error(t, location.Error)

		assert.Empty(t, global.String())
	})
}

func TestCRLCacheShowsInTheTrace(t *testing.T) {
	// A "reading" line without a "downloading" one after it is a list already
	// held, which is how a scan of many hosts behind one authority shows that
	// it downloaded the list once.
	logger, out := traced()
	checker := &RevocationChecker{Logger: logger}

	_, _ = checker.crlCache.get("http://example.invalid/one.crl", func() (*x509.RevocationList, error) {
		checker.log().Debug("downloading a CRL", slog.String("distribution_point", "http://example.invalid/one.crl"))
		return &x509.RevocationList{}, nil
	})
	_, _ = checker.crlCache.get("http://example.invalid/one.crl", func() (*x509.RevocationList, error) {
		checker.log().Debug("downloading a CRL", slog.String("distribution_point", "http://example.invalid/one.crl"))
		return &x509.RevocationList{}, nil
	})

	assert.Equal(t, 1, strings.Count(out.String(), "downloading a CRL"), "the second call is served from the cache")
}

// redirectingServer sends the first request somewhere else, and records what
// each of its two addresses was asked for.
func redirectingServer(t *testing.T) (start string, reached *[]string) {
	t.Helper()

	var asked []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, "target"+r.URL.Path)
		_, _ = w.Write([]byte("not a crl, but reaching here is the point"))
	}))
	t.Cleanup(target.Close)

	from := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, "start"+r.URL.Path)
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	}))
	t.Cleanup(from.Close)

	return from.URL + "/list.crl", &asked
}

func TestRedirectsAreNotFollowedByDefault(t *testing.T) {
	t.Run("given a redirect, then the second address is never asked", func(t *testing.T) {
		// The address came out of a certificate. Being sent from there to a
		// second address is a request nobody reading the certificate asked for,
		// and it can reach somewhere the certificate has no business naming.
		start, asked := redirectingServer(t)
		checker := &RevocationChecker{}

		_, err := checker.fetchCRL(context.Background(), start)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not where the certificate said")
		assert.Contains(t, err.Error(), "-follow-redirects")
		assert.Equal(t, []string{"start/list.crl"}, *asked, "only the address named was asked")
	})

	t.Run("given the flag, then it is followed and each hop is traced", func(t *testing.T) {
		start, asked := redirectingServer(t)
		logger, out := traced()
		checker := &RevocationChecker{FollowRedirects: true, Logger: logger}

		// it fails to parse, which is fine: reaching the second address is what
		// is being tested
		_, _ = checker.fetchCRL(context.Background(), start)

		assert.Equal(t, []string{"start/list.crl", "target/elsewhere"}, *asked)
		assert.Contains(t, out.String(), "following a redirect")
	})
}

func TestRedirectChainIsCapped(t *testing.T) {
	var server *httptest.Server
	var hops int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, server.URL+"/again", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	checker := &RevocationChecker{FollowRedirects: true}
	_, err := checker.fetchCRL(context.Background(), server.URL+"/start")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirected more than")
	assert.LessOrEqual(t, hops, maxRedirects+1, "the chain stops rather than running to Go's ten")
}
