package cert

import (
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
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
