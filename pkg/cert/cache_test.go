package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func Test_singleFlightCache(t *testing.T) {

	t.Run("given repeated asks then the value is fetched once", func(t *testing.T) {
		var cache singleFlightCache[int]
		var calls atomic.Int64

		for i := 0; i < 5; i++ {
			value, err := cache.get("key", func() (int, error) {
				calls.Add(1)
				return 42, nil
			})
			require.NoError(t, err)
			assert.Equal(t, 42, value)
		}
		assert.Equal(t, int64(1), calls.Load())
	})

	t.Run("given simultaneous asks then the value is still fetched once", func(t *testing.T) {
		// this is the case a plain map does not handle: every goroutine misses
		// together, so every one fetches
		var cache singleFlightCache[int]
		var calls atomic.Int64

		release := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				value, err := cache.get("key", func() (int, error) {
					calls.Add(1)
					<-release // hold the fetch open so the others pile up behind it
					return 7, nil
				})
				assert.NoError(t, err)
				assert.Equal(t, 7, value)
			}()
		}

		// give the goroutines time to arrive, then let the one fetch finish
		time.Sleep(50 * time.Millisecond)
		close(release)
		wg.Wait()

		assert.Equal(t, int64(1), calls.Load(), "one fetch should serve all of them")
	})

	t.Run("given different keys then each is fetched", func(t *testing.T) {
		var cache singleFlightCache[string]
		var calls atomic.Int64

		for _, key := range []string{"a", "b", "a", "b", "c"} {
			_, err := cache.get(key, func() (string, error) {
				calls.Add(1)
				return key, nil
			})
			require.NoError(t, err)
		}
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, 3, cache.len())
	})

	t.Run("given a failure then it is not remembered", func(t *testing.T) {
		// a transient failure should not poison the key for the rest of the run
		var cache singleFlightCache[int]
		var calls atomic.Int64

		_, err := cache.get("key", func() (int, error) {
			calls.Add(1)
			return 0, errors.New("boom")
		})
		require.Error(t, err)
		assert.Zero(t, cache.len(), "a failed fetch should leave nothing behind")

		value, err := cache.get("key", func() (int, error) {
			calls.Add(1)
			return 9, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 9, value)
		assert.Equal(t, int64(2), calls.Load(), "the second caller should get its own attempt")
	})
}

func TestCRLIsFetchedOncePerURL(t *testing.T) {

	t.Run("given many certificates behind one distribution point then it is downloaded once", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		checker := NewRevocationChecker()
		for i := 0; i < 4; i++ {
			status := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)
			require.Equal(t, "good", status.Status)
		}

		assert.Equal(t, int64(1), crlPoint.calls.Load(),
			"a crl from a public ca can be tens of megabytes")
	})

	t.Run("given concurrent checks then it is still downloaded once", func(t *testing.T) {
		// the shape that matters: CheckRevocation starts every location at once
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		checker := NewRevocationChecker()
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				status := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)
				assert.Equal(t, "good", status.Status)
			}()
		}
		wg.Wait()

		assert.Equal(t, int64(1), crlPoint.calls.Load())
	})

	t.Run("given a cached crl then the signature is still checked per certificate", func(t *testing.T) {
		// two hosts can share a distribution point without sharing an issuer,
		// so the cache must not carry the verification with it
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		other := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))

		checker := NewRevocationChecker()

		good := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)
		assert.Equal(t, "good", good.Status)

		// the same cached list, checked against an issuer that did not sign it
		bad := checker.Check(context.Background(), other.leaf, other.issuer, nil)
		assert.True(t, bad.IsUnknown())
		require.NotEmpty(t, bad.Attempts)
		assert.Contains(t, bad.Attempts[len(bad.Attempts)-1].Err.Error(), "bad CRL signature")

		assert.Equal(t, int64(1), crlPoint.calls.Load())
	})

	t.Run("given a failed download then a later check retries", func(t *testing.T) {
		crlPoint := newStubServer(t)
		chain := newOCSPTestChain(t, withCRLPoint(crlPoint.URL))
		crlPoint.serveStatus(http.StatusInternalServerError)

		checker := NewRevocationChecker()
		first := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)
		assert.True(t, first.IsUnknown())

		crlPoint.serveBytes("application/pkix-crl", chain.crl(t, time.Now().Add(24*time.Hour)))
		second := checker.Check(context.Background(), chain.leaf, chain.issuer, nil)

		assert.Equal(t, "good", second.Status, "a failure must not be cached")
		assert.Equal(t, int64(2), crlPoint.calls.Load())
	})
}

func TestIssuerIsFetchedOnceConcurrently(t *testing.T) {
	// the issuer cache had the same flaw, and shares the fix
	issuerServer := newStubServer(t)
	responder := newStubServer(t)
	chain := newOCSPTestChain(t, withIssuerURL(issuerServer.URL), withOCSPServer(responder.URL))
	issuerServer.serveBytes("application/pkix-cert", chain.issuer.Raw)
	responder.serveBytes(ocspResponseContentType, chain.response(t, ocsp.Response{Status: ocsp.Good}))

	checker := NewRevocationChecker()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status := checker.Check(context.Background(), chain.leaf, nil, nil)
			assert.Equal(t, "good", status.Status)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), issuerServer.calls.Load())
}

func TestCheckRevocationConcurrencyCap(t *testing.T) {

	// a responder that reports the most requests it ever had in flight, since
	// that is the only thing worth asserting about a cap
	measure := func(t *testing.T, limit int) int64 {
		t.Helper()

		var inFlight, peak atomic.Int64
		responder := newStubServer(t)
		chain := newOCSPTestChain(t, withOCSPServer(responder.URL))
		response := chain.response(t, ocsp.Response{Status: ocsp.Good})

		responder.serve(func(w http.ResponseWriter, _ *http.Request) {
			current := inFlight.Add(1)
			for {
				highest := peak.Load()
				if current <= highest || peak.CompareAndSwap(highest, current) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			_, _ = w.Write(response)
		})

		var locations Locations
		for i := 0; i < 24; i++ {
			locations = append(locations, Location{
				Path:         "host.test:443",
				ContentType:  ContentTypeCertificate,
				Certificates: FromX509Certificates([]*x509.Certificate{chain.leaf, chain.issuer}),
			})
		}

		checker := &RevocationChecker{Concurrency: limit}
		for _, location := range locations.CheckRevocation(context.Background(), checker) {
			require.Equal(t, "good", location.Revocation.Status)
		}
		return peak.Load()
	}

	t.Run("given a limit then no more checks run at once", func(t *testing.T) {
		assert.LessOrEqual(t, measure(t, 3), int64(3))
	})

	t.Run("given no limit then they are not held back", func(t *testing.T) {
		// every location starts at once, which is the behaviour the cap bounds
		assert.Greater(t, measure(t, 0), int64(3))
	})
}
