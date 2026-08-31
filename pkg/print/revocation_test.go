package print

import (
	"errors"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func Test_printRevocation(t *testing.T) {

	t.Run("given an OCSP verdict then source and metadata are printed", func(t *testing.T) {
		location := cert.Location{
			Path:        "certreader.test:443",
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:            cert.RevocationSourceOCSP,
				URL:               "http://ocsp.example.com",
				Status:            "good",
				SerialNumber:      "01:02:03",
				ProducedAt:        time.Now().Add(-time.Hour),
				ThisUpdate:        time.Now().Add(-time.Hour),
				NextUpdate:        time.Now().Add(24 * time.Hour),
				SignatureVerified: true,
			},
		}

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "Revocation")
		assert.Contains(t, output, "good")
		assert.Contains(t, output, "OCSP responder (http://ocsp.example.com)")
		assert.Contains(t, output, "01:02:03")
		assert.Contains(t, output, "Produced At")
		assert.Contains(t, output, "verified against issuer")
		assert.NotContains(t, output, "Not Answered")
		assert.NotContains(t, output, "[stale]")
	})

	t.Run("given a revoked verdict then reason and time are printed", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:           cert.RevocationSourceCRL,
				URL:              "http://crl.example.com/a.crl",
				Status:           "revoked",
				RevokedAt:        time.Now().Add(-48 * time.Hour),
				RevocationReason: "key compromise",
				ThisUpdate:       time.Now().Add(-time.Hour),
			},
		}

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "revoked")
		assert.Contains(t, output, "Revoked At")
		assert.Contains(t, output, "key compromise")
		assert.Contains(t, output, "CRL (http://crl.example.com/a.crl)")
		assert.Contains(t, output, "not verified (issuer certificate unavailable)")
		assert.NotContains(t, output, "Produced At", "CRLs carry no producedAt")
	})

	t.Run("given a staple verdict then no endpoint is shown", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:            cert.RevocationSourceStaple,
				Status:            "good",
				SignatureVerified: true,
			},
		}

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "stapled OCSP")
		assert.NotContains(t, output, "(")
	})

	t.Run("given an unknown verdict then the failed sources are listed", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Status: "unknown",
				Attempts: []cert.RevocationAttempt{
					{Source: cert.RevocationSourceOCSP, URL: "http://ocsp.example.com", Err: errors.New("connection refused")},
					{Source: cert.RevocationSourceCRL, URL: "http://crl.example.com", Err: errors.New("unexpected response status 404 Not Found")},
				},
			},
		}

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "unknown")
		assert.Contains(t, output, "Not Answered")
		assert.Contains(t, output, "OCSP responder http://ocsp.example.com: connection refused")
		assert.Contains(t, output, "CRL http://crl.example.com: unexpected response status 404 Not Found")
		assert.NotContains(t, output, "Signature", "nothing was authenticated")
	})

	t.Run("given a stale verdict then it is marked", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:     cert.RevocationSourceCRL,
				Status:     "good",
				ThisUpdate: time.Now().Add(-48 * time.Hour),
				NextUpdate: time.Now().Add(-24 * time.Hour),
			},
		}

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "[stale]")
	})

	t.Run("given no check was requested then the staple block is printed instead", func(t *testing.T) {
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)

		output := captureStdout(t, func() { printRevocation(location) })

		assert.Contains(t, output, "OCSP Staple")
		assert.NotContains(t, output, "Revocation")
	})

	t.Run("given neither a check nor a staple then nothing is printed", func(t *testing.T) {
		chain := newStapleTestChain(t)

		output := captureStdout(t, func() { printRevocation(chain.location(nil, true)) })

		assert.Empty(t, output)
	})
}

func Test_revocationSource(t *testing.T) {
	withURL := &cert.RevocationStatus{Source: cert.RevocationSourceOCSP, URL: "http://ocsp.example.com"}
	assert.Equal(t, "OCSP responder (http://ocsp.example.com)", revocationSource(withURL))

	withoutURL := &cert.RevocationStatus{Source: cert.RevocationSourceStaple}
	assert.Equal(t, "stapled OCSP", revocationSource(withoutURL))
}

func TestLocationsPrintsRevocation(t *testing.T) {
	chain := newStapleTestChain(t)
	location := chain.location(nil, true)
	location.Revocation = &cert.RevocationStatus{
		Source:            cert.RevocationSourceOCSP,
		URL:               "http://ocsp.example.com",
		Status:            "revoked",
		RevokedAt:         time.Now().Add(-time.Hour),
		RevocationReason:  "superseded",
		SignatureVerified: true,
	}

	output := captureStdout(t, func() {
		Locations(cert.Locations{location}, Options{})
	})

	assert.Contains(t, output, "certreader.test:443")
	assert.Contains(t, output, "Revocation")
	assert.Contains(t, output, "revoked")
	assert.Contains(t, output, "superseded")
}
