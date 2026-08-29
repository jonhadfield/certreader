package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certificateExpiring builds a location holding one certificate that expires at
// the given time, so the checks can be driven without touching the network.
func certificateExpiring(t *testing.T, notAfter time.Time) cert.Location {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certreader.test"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert.Location{
		Path:         "certreader.test:443",
		ContentType:  cert.ContentTypeCertificate,
		Certificates: cert.FromX509Certificates([]*x509.Certificate{parsed}),
	}
}

func TestExitStatus(t *testing.T) {

	healthy := func(t *testing.T) cert.Location {
		return certificateExpiring(t, time.Now().Add(365*24*time.Hour))
	}

	t.Run("given nothing to report then it succeeds", func(t *testing.T) {
		assert.Equal(t, exitOK, exitStatus(nil, Flags{}))
	})

	t.Run("given a healthy certificate and no checks then it succeeds", func(t *testing.T) {
		assert.Equal(t, exitOK, exitStatus(cert.Locations{healthy(t)}, Flags{}))
	})

	t.Run("given a location that failed to load then it reports a load error", func(t *testing.T) {
		locations := cert.Locations{{Path: "missing.pem", Error: errors.New("no such file")}}
		assert.Equal(t, exitLoadError, exitStatus(locations, Flags{}))
	})

	t.Run("given a revoked certificate then the check fails", func(t *testing.T) {
		location := healthy(t)
		location.Revocation = &cert.RevocationStatus{Status: "revoked"}
		assert.Equal(t, exitCheckFailed, exitStatus(cert.Locations{location}, Flags{}))
	})

	t.Run("given a good revocation result then it succeeds", func(t *testing.T) {
		location := healthy(t)
		location.Revocation = &cert.RevocationStatus{Status: "good"}
		assert.Equal(t, exitOK, exitStatus(cert.Locations{location}, Flags{}))
	})

	t.Run("given an unknown revocation result then it succeeds", func(t *testing.T) {
		// unknown is not a failed check: nothing was proven either way, and
		// treating it as failure would alert on every unreachable responder
		location := healthy(t)
		location.Revocation = &cert.RevocationStatus{Status: "unknown"}
		assert.Equal(t, exitOK, exitStatus(cert.Locations{location}, Flags{}))
	})

	t.Run("given both a load error and a revocation then the check outranks it", func(t *testing.T) {
		revoked := healthy(t)
		revoked.Revocation = &cert.RevocationStatus{Status: "revoked"}
		locations := cert.Locations{
			{Path: "missing.pem", Error: errors.New("no such file")},
			revoked,
		}
		assert.Equal(t, exitCheckFailed, exitStatus(locations, Flags{}))
	})

	t.Run("given a certificate inside the window then the check fails", func(t *testing.T) {
		locations := cert.Locations{certificateExpiring(t, time.Now().Add(5*24*time.Hour))}
		flags := Flags{ExpiringWithin: "30d", ExpiringWindow: 30 * 24 * time.Hour}
		assert.Equal(t, exitCheckFailed, exitStatus(locations, flags))
	})

	t.Run("given a certificate outside the window then it succeeds", func(t *testing.T) {
		locations := cert.Locations{certificateExpiring(t, time.Now().Add(90*24*time.Hour))}
		flags := Flags{ExpiringWithin: "30d", ExpiringWindow: 30 * 24 * time.Hour}
		assert.Equal(t, exitOK, exitStatus(locations, flags))
	})

	t.Run("given an expired certificate then any window catches it", func(t *testing.T) {
		locations := cert.Locations{certificateExpiring(t, time.Now().Add(-24*time.Hour))}
		flags := Flags{ExpiringWithin: "0", ExpiringWindow: 0}
		assert.Equal(t, exitCheckFailed, exitStatus(locations, flags))
	})

	t.Run("given no window was asked for then expiry is not checked", func(t *testing.T) {
		locations := cert.Locations{certificateExpiring(t, time.Now().Add(-24*time.Hour))}
		assert.Equal(t, exitOK, exitStatus(locations, Flags{}), "an expired certificate alone is not a failure")
	})

	t.Run("given one healthy and one expiring location then the check fails", func(t *testing.T) {
		locations := cert.Locations{
			certificateExpiring(t, time.Now().Add(365*24*time.Hour)),
			certificateExpiring(t, time.Now().Add(time.Hour)),
		}
		flags := Flags{ExpiringWithin: "7d", ExpiringWindow: 7 * 24 * time.Hour}
		assert.Equal(t, exitCheckFailed, exitStatus(locations, flags))
	})
}

func Test_expiresWithin(t *testing.T) {

	t.Run("given a certificate that failed to parse then it is skipped", func(t *testing.T) {
		location := cert.Location{
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.Certificates{{}},
		}
		// must not panic: the accessors are unsafe on an unparsed certificate
		assert.NotPanics(t, func() {
			assert.False(t, expiresWithin(location, 30*24*time.Hour))
		})
	})

	t.Run("given a boundary case then expiry exactly at the window counts", func(t *testing.T) {
		location := certificateExpiring(t, time.Now().Add(24*time.Hour))
		assert.True(t, expiresWithin(location, 25*time.Hour))
		assert.False(t, expiresWithin(location, 23*time.Hour))
	})
}

func Test_parseExpiryWindow(t *testing.T) {

	valid := []struct {
		in       string
		expected time.Duration
	}{
		{"30d", 30 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"72h", 72 * time.Hour},
		{"90m", 90 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"0", 0},
		{"0d", 0},
		{"1.5d", 36 * time.Hour},
		{" 30d ", 30 * 24 * time.Hour},
	}
	for _, test := range valid {
		window, err := parseExpiryWindow(test.in)
		require.NoError(t, err, test.in)
		assert.Equal(t, test.expected, window, test.in)
	}

	invalid := []string{"", "   ", "abc", "30x", "-5d", "-1h", "d", "1d12h"}
	for _, test := range invalid {
		_, err := parseExpiryWindow(test)
		assert.Error(t, err, "%q should be rejected", test)
	}
}
