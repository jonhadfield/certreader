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

// healthyCertificate builds a location whose certificate has nothing to warn
// about: a name, a modern key, and a lifetime inside the server limit.
func healthyCertificate(t *testing.T) cert.Location {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "healthy.example.com"},
		DNSNames:     []string{"healthy.example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert.Location{
		Path:         "healthy.example.com:443",
		ContentType:  cert.ContentTypeCertificate,
		Certificates: cert.FromX509Certificates([]*x509.Certificate{parsed}),
	}
}

func TestExitStatusFailOnWarning(t *testing.T) {

	// a lifetime beyond the server limit, and no subject alternative name.
	// It has to be signed by a CA: a self-signed certificate is classified a
	// root, and those rules apply only to end-entity certificates
	warned := certificateWithWarnings(t)
	require.NotEmpty(t, warned.Certificates[0].Warnings(), "fixture must actually warn")

	t.Run("given warnings and no flag then they do not fail the run", func(t *testing.T) {
		// whether a weak certificate should fail a check is a policy decision,
		// so it stays opt-in
		assert.Equal(t, exitOK, exitStatus(cert.Locations{warned}, Flags{}))
	})

	t.Run("given warnings and the flag then the check fails", func(t *testing.T) {
		assert.Equal(t, exitCheckFailed, exitStatus(cert.Locations{warned}, Flags{FailOnWarning: true}))
	})

	t.Run("given no warnings and the flag then it succeeds", func(t *testing.T) {
		healthy := healthyCertificate(t)
		require.Empty(t, healthy.Certificates[0].Warnings())

		assert.Equal(t, exitOK, exitStatus(cert.Locations{healthy}, Flags{FailOnWarning: true}))
	})

	t.Run("given a chain warning and the flag then the check fails", func(t *testing.T) {
		healthy := healthyCertificate(t)
		healthy.Verification = &cert.VerificationResult{
			OK:            true,
			ChainWarnings: []cert.Warning{{Code: cert.ChainWarningRootIncluded, Message: "the root is sent"}},
		}

		assert.Equal(t, exitCheckFailed, exitStatus(cert.Locations{healthy}, Flags{FailOnWarning: true}))
	})

	t.Run("given no verification then chain warnings are simply absent", func(t *testing.T) {
		// they are only computed by -verify, so without it there are none to
		// fail on rather than a nil to trip over
		healthy := healthyCertificate(t)
		require.Nil(t, healthy.Verification)

		assert.NotPanics(t, func() {
			assert.Equal(t, exitOK, exitStatus(cert.Locations{healthy}, Flags{FailOnWarning: true}))
		})
	})

	t.Run("given a revoked certificate then it fails regardless of the flag", func(t *testing.T) {
		healthy := healthyCertificate(t)
		healthy.Revocation = &cert.RevocationStatus{Status: "revoked"}

		assert.Equal(t, exitCheckFailed, exitStatus(cert.Locations{healthy}, Flags{}))
	})
}

func Test_hasWarnings(t *testing.T) {

	assert.False(t, hasWarnings(healthyCertificate(t)))
	assert.True(t, hasWarnings(certificateWithWarnings(t)))

	t.Run("given a certificate that failed to parse then it is skipped", func(t *testing.T) {
		location := cert.Location{
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.Certificates{{}},
		}
		assert.NotPanics(t, func() { assert.False(t, hasWarnings(location)) })
	})
}

// certificateWithWarnings builds a location whose certificate warns: it lives
// beyond the server limit and carries no subject alternative name. It is signed
// by a CA rather than itself, because a self-signed certificate is classified a
// root and those rules do not apply to roots.
func certificateWithWarnings(t *testing.T) cert.Location {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "warning test CA"},
		SubjectKeyId:          []byte{3, 3, 3},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(1000 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "warned.example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(500 * 24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return cert.Location{
		Path:         "warned.example.com:443",
		ContentType:  cert.ContentTypeCertificate,
		Certificates: cert.FromX509Certificates([]*x509.Certificate{leaf}),
	}
}

func Test_revocationIsRendered(t *testing.T) {
	// it decides whether the network work happens, so getting it wrong either
	// wastes requests or silently drops a result the user asked for

	assert.True(t, revocationIsRendered(Flags{}), "the default output shows it")
	assert.True(t, revocationIsRendered(Flags{JSON: true}))

	assert.False(t, revocationIsRendered(Flags{Expiry: true}), "expiry output has nowhere to put it")
	assert.False(t, revocationIsRendered(Flags{PemOnly: true}))

	// json wins over the narrower modes, so the work is still worth doing
	assert.True(t, revocationIsRendered(Flags{JSON: true, Expiry: true}))
	assert.True(t, revocationIsRendered(Flags{JSON: true, PemOnly: true}))
}
