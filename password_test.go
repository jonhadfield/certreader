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
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// pfxBundle builds a PKCS#12 bundle protected by the given password, which is
// what drives every branch of the prompting.
func pfxBundle(t *testing.T, password string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certreader password test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	encoder := pkcs12.Modern2023
	if password == "" {
		encoder = pkcs12.Passwordless
	}
	pfx, err := encoder.Encode(key, certificate, nil, password)
	require.NoError(t, err)
	return pfx
}

// lockedLocation is a location that failed to load because it needs a password,
// which is the state the prompting exists to resolve.
func lockedLocation(t *testing.T, path, password string) cert.Location {
	t.Helper()

	_, err := cert.FromBytes(pfxBundle(t, password), "")
	require.Error(t, err)

	var pwErr *cert.PasswordRequiredError
	require.ErrorAs(t, err, &pwErr, "the fixture must actually ask for a password")
	require.NotNil(t, pwErr.Data())

	return cert.Location{Path: path, Error: err}
}

// withPrompt substitutes the terminal for a scripted set of answers, and
// reports how many times it was asked.
func withPrompt(t *testing.T, answers []string, cancel bool) *int {
	t.Helper()

	asked := 0
	originalCan, originalPrompt := canPromptForPassword, promptForPasswordInput
	t.Cleanup(func() {
		canPromptForPassword, promptForPasswordInput = originalCan, originalPrompt
	})

	canPromptForPassword = func() bool { return true }
	promptForPasswordInput = func(_ string, attempt int) (string, bool) {
		asked++
		if cancel {
			return "", false
		}
		if attempt >= len(answers) {
			return "", false
		}
		return answers[attempt], true
	}
	return &asked
}

func TestPromptingResolvesPFX(t *testing.T) {

	t.Run("given the right password on the first ask then it is resolved", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"secret"}, false)

		flags := &Flags{}
		out := maybePromptForPFXPasswords(locations, flags)

		require.NoError(t, out[0].Error)
		require.NotEmpty(t, out[0].Certificates)
		assert.Equal(t, 1, *asked)
		assert.Equal(t, "secret", flags.PfxPassword,
			"the password is remembered so a second bundle is not asked for again")
	})

	t.Run("given two wrong answers then the third is still accepted", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"wrong", "alsowrong", "secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		require.NoError(t, out[0].Error)
		assert.Equal(t, 3, *asked)
	})

	t.Run("given three wrong answers then it gives up rather than asking forever", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"one", "two", "three"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		require.Error(t, out[0].Error)
		assert.Equal(t, 3, *asked, "three attempts, then stop")
	})

	t.Run("given the prompt is cancelled then it stops at once", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, nil, true)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		require.Error(t, out[0].Error)
		assert.Equal(t, 1, *asked, "a cancelled prompt is not retried")
	})

	t.Run("given an empty answer then it stops rather than retrying", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"", "secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		require.Error(t, out[0].Error, "an empty answer means the user declined")
		assert.Equal(t, 1, *asked)
	})
}

func TestPromptingUsesSuppliedPassword(t *testing.T) {

	t.Run("given the right password on the flag then nothing is asked", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{PfxPassword: "secret"})

		require.NoError(t, out[0].Error)
		assert.Zero(t, *asked, "the supplied password should be tried before the terminal")
	})

	t.Run("given the wrong password on the flag then the prompt takes over", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}
		asked := withPrompt(t, []string{"secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{PfxPassword: "wrong"})

		require.NoError(t, out[0].Error)
		assert.Equal(t, 1, *asked)
	})

	t.Run("given the wrong password and no terminal then it is left unresolved", func(t *testing.T) {
		// the non-interactive case: a script supplying the wrong password
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}

		originalCan := canPromptForPassword
		t.Cleanup(func() { canPromptForPassword = originalCan })
		canPromptForPassword = func() bool { return false }

		out := maybePromptForPFXPasswords(locations, &Flags{PfxPassword: "wrong"})

		require.Error(t, out[0].Error)
	})
}

func TestPromptingLeavesOtherLocationsAlone(t *testing.T) {

	t.Run("given no terminal then nothing is asked", func(t *testing.T) {
		locations := cert.Locations{lockedLocation(t, "bundle.pfx", "secret")}

		originalCan := canPromptForPassword
		t.Cleanup(func() { canPromptForPassword = originalCan })
		canPromptForPassword = func() bool { return false }

		out := maybePromptForPFXPasswords(locations, &Flags{})

		require.Error(t, out[0].Error, "a locked bundle stays locked rather than being skipped silently")
	})

	t.Run("given a location that needs no password then it is untouched", func(t *testing.T) {
		locations := cert.Locations{{Path: "fine.pem"}}
		asked := withPrompt(t, []string{"secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		assert.NoError(t, out[0].Error)
		assert.Zero(t, *asked)
	})

	t.Run("given an error that is not about a password then it is untouched", func(t *testing.T) {
		locations := cert.Locations{{Path: "broken.pem", Error: errors.New("no such file")}}
		asked := withPrompt(t, []string{"secret"}, false)

		out := maybePromptForPFXPasswords(locations, &Flags{})

		assert.Error(t, out[0].Error)
		assert.Zero(t, *asked)
	})

	t.Run("given several locations then each is handled in turn", func(t *testing.T) {
		locations := cert.Locations{
			lockedLocation(t, "one.pfx", "secret"),
			{Path: "fine.pem"},
			lockedLocation(t, "two.pfx", "secret"),
		}
		asked := withPrompt(t, []string{"secret"}, false)

		flags := &Flags{}
		out := maybePromptForPFXPasswords(locations, flags)

		require.NoError(t, out[0].Error)
		require.NoError(t, out[2].Error)
		assert.Equal(t, 1, *asked,
			"the password from the first is reused for the second rather than asked again")
	})
}
