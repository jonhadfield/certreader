package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {

	t.Run("given empty args and env vars then flags are set to default values", func(t *testing.T) {

		setInput(t, nil, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.False(t, flags.Expiry)
		assert.False(t, flags.Insecure)
		assert.False(t, flags.Revocation)
		assert.False(t, flags.Chains)
		assert.False(t, flags.Pem)
		assert.False(t, flags.PemOnly)
		assert.False(t, flags.JSON)
		assert.Empty(t, flags.ExpiringWithin)
		assert.Zero(t, flags.ExpiringWindow)
		assert.False(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are set and env vars empty then flags are set to provided args", func(t *testing.T) {

		setInput(t, []string{"flag",
			"-expiry=true",
			"-insecure=true",
			"-revocation=true",
			"-chains=true",
			"-chains=true",
			"-pem=true",
			"-pem-only=true",
			"-json=true",
			"-version=true",
		}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.True(t, flags.Revocation)
		assert.True(t, flags.Chains)
		assert.True(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.True(t, flags.JSON)
		assert.True(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are not set and env vars are set then flags are set to provided env vars", func(t *testing.T) {

		setInput(t, []string{"flag"}, map[string]string{
			"CERTREADER_EXPIRY":     "true",
			"CERTREADER_INSECURE":   "true",
			"CERTREADER_REVOCATION": "true",
			"CERTREADER_CHAINS":     "true",
			"CERTREADER_PEM":        "true",
			"CERTREADER_PEM_ONLY":   "true",
			"CERTREADER_JSON":       "true",
			"CERTREADER_VERSION":    "true",
		})

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.True(t, flags.Revocation)
		assert.True(t, flags.Chains)
		assert.True(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.True(t, flags.JSON)
		assert.True(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are set and env vars are set then flags are set to provided args", func(t *testing.T) {

		setInput(t, []string{"flag",
			"-insecure=true",
			"-revocation=false",
			"-chains=true",
			"-pem=false",
			"-version=false",
		}, map[string]string{
			"CERTREADER_EXPIRY":     "true",
			"CERTREADER_REVOCATION": "true",
			"CERTREADER_CHAINS":     "true",
			"CERTREADER_PEM":        "true",
			"CERTREADER_PEM_ONLY":   "true",
			"CERTREADER_VERSION":    "true",
		})

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.False(t, flags.Revocation, "flag overrides env")
		assert.True(t, flags.Chains)
		assert.False(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.False(t, flags.Version)
		assert.Empty(t, flags.Args)
	})
}

// --- helper functions ---

func setInput(t *testing.T, args []string, env map[string]string) {

	osArgs := os.Args
	if args == nil {
		args = []string{"test"}
	}

	os.Args = args
	for k, v := range env {
		os.Setenv(k, v)
	}

	t.Cleanup(func() {
		os.Args = osArgs
		for k := range env {
			os.Unsetenv(k)
		}
	})
}

func TestParseFlagsExpiringWithin(t *testing.T) {

	t.Run("given a valid window then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag", "-expiring-within=30d"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.Equal(t, "30d", flags.ExpiringWithin)
		assert.Equal(t, 30*24*time.Hour, flags.ExpiringWindow)
	})

	t.Run("given the env var then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_EXPIRING_WITHIN": "2w"})

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.Equal(t, 14*24*time.Hour, flags.ExpiringWindow)
	})

	t.Run("given an invalid window then parsing fails", func(t *testing.T) {
		setInput(t, []string{"flag", "-expiring-within=soon"}, nil)

		_, err := ParseFlags()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-expiring-within")
	})

	t.Run("given no window then the check stays off", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.Empty(t, flags.ExpiringWithin, "empty is what keeps a zero window meaningful")
	})
}
