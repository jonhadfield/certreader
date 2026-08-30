package main

import (
	"io"
	"os"

	"github.com/jonhadfield/certreader/pkg/cert"
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
		assert.Empty(t, flags.StartTLS)
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

func TestFilterFlagDescriptions(t *testing.T) {
	// The two descriptions were each other's: -subject-like said it matched
	// the issuer field, and -issuer-like the subject. Both filters have always
	// worked on the field they are named for, so only the help was wrong,
	// which is the worse way round. The flag that does what you want is the
	// one the help talks you out of picking.
	t.Run("given the usage text, then each filter flag describes the field it filters on", func(t *testing.T) {
		setInput(t, nil, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		usage := captureStderr(t, flags.Usage)

		assert.Regexp(t, `-subject-like string\n\s+print certificates with subject field`, usage)
		assert.Regexp(t, `-issuer-like string\n\s+print certificates with issuer field`, usage)
	})
}

// --- helper functions ---

// captureStderr collects what a function writes to stderr, which is where the
// flag package prints usage.
func captureStderr(t *testing.T, write func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = original }()

	write()
	require.NoError(t, writer.Close())

	captured, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	return string(captured)
}

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

func TestParseFlagsStartTLS(t *testing.T) {

	t.Run("given a supported protocol then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag", "-starttls=smtp"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, cert.StartTLSSMTP, flags.StartTLS)
	})

	t.Run("given the env var then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_STARTTLS": "imap"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, cert.StartTLSIMAP, flags.StartTLS)
	})

	t.Run("given an unsupported protocol then parsing fails", func(t *testing.T) {
		setInput(t, []string{"flag", "-starttls=telnet"}, nil)

		_, err := ParseFlags()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-starttls")
	})

	t.Run("given no protocol then direct tls is used", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, cert.StartTLSNone, flags.StartTLS)
	})
}

func Test_defaultPort(t *testing.T) {
	assert.Equal(t, "443", defaultPort(cert.StartTLSNone))
	assert.Equal(t, "587", defaultPort(cert.StartTLSSMTP))
	assert.Equal(t, "389", defaultPort(cert.StartTLSLDAP))
}

func Test_parseTimeout(t *testing.T) {

	valid := map[string]time.Duration{
		"5s":     5 * time.Second,
		"500ms":  500 * time.Millisecond,
		"2m":     2 * time.Minute,
		"1m30s":  90 * time.Second,
		" 10s  ": 10 * time.Second,
	}
	for in, expected := range valid {
		out, err := parseTimeout(in)
		require.NoError(t, err, in)
		assert.Equal(t, expected, out, in)
	}

	// a timeout is not a span of days, so those suffixes would only invite mistakes
	for _, in := range []string{"", "  ", "0", "-5s", "abc", "30d", "5"} {
		_, err := parseTimeout(in)
		assert.Error(t, err, "%q should be rejected", in)
	}
}

func TestParseFlagsTimeout(t *testing.T) {

	t.Run("given no flag then the default applies", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, defaultTimeout, flags.Timeout)
	})

	t.Run("given a flag then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag", "-timeout=20s"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, 20*time.Second, flags.Timeout)
	})

	t.Run("given the env var then it is parsed", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_TIMEOUT": "1m"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, time.Minute, flags.Timeout)
	})

	t.Run("given an invalid value then parsing fails", func(t *testing.T) {
		setInput(t, []string{"flag", "-timeout=soon"}, nil)

		_, err := ParseFlags()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-timeout")
	})

	t.Run("given the default then the derived revocation timeouts match the old hardcoded ones", func(t *testing.T) {
		// the defaults must not shift just because they became configurable
		assert.Equal(t, 10*time.Second, defaultTimeout*revocationRequestMultiple)
		assert.Equal(t, 30*time.Second, defaultTimeout*revocationBudgetMultiple)
	})
}

func TestParseFlagsVerify(t *testing.T) {

	t.Run("given no flag then verification is off", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.False(t, flags.Verify)
	})

	t.Run("given the flag then it is set", func(t *testing.T) {
		setInput(t, []string{"flag", "-verify=true"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.True(t, flags.Verify)
	})

	t.Run("given the env var then it is set", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_VERIFY": "true"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.True(t, flags.Verify)
	})
}

func TestParseFlagsFailOnWarning(t *testing.T) {

	t.Run("given no flag then warnings do not affect the exit code", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.False(t, flags.FailOnWarning)
	})

	t.Run("given the flag then it is set", func(t *testing.T) {
		setInput(t, []string{"flag", "-fail-on-warning=true"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.True(t, flags.FailOnWarning)
	})

	t.Run("given the env var then it is set", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_FAIL_ON_WARNING": "true"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.True(t, flags.FailOnWarning)
	})
}

func TestParseFlagsConcurrency(t *testing.T) {

	t.Run("given no flag then the default applies", func(t *testing.T) {
		setInput(t, []string{"flag"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, defaultConcurrency, flags.Concurrency)
	})

	t.Run("given a limit then it is used", func(t *testing.T) {
		setInput(t, []string{"flag", "-concurrency=8"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, 8, flags.Concurrency)
	})

	t.Run("given zero then there is no limit", func(t *testing.T) {
		setInput(t, []string{"flag", "-concurrency=0"}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Zero(t, flags.Concurrency)
	})

	t.Run("given the env var then it is used", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_CONCURRENCY": "16"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, 16, flags.Concurrency)
	})

	t.Run("given a negative limit then parsing fails", func(t *testing.T) {
		setInput(t, []string{"flag", "-concurrency=-1"}, nil)

		_, err := ParseFlags()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-concurrency")
	})

	t.Run("given a nonsense env var then the default applies", func(t *testing.T) {
		setInput(t, []string{"flag"}, map[string]string{"CERTREADER_CONCURRENCY": "lots"})

		flags, err := ParseFlags()
		require.NoError(t, err)
		assert.Equal(t, defaultConcurrency, flags.Concurrency)
	})
}
