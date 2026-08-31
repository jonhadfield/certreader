package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"golang.design/x/clipboard"
)

type Flags struct {
	Usage       func()
	CSR         bool
	Expiry      bool
	NoDuplicate bool
	NoExpired   bool
	SortExpiry  bool
	SubjectLike string
	IssuerLike  string
	// ExpiringWithin is the raw flag value; empty means the check is off, so
	// that a window of zero stays meaningful as "already expired".
	ExpiringWithin string
	ExpiringWindow time.Duration
	ServerName     string
	// StartTLS names a protocol to upgrade from plaintext, empty for direct TLS.
	StartTLS cert.StartTLSProtocol
	// TimeoutRaw is the raw flag value, Timeout its parsed form.
	TimeoutRaw string
	Timeout    time.Duration
	Insecure   bool
	Revocation bool
	Verify     bool
	// FailOnWarning widens what counts as a failed check to include warnings,
	// which are otherwise reported without affecting the exit code.
	FailOnWarning bool
	// Concurrency bounds how many locations are read at once. Zero means no
	// bound.
	Concurrency int
	Chains      bool
	Compare     bool
	Fingerprint bool
	Extensions  bool
	Signature   bool
	Pem         bool
	PemOnly     bool
	JSON        bool
	Verbose     bool
	Version     bool
	More        bool
	Clipboard   bool
	PfxPassword string
	Args        []string
}

func ParseFlags() (Flags, error) {

	var flags Flags
	var startTLS string
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.BoolVar(&flags.CSR, "csr", getBoolEnv("CERTREADER_CSR", false),
		"force CSR mode (optional - CSRs are auto-detected)")
	flagSet.BoolVar(&flags.Expiry, "expiry", getBoolEnv("CERTREADER_EXPIRY", false),
		"print expiry of certificates")
	flagSet.BoolVar(&flags.NoDuplicate, "no-duplicate", getBoolEnv("CERTREADER_NO_DUPLICATE", false),
		"do not print duplicate certificates")
	flagSet.BoolVar(&flags.NoExpired, "no-expired", getBoolEnv("CERTREADER_NO_EXPIRED", false),
		"do not print expired certificates")
	flagSet.BoolVar(&flags.SortExpiry, "sort-expiry", getBoolEnv("CERTREADER_SORT_EXPIRY", false),
		"sort certificates by expiration date")
	flagSet.StringVar(&flags.SubjectLike, "subject-like", getStringEnv("CERTREADER_SUBJECT_LIKE", ""),
		"print certificates with subject field containing supplied string")
	flagSet.StringVar(&flags.IssuerLike, "issuer-like", getStringEnv("CERTREADER_ISSUER_LIKE", ""),
		"print certificates with issuer field containing supplied string")
	flagSet.StringVar(&flags.ExpiringWithin, "expiring-within", getStringEnv("CERTREADER_EXPIRING_WITHIN", ""),
		"exit non-zero if any certificate expires within this window, e.g. 30d, 2w, 72h")
	flagSet.StringVar(&flags.ServerName, "server-name", getStringEnv("CERTREADER_SERVER_NAME", ""),
		"verify the hostname on the returned certificates, useful for testing SNI")
	flagSet.StringVar(&startTLS, "starttls", getStringEnv("CERTREADER_STARTTLS", ""),
		fmt.Sprintf("upgrade a plaintext connection to tls, one of: %s", strings.Join(cert.StartTLSProtocols(), ", ")))
	flagSet.StringVar(&flags.TimeoutRaw, "timeout", getStringEnv("CERTREADER_TIMEOUT", defaultTimeout.String()),
		"how long to wait for a connection, and proportionally longer for revocation requests")
	flagSet.BoolVar(&flags.Insecure, "insecure", getBoolEnv("CERTREADER_INSECURE", false),
		"whether a client verifies the server's certificate chain and host name (only applicable for host)")
	flagSet.BoolVar(&flags.Revocation, "revocation", getBoolEnv("CERTREADER_REVOCATION", false),
		"check revocation status via OCSP, falling back to CRL (makes network requests)")
	flagSet.IntVar(&flags.Concurrency, "concurrency", getIntEnv("CERTREADER_CONCURRENCY", defaultConcurrency),
		"how many locations to read at once, 0 for no limit")
	flagSet.BoolVar(&flags.FailOnWarning, "fail-on-warning", getBoolEnv("CERTREADER_FAIL_ON_WARNING", false),
		"exit non-zero if any certificate or chain warning is reported")
	flagSet.BoolVar(&flags.Verify, "verify", getBoolEnv("CERTREADER_VERIFY", false),
		"verify against the system trust store and report why it fails")
	flagSet.BoolVar(&flags.Compare, "compare", getBoolEnv("CERTREADER_COMPARE", false),
		"compare two locations and report whether they serve the same certificate")
	flagSet.BoolVar(&flags.Fingerprint, "fingerprint", getBoolEnv("CERTREADER_FINGERPRINT", false),
		"print the sha-256 of the certificate and of its public key")
	flagSet.BoolVar(&flags.Chains, "chains", getBoolEnv("CERTREADER_CHAINS", false),
		"whether to print verified chains as well (only applicable for host)")
	flagSet.BoolVar(&flags.Extensions, "extensions", getBoolEnv("CERTREADER_EXTENSIONS", false),
		"whether to print extensions")
	flagSet.BoolVar(&flags.Signature, "signature", getBoolEnv("CERTREADER_SIGNATURE", false),
		"whether to print signature")
	flagSet.BoolVar(&flags.Pem, "pem", getBoolEnv("CERTREADER_PEM", false),
		"whether to print pem as well")
	flagSet.BoolVar(&flags.PemOnly, "pem-only", getBoolEnv("CERTREADER_PEM_ONLY", false),
		"whether to print only pem (useful for downloading certs from host)")
	flagSet.BoolVar(&flags.JSON, "json", getBoolEnv("CERTREADER_JSON", false),
		"output as json (takes precedence over -expiry and -pem-only)")
	flagSet.StringVar(&flags.PfxPassword, "pfx-password", getStringEnv("CERTREADER_PFX_PASSWORD", ""),
		"password for PKCS#12/PFX bundles (defaults to empty)")
	if isClipboardSupported() {
		flagSet.BoolVar(&flags.Clipboard, "clipboard", false,
			"read input from clipboard")
	}
	flagSet.BoolVar(&flags.Verbose, "verbose", getBoolEnv("CERTREADER_VERBOSE", false),
		"verbose logging")
	flagSet.BoolVar(&flags.Version, "version", getBoolEnv("CERTREADER_VERSION", false),
		"certreader version")
	flagSet.BoolVar(&flags.More, "more", getBoolEnv("CERTREADER_MORE", false), "combination of '-pem -signature -chains'")

	flagSet.Usage = func() {
		// usage goes wherever the flag package is writing; a failed write there
		// is nothing this can do anything about
		_, _ = fmt.Fprint(flagSet.Output(), "Usage: certreader [flags] [<file>|<host:port> ...]\n")
		flagSet.PrintDefaults()
	}
	flags.Usage = flagSet.Usage

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return Flags{}, err
	}
	flags.Args = flagSet.Args()

	timeout, err := parseTimeout(flags.TimeoutRaw)
	if err != nil {
		return Flags{}, fmt.Errorf("-timeout: %w", err)
	}
	flags.Timeout = timeout

	if flags.Concurrency < 0 {
		return Flags{}, fmt.Errorf("-concurrency: %d is negative", flags.Concurrency)
	}

	protocol, err := cert.ParseStartTLSProtocol(startTLS)
	if err != nil {
		return Flags{}, fmt.Errorf("-starttls: %w", err)
	}
	flags.StartTLS = protocol

	if flags.ExpiringWithin != "" {
		window, err := parseExpiryWindow(flags.ExpiringWithin)
		if err != nil {
			return Flags{}, fmt.Errorf("-expiring-within: %w", err)
		}
		flags.ExpiringWindow = window
	}

	// Combination of flags
	if flags.More {
		flags.Pem = true
		flags.Signature = true
		flags.Chains = true
	}

	return flags, nil
}

func getStringEnv(envName string, defaultValue string) string {

	if env, ok := os.LookupEnv(envName); ok {
		return env
	}
	return defaultValue
}

func getBoolEnv(envName string, defaultValue bool) bool {

	env, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}

	if intValue, err := strconv.ParseBool(env); err == nil {
		return intValue
	}
	return defaultValue
}

func isClipboardSupported() (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			ok = false
		}
	}()
	return clipboard.Init() == nil
}

// parseExpiryWindow accepts go duration syntax, plus the day and week suffixes
// that certificate lifetimes are actually discussed in. A window of zero is
// valid and means "already expired".
func parseExpiryWindow(in string) (time.Duration, error) {

	in = strings.TrimSpace(in)
	if in == "" {
		return 0, errors.New("no duration given")
	}

	unit := time.Duration(0)
	switch in[len(in)-1] {
	case 'd':
		unit = 24 * time.Hour
	case 'w':
		unit = 7 * 24 * time.Hour
	}

	var window time.Duration
	if unit == 0 {
		parsed, err := time.ParseDuration(in)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration, expected something like 30d, 2w or 72h", in)
		}
		window = parsed
	} else {
		value, err := strconv.ParseFloat(in[:len(in)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration, expected something like 30d, 2w or 72h", in)
		}
		window = time.Duration(value * float64(unit))
	}

	if window < 0 {
		return 0, fmt.Errorf("%q is negative", in)
	}
	return window, nil
}

// defaultTimeout is how long a connection is given, and the base the revocation
// timeouts are derived from.
const defaultTimeout = 5 * time.Second

// parseTimeout accepts go duration syntax. Unlike an expiry window this is not
// a span of days, so the day and week suffixes would only invite mistakes.
func parseTimeout(in string) (time.Duration, error) {

	in = strings.TrimSpace(in)
	if in == "" {
		return 0, errors.New("no duration given")
	}
	timeout, err := time.ParseDuration(in)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration, expected something like 5s or 500ms", in)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("%q is not positive", in)
	}
	return timeout, nil
}

// defaultConcurrency bounds how many locations are read at once. It is set well
// above what anyone checking a handful of hosts will reach, so the common case
// is unaffected, while still holding a scan of hundreds to a number of sockets
// a machine will lend it.
const defaultConcurrency = 100

func getIntEnv(envName string, defaultValue int) int {

	env, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}
	value, err := strconv.Atoi(env)
	if err != nil {
		return defaultValue
	}
	return value
}
