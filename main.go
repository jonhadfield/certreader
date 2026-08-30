package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/jonhadfield/certreader/pkg/print"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/term"
)

var Version = "dev"

// A revocation check makes several requests one after another, and a CRL can be
// large, so a request is given more time than a handshake and the whole check
// more again. At the default timeout these work out as the ten and thirty
// seconds that used to be hardcoded.
const (
	revocationRequestMultiple = 2
	revocationBudgetMultiple  = 6
)

func main() {

	flags, err := ParseFlags()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	setLogger(flags.Verbose)

	if flags.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	locations := LoadLocations(flags)
	if flags.NoExpired {
		locations = locations.RemoveExpired()
	}
	if flags.NoDuplicate {
		locations = locations.RemoveDuplicates()
	}
	if flags.SubjectLike != "" {
		locations = locations.SubjectLike(flags.SubjectLike)
	}
	if flags.IssuerLike != "" {
		locations = locations.IssuerLike(flags.IssuerLike)
	}
	if flags.SortExpiry {
		locations = locations.SortByExpiry()
	}
	if flags.Verify {
		locations = locations.Verify()
	}
	if flags.Revocation && revocationIsRendered(flags) {
		ctx, cancel := context.WithTimeout(context.Background(), flags.Timeout*revocationBudgetMultiple)
		checker := &cert.RevocationChecker{
			RequestTimeout: flags.Timeout * revocationRequestMultiple,
			Concurrency:    flags.Concurrency,
		}
		locations = locations.CheckRevocation(ctx, checker)
		// not deferred, because the process exits below without unwinding
		cancel()
	}

	switch {
	case flags.JSON:
		if err := print.JSON(locations, flags.Chains, flags.Pem, flags.Extensions, flags.Signature); err != nil {
			slog.Error(fmt.Sprintf("writing json: %v", err))
			os.Exit(exitLoadError)
		}
	case flags.Expiry:
		print.Expiry(locations)
	case flags.PemOnly:
		print.Pem(locations, flags.Chains)
	default:
		print.Locations(locations, flags.Chains, flags.Pem, flags.Extensions, flags.Signature)
	}

	os.Exit(exitStatus(locations, flags))
}

// revocationIsRendered reports whether the selected output would show a
// revocation result. The narrower text modes do not, so the network work is
// skipped rather than performed and discarded.
func revocationIsRendered(flags Flags) bool {
	if flags.JSON {
		return true
	}
	return !flags.Expiry && !flags.PemOnly
}

func setLogger(verbose bool) {
	level := slog.LevelError
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func LoadLocations(flags Flags) cert.Locations {
	var locations cert.Locations
	if flags.Clipboard {
		locations = append(locations, cert.LoadFromClipboard(flags.PfxPassword))
	}

	if len(flags.Args) > 0 {
		locations = append(locations, loadFromArgs(flags.Args, flags)...)
	}

	if shouldReadStdin(flags, isStdin()) {
		locations = append(locations, cert.LoadFromStdin(flags.PfxPassword))
	}

	locations = maybePromptForPFXPasswords(locations, &flags)

	if len(locations) > 0 {
		return locations
	}

	// no stdin and no args
	flags.Usage()
	os.Exit(0)
	return nil
}

func loadFromArgs(args []string, flags Flags) cert.Locations {
	type result struct {
		arg      string
		location cert.Location
	}
	// One socket per argument, all at once, is fine for a handful of hosts and
	// less so for a list of hundreds, which can outrun the file descriptors a
	// machine will lend it.
	slots := newSemaphore(flags.Concurrency)

	out := make(chan result)
	go func() {
		var wg sync.WaitGroup
		for _, arg := range args {
			wg.Add(1)
			go func() {
				defer wg.Done()
				slots.acquire()
				defer slots.release()
				out <- result{arg: arg, location: loadFromArg(arg, flags)}
			}()
		}
		wg.Wait()
		close(out)
	}()

	// load from the channel
	locationsByArgs := make(map[string]cert.Location)
	for r := range out {
		locationsByArgs[r.arg] = r.location
	}

	// sort by input arguments
	var locationsSortedByArgs cert.Locations
	for _, arg := range args {
		locationsSortedByArgs = append(locationsSortedByArgs, locationsByArgs[arg])
	}
	return locationsSortedByArgs
}

func loadFromArg(arg string, flags Flags) cert.Location {
	options := cert.NetworkOptions{
		ServerName:         flags.ServerName,
		InsecureSkipVerify: flags.Insecure,
		StartTLS:           flags.StartTLS,
		Timeout:            flags.Timeout,
	}
	if isTCPNetworkAddress(arg) {
		return cert.LoadFromNetwork(arg, options)
	}
	if _, err := os.Stat(arg); err != nil && os.IsNotExist(err) && looksLikeFQDN(arg) {
		location := cert.LoadFromNetwork(arg+":"+defaultPort(flags.StartTLS), options)
		location.Path = arg
		return location
	}
	return cert.LoadFromFile(arg, flags.PfxPassword)
}

// defaultPort is the port assumed for a bare hostname. Without -starttls that
// is https, otherwise the port the named protocol normally listens on.
func defaultPort(protocol cert.StartTLSProtocol) string {
	if port := protocol.DefaultPort(); port != "" {
		return port
	}
	return "443"
}

func maybePromptForPFXPasswords(locations cert.Locations, flags *Flags) cert.Locations {
	for i := range locations {
		var pwErr *cert.PasswordRequiredError
		if !errors.As(locations[i].Error, &pwErr) {
			continue
		}
		if pwErr == nil || pwErr.Data() == nil {
			continue
		}

		// Reattempt automatically if a new password has been supplied since initial load
		if flags.PfxPassword != "" {
			updated := reloadWithPassword(locations[i], pwErr, flags.PfxPassword)
			if updated.Error == nil {
				locations[i] = updated
				continue
			}
			var newPwErr *cert.PasswordRequiredError
			if errors.As(updated.Error, &newPwErr) {
				pwErr = newPwErr
			} else {
				locations[i] = updated
				continue
			}
		}

		if !canPromptForPassword() {
			continue
		}

		fmt.Fprintf(os.Stderr, "%s requires a password.\n", promptLabel(locations[i].Path))
		for attempt := 0; attempt < 3; attempt++ {
			password, ok := promptForPasswordInput(locations[i].Path, attempt)
			if !ok {
				break
			}
			if password == "" {
				fmt.Fprintln(os.Stderr, "No password entered; leaving certificate unresolved.")
				break
			}
			updated := reloadWithPassword(locations[i], pwErr, password)
			if updated.Error == nil {
				locations[i] = updated
				flags.PfxPassword = password
				break
			}
			var newPwErr *cert.PasswordRequiredError
			if errors.As(updated.Error, &newPwErr) {
				pwErr = newPwErr
				fmt.Fprintln(os.Stderr, "Password incorrect; try again.")
				continue
			}
			locations[i] = updated
			break
		}
	}
	return locations
}

func reloadWithPassword(location cert.Location, pwErr *cert.PasswordRequiredError, password string) cert.Location {
	certificates, err := cert.FromBytes(pwErr.Data(), password)
	if err != nil {
		var newPwErr *cert.PasswordRequiredError
		if errors.As(err, &newPwErr) {
			newPwErr.SetSource(pwErr.Source())
		}
		return cert.Location{
			Path:       location.Path,
			TLSVersion: location.TLSVersion,
			Error:      err,
		}
	}
	return cert.Location{
		Path:         location.Path,
		TLSVersion:   location.TLSVersion,
		ContentType:  cert.ContentTypeCertificate,
		Certificates: certificates,
	}
}

func promptLabel(path string) string {
	switch path {
	case "stdin":
		return "stdin"
	case "clipboard":
		return "clipboard"
	default:
		return path
	}
}

// canPromptForPassword and promptForPasswordInput are variables rather than
// plain functions so that the retry loop above can be tested. It is the most
// intricate logic here and it handles credentials, which is a poor combination
// to leave unexercised for want of a terminal.
var canPromptForPassword = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

var promptForPasswordInput = func(path string, attempt int) (string, bool) {
	prompt := fmt.Sprintf("Enter password for %s", promptLabel(path))
	if attempt > 0 {
		prompt += " (try again)"
	}
	prompt += ": "
	fmt.Fprint(os.Stderr, prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		slog.Error("reading password", slog.String("path", path), slog.Any("err", err))
		return "", false
	}
	return strings.TrimSpace(string(passwordBytes)), true
}

func isTCPNetworkAddress(arg string) bool {

	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return false
	}
	return true
}

func looksLikeFQDN(s string) bool {
	if s == "" || strings.ContainsAny(s, `/\`) || !strings.Contains(s, ".") {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}

func isDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// shouldReadStdin reports whether stdin is worth reading. It is read only when
// nothing else was named: a pipe on stdin says nothing about whether the caller
// meant to send anything down it, and a parent process holding an idle pipe
// open would otherwise block the read for ever with a file or host already
// given to read. Reading both also invented a second location out of whatever
// happened to be on the pipe, which failed the run.
func shouldReadStdin(flags Flags, piped bool) bool {
	if !piped {
		return false
	}
	return !flags.Clipboard && len(flags.Args) == 0
}

// isStdin reports whether stdin is a pipe or a redirect rather than a terminal.
func isStdin() bool {

	info, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("checking stdin: %v\n", err)
		return false
	}

	if (info.Mode() & os.ModeCharDevice) == 0 {
		return true
	}
	return false
}
