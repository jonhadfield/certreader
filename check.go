package main

import (
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
)

// Exit codes are part of the tool's interface, since a monitoring check reads
// them. Keep their meanings stable.
const (
	// exitOK means every location was read and passed the checks requested.
	exitOK = 0
	// exitLoadError means at least one location could not be read, so its
	// status is unknown rather than good.
	exitLoadError = 1
	// exitCheckFailed means a certificate was found revoked, or falls due
	// inside the -expiring-within window.
	exitCheckFailed = 2
)

// exitStatus works out the process exit code from what was found.
//
// A failed check outranks a load error: a certificate known to be revoked is
// more actionable than one that could not be read, and load failures are
// reported on stderr regardless.
//
// Only what survived the filtering flags is considered, so -no-expired and
// friends exclude certificates from the checks as well as from the output.
func exitStatus(locations cert.Locations, flags Flags) int {

	var loadFailed bool
	for _, location := range locations {
		if location.Error != nil {
			loadFailed = true
			continue
		}
		// nil when no check was requested, and nil-safe
		if location.Revocation.IsRevoked() {
			return exitCheckFailed
		}
		if flags.ExpiringWithin != "" && expiresWithin(location, flags.ExpiringWindow) {
			return exitCheckFailed
		}
		if flags.FailOnWarning && hasWarnings(location) {
			return exitCheckFailed
		}
	}

	if loadFailed {
		return exitLoadError
	}
	return exitOK
}

// expiresWithin reports whether any readable certificate in the location falls
// due inside the window. An already expired certificate always qualifies.
func expiresWithin(location cert.Location, window time.Duration) bool {

	for _, certificate := range location.Certificates {
		if certificate.Error() != nil {
			continue
		}
		if time.Until(certificate.NotAfter()) <= window {
			return true
		}
	}
	return false
}

// hasWarnings reports whether anything was flagged about the certificates or
// the way the chain was served. Chain warnings are only present when
// verification ran, so without -verify this considers the certificates alone.
func hasWarnings(location cert.Location) bool {

	if location.Verification != nil && len(location.Verification.ChainWarnings) != 0 {
		return true
	}
	for _, certificate := range location.Certificates {
		if len(certificate.Warnings()) != 0 {
			return true
		}
	}
	// a request whose self-signature does not hold is the one warning a
	// request can carry, and the one worth failing a check over
	for _, csr := range location.CSRs {
		if len(csr.Warnings()) != 0 {
			return true
		}
	}
	return false
}
