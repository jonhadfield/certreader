package print

import (
	"fmt"

	"github.com/jonhadfield/certreader/pkg/cert"
)

// printRevocation prints the outcome of a revocation check when one was
// requested, and otherwise falls back to whatever the server stapled.
func printRevocation(location cert.Location) {
	if location.Revocation == nil {
		printStapledOCSP(location)
		return
	}

	status := location.Revocation

	fmt.Printf("%s\n", AttributeName("Revocation"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Status"), OCSPStatus(status.Status))
	if status.Source != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Source"), revocationSource(status))
	}
	if status.SerialNumber != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Serial Number"), status.SerialNumber)
	}
	if status.IsRevoked() {
		fmt.Printf("    %s: %s\n", SubAttributeName("Revoked At"), validityFormat(status.RevokedAt))
		fmt.Printf("    %s: %s\n", SubAttributeName("Reason"), status.RevocationReason)
	}
	if !status.ProducedAt.IsZero() {
		fmt.Printf("    %s: %s\n", SubAttributeName("Produced At"), validityFormat(status.ProducedAt))
	}
	if !status.ThisUpdate.IsZero() {
		fmt.Printf("    %s: %s\n", SubAttributeName("This Update"), validityFormat(status.ThisUpdate))
	}
	if !status.NextUpdate.IsZero() {
		nextUpdate := validityFormat(status.NextUpdate)
		if status.IsStale() {
			nextUpdate = ExpiryStatus(true, nextUpdate+" [stale]")
		}
		fmt.Printf("    %s: %s\n", SubAttributeName("Next Update"), nextUpdate)
	}
	if status.Source != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Signature"), signatureStatus(status.SignatureVerified))
	}
	if status.IssuerFetchedFrom != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Issuer"), "fetched from "+status.IssuerFetchedFrom)
	}
	if len(status.Attempts) > 0 {
		fmt.Printf("    %s\n", SubAttributeName("Not Answered"))
		for _, attempt := range status.Attempts {
			fmt.Printf("        %s\n", attempt)
		}
	}
	fmt.Println()
}

// revocationSource names where a verdict came from, with the endpoint when the
// answer required a request.
func revocationSource(status *cert.RevocationStatus) string {
	if status.URL == "" {
		return string(status.Source)
	}
	return fmt.Sprintf("%s (%s)", status.Source, status.URL)
}

// printStapledOCSP prints the revocation status a TLS server volunteered during
// the handshake. Nothing is printed for locations without a stapled response.
func printStapledOCSP(location cert.Location) {
	if !location.HasOCSPStaple() {
		return
	}

	staple, err := location.StapledOCSP()
	if err != nil {
		fmt.Printf("%s: %v\n\n", AttributeName("OCSP Staple"), err)
		return
	}

	fmt.Printf("%s\n", AttributeName("OCSP Staple"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Status"), OCSPStatus(staple.Status))
	if staple.SerialNumber != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Serial Number"), staple.SerialNumber)
	}
	if staple.IsRevoked() {
		fmt.Printf("    %s: %s\n", SubAttributeName("Revoked At"), validityFormat(staple.RevokedAt))
		fmt.Printf("    %s: %s\n", SubAttributeName("Reason"), staple.RevocationReason)
	}
	fmt.Printf("    %s: %s\n", SubAttributeName("Produced At"), validityFormat(staple.ProducedAt))
	fmt.Printf("    %s: %s\n", SubAttributeName("This Update"), validityFormat(staple.ThisUpdate))
	if !staple.NextUpdate.IsZero() {
		nextUpdate := validityFormat(staple.NextUpdate)
		if staple.IsStale() {
			nextUpdate = ExpiryStatus(true, nextUpdate+" [stale]")
		}
		fmt.Printf("    %s: %s\n", SubAttributeName("Next Update"), nextUpdate)
	}
	fmt.Printf("    %s: %s\n", SubAttributeName("Signature"), signatureStatus(staple.SignatureVerified))
	fmt.Println()
}

// signatureStatus describes whether a response was authenticated against the
// issuing CA.
func signatureStatus(verified bool) string {
	if verified {
		return "verified against issuer"
	}
	return "not verified (issuer certificate unavailable)"
}
