package print

import (
	"fmt"

	"github.com/jonhadfield/certreader/pkg/cert"
)

// printVerification prints the outcome of checking against the system trust
// store, when one was asked for.
func printVerification(location cert.Location) {

	result := location.Verification
	if result == nil {
		return
	}

	fmt.Printf("%s\n", AttributeName("Verification"))
	if result.OK {
		fmt.Printf("    %s: %s\n", SubAttributeName("Result"), validDateColor("verified"))
		fmt.Printf("    %s: %d\n", SubAttributeName("Chains"), result.Chains)
	} else {
		fmt.Printf("    %s: %s\n", SubAttributeName("Result"), ExpiryStatus(true, "not verified"))
	}
	if result.Hostname != "" {
		fmt.Printf("    %s: %s\n", SubAttributeName("Hostname"), result.Hostname)
	}
	for _, warning := range result.ChainWarnings {
		fmt.Printf("    %s: %s\n", SubAttributeName("Chain"), WarningText(warning.Message))
	}
	for _, problem := range result.Problems {
		fmt.Printf("    %s: %s\n", SubAttributeName("Reason"), WarningText(problem.Message))
		if problem.Subject != "" {
			fmt.Printf("        %s\n", problem.Subject)
		}
	}
	fmt.Println()
}
