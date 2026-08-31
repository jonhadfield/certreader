package print

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jonhadfield/certreader/pkg/cert"
)

// Compare prints how two locations differ.
func Compare(comparison cert.Comparison) {
	fmt.Printf("--- [%s vs %s] ---\n", comparison.Left, comparison.Right)

	fmt.Printf("%s: %s\n", AttributeName("Certificate"), sameOrNot(comparison.SameCertificate))
	if comparison.SameCertificate {
		fmt.Printf("    %s: %s\n", SubAttributeName("SHA-256"), comparison.LeftFingerprint)
	} else {
		fmt.Printf("    %s: %s\n", SubAttributeName(comparison.Left), comparison.LeftFingerprint)
		fmt.Printf("    %s: %s\n", SubAttributeName(comparison.Right), comparison.RightFingerprint)
	}

	// the key is the interesting half when the certificates differ: it says
	// whether this was a reissue or a rotation
	fmt.Printf("%s: %s\n", AttributeName("Public Key"), sameOrNot(comparison.SameKey))
	if !comparison.SameKey {
		fmt.Printf("    %s: %s\n", SubAttributeName(comparison.Left), comparison.LeftKeyFingerprint)
		fmt.Printf("    %s: %s\n", SubAttributeName(comparison.Right), comparison.RightKeyFingerprint)
	}

	fmt.Printf("%s: %s\n", AttributeName("Chain"), chainSummary(comparison))
	fmt.Printf("%s: %s\n", AttributeName("Result"), comparison.Summary())
	fmt.Println()
}

func sameOrNot(same bool) string {
	if same {
		return "same"
	}
	return WarningText("different")
}

func chainSummary(comparison cert.Comparison) string {
	if comparison.SameChain {
		return fmt.Sprintf("same (%d)", comparison.LeftCount)
	}
	if comparison.LeftCount != comparison.RightCount {
		return WarningText(fmt.Sprintf("different (%s sends %d, %s sends %d)",
			comparison.Left, comparison.LeftCount, comparison.Right, comparison.RightCount))
	}
	return WarningText(fmt.Sprintf("different (%d each)", comparison.LeftCount))
}

type jsonComparison struct {
	Left            string `json:"left"`
	Right           string `json:"right"`
	Same            bool   `json:"same"`
	SameCertificate bool   `json:"same_certificate"`
	SameKey         bool   `json:"same_key"`
	SameChain       bool   `json:"same_chain"`
	Summary         string `json:"summary"`

	LeftFingerprint     string `json:"left_fingerprint_sha256"`
	RightFingerprint    string `json:"right_fingerprint_sha256"`
	LeftKeyFingerprint  string `json:"left_public_key_sha256"`
	RightKeyFingerprint string `json:"right_public_key_sha256"`
	LeftCount           int    `json:"left_certificates"`
	RightCount          int    `json:"right_certificates"`
}

// CompareJSON writes the comparison as json, for a check that acts on it.
func CompareJSON(comparison cert.Comparison) error {
	return writeCompareJSON(os.Stdout, comparison)
}

func writeCompareJSON(w io.Writer, comparison cert.Comparison) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonComparison{
		Left:                comparison.Left,
		Right:               comparison.Right,
		Same:                comparison.Same(),
		SameCertificate:     comparison.SameCertificate,
		SameKey:             comparison.SameKey,
		SameChain:           comparison.SameChain,
		Summary:             comparison.Summary(),
		LeftFingerprint:     comparison.LeftFingerprint,
		RightFingerprint:    comparison.RightFingerprint,
		LeftKeyFingerprint:  comparison.LeftKeyFingerprint,
		RightKeyFingerprint: comparison.RightKeyFingerprint,
		LeftCount:           comparison.LeftCount,
		RightCount:          comparison.RightCount,
	})
}
