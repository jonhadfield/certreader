package print

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func comparisonOf(t *testing.T, left, right string) cert.Comparison {
	t.Helper()

	comparison, err := cert.Locations{
		cert.LoadFromFile("../cert/testdata/"+left, ""),
		cert.LoadFromFile("../cert/testdata/"+right, ""),
	}.Compare()
	require.NoError(t, err)
	return comparison
}

func TestPrintCompare(t *testing.T) {
	t.Run("given the same certificate, then it is printed once rather than twice", func(t *testing.T) {
		output := captureStdout(t, func() { Compare(comparisonOf(t, "cert.pem", "cert.pem")) })

		assert.Contains(t, output, "Certificate: same")
		assert.Contains(t, output, "Public Key: same")
		assert.Contains(t, output, "Result: the same certificate and the same chain")
		// one fingerprint, not the same one twice
		assert.Equal(t, 1, strings.Count(output, "CB:3C:CB:B7"))
	})

	t.Run("given different certificates, then both fingerprints are named", func(t *testing.T) {
		output := captureStdout(t, func() { Compare(comparisonOf(t, "cert.pem", "sct.pem")) })

		assert.Contains(t, output, "Certificate: different")
		assert.Contains(t, output, "cert.pem")
		assert.Contains(t, output, "sct.pem")
		assert.Contains(t, output, "CB:3C:CB:B7")
		assert.Contains(t, output, "73:10:E1:6F")
	})
}

func TestCompareJSON(t *testing.T) {
	var out strings.Builder
	require.NoError(t, writeCompareJSON(&out, comparisonOf(t, "cert.pem", "sct.pem")))

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &document))

	assert.Equal(t, false, document["same"])
	assert.Equal(t, false, document["same_certificate"])
	assert.Equal(t, false, document["same_key"])
	assert.Contains(t, document, "left_fingerprint_sha256")
	assert.Contains(t, document, "right_public_key_sha256")
	assert.Contains(t, document["summary"], "different keys")
}
