package print

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func csrFixture(t *testing.T, file string) []cert.Location {
	t.Helper()

	location := cert.LoadFromFile("../cert/testdata/"+file, "")
	require.Nil(t, location.Error)
	require.True(t, location.IsCSR())
	return []cert.Location{location}
}

func TestPrintCSRSelfSignature(t *testing.T) {
	t.Run("given a request that verifies, then it says so", func(t *testing.T) {
		output := captureStdout(t, func() { Locations(csrFixture(t, "csr_san.pem"), Options{}) })

		assert.Contains(t, output, "Self-Signature: verified against the key in the request")
	})

	t.Run("given a request that does not verify, then it says why", func(t *testing.T) {
		output := captureStdout(t, func() { Locations(csrFixture(t, "csr_bad_signature.pem"), Options{}) })

		assert.Contains(t, output, "does not verify")
		// the rest is still printed: it is what the request claims, and worth
		// reading alongside the reason not to believe it
		assert.Contains(t, output, "test.example.com")
	})
}

func TestJSONCarriesCSRSelfSignature(t *testing.T) {
	decode := func(t *testing.T, file string) map[string]any {
		t.Helper()

		var out strings.Builder
		require.NoError(t, writeJSON(&out, csrFixture(t, file), Options{}))

		var document map[string]any
		require.NoError(t, json.Unmarshal([]byte(out.String()), &document))

		locations := document["locations"].([]any)
		csrs := locations[0].(map[string]any)["csrs"].([]any)
		return csrs[0].(map[string]any)
	}

	t.Run("given a request that verifies, then the field is true and there is no warning", func(t *testing.T) {
		csr := decode(t, "csr_san.pem")

		assert.Equal(t, true, csr["self_signature_valid"])
		assert.NotContains(t, csr, "warnings")
	})

	t.Run("given a request that does not, then false is reported rather than omitted", func(t *testing.T) {
		csr := decode(t, "csr_bad_signature.pem")

		// false has to survive into the document: a consumer needs to tell it
		// from a field that was never filled in
		assert.Equal(t, false, csr["self_signature_valid"])

		warnings := csr["warnings"].([]any)
		require.Len(t, warnings, 1)
		assert.Equal(t, "invalid-self-signature", warnings[0].(map[string]any)["code"])
	})
}

func TestPrintCSRVersion(t *testing.T) {
	t.Run("given a request, then the version reads as the number and the encoding", func(t *testing.T) {
		// what openssl prints for the same file, so a reader cross-checking
		// against it sees the same thing
		output := captureStdout(t, func() { Locations(csrFixture(t, "csr_san.pem"), Options{}) })

		assert.Contains(t, output, "Version: 1 (0x0)")
		assert.NotContains(t, output, "Version: 0")
	})

	t.Run("given a request, then json reports the version a certificate would", func(t *testing.T) {
		var out strings.Builder
		require.NoError(t, writeJSON(&out, csrFixture(t, "csr_san.pem"), Options{}))

		var document map[string]any
		require.NoError(t, json.Unmarshal([]byte(out.String()), &document))

		locations := document["locations"].([]any)
		csr := locations[0].(map[string]any)["csrs"].([]any)[0].(map[string]any)
		assert.Equal(t, float64(1), csr["version"])
	})
}
