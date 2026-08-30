package print

import (
	"os"
	"strings"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadTestCSRs reads a certificate request fixture from the cert package's
// testdata, which is where the requests already live.
func loadTestCSRs(t *testing.T, file string) cert.CSRs {
	t.Helper()

	raw, err := os.ReadFile("../cert/testdata/" + file)
	require.NoError(t, err)

	csrs, err := cert.FromCSRBytes(raw)
	require.NoError(t, err)
	require.NotEmpty(t, csrs)
	return csrs
}

func TestPrintCSR(t *testing.T) {

	t.Run("given a request then its fields are printed", func(t *testing.T) {
		csrs := loadTestCSRs(t, "csr.pem")

		output := captureStdout(t, func() { printCSRs(csrs, false, false, false) })

		assert.Contains(t, output, "Version")
		assert.Contains(t, output, "Signature Algorithm")
		assert.Contains(t, output, "Subject")
		assert.Contains(t, output, "test.example.com")
		assert.Contains(t, output, "Public Key")
		assert.NotContains(t, output, "Extensions")
		assert.NotContains(t, output, "Signature Value")
	})

	t.Run("given a request with names then they are printed", func(t *testing.T) {
		csrs := loadTestCSRs(t, "csr_san.pem")

		output := captureStdout(t, func() { printCSRs(csrs, false, false, false) })

		assert.Contains(t, output, "DNS Names")
		assert.Contains(t, output, "IP Addresses")
		assert.Contains(t, output, "Email Addresses")
		assert.Contains(t, output, "URIs")
	})

	t.Run("given the verbose flags then their sections appear", func(t *testing.T) {
		csrs := loadTestCSRs(t, "csr_san.pem")

		output := captureStdout(t, func() { printCSRs(csrs, true, true, true) })

		assert.Contains(t, output, "Extensions")
		assert.Contains(t, output, "Signature Value")
		assert.Contains(t, output, "BEGIN CERTIFICATE REQUEST")
	})

	t.Run("given a request that failed to parse then the error is printed", func(t *testing.T) {
		output := captureStdout(t, func() { printCSR(cert.CSR{}, false, false) })

		assert.NotEmpty(t, strings.TrimSpace(output))
		assert.NotContains(t, output, "Public Key", "nothing else is safe to read")
	})
}

func TestLocationsPrintsCSRs(t *testing.T) {
	locations := cert.Locations{{
		Path:        "request.csr",
		ContentType: cert.ContentTypeCSR,
		CSRs:        loadTestCSRs(t, "csr.pem"),
	}}

	output := captureStdout(t, func() { Locations(locations, false, false, false, false) })

	assert.Contains(t, output, "request.csr")
	assert.Contains(t, output, "test.example.com")
}

func TestJSONCSRFields(t *testing.T) {
	locations := []cert.Location{{
		Path:        "request.csr",
		ContentType: cert.ContentTypeCSR,
		CSRs:        loadTestCSRs(t, "csr_san.pem"),
	}}

	location := firstLocation(t, decodeJSON(t, locations, false, true, true, true))
	require.Equal(t, "csr", location["type"])

	csrs, ok := location["csrs"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, csrs)

	csr := csrs[0].(map[string]any)
	assert.Contains(t, csr, "version")
	assert.NotEmpty(t, csr["subject"])
	assert.NotEmpty(t, csr["signature_algorithm"])
	assert.NotEmpty(t, csr["public_key_algorithm"])
	assert.NotEmpty(t, csr["dns_names"])
	assert.NotEmpty(t, csr["extensions"])
	assert.NotEmpty(t, csr["signature"])
	assert.Contains(t, csr["pem"], "BEGIN CERTIFICATE REQUEST")
}

func TestJSONCSRError(t *testing.T) {
	locations := []cert.Location{{
		Path:        "broken.csr",
		ContentType: cert.ContentTypeCSR,
		CSRs:        cert.CSRs{{}},
	}}

	csr := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["csrs"].([]any)[0].(map[string]any)

	assert.NotEmpty(t, csr["error"])
	assert.NotContains(t, csr, "subject", "nothing else is safe to read")
}
