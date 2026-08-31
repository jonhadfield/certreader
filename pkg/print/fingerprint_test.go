package print

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, file string) cert.Location {
	t.Helper()

	location := cert.LoadFromFile("../cert/testdata/"+file, "")
	require.Nil(t, location.Error)
	return location
}

func TestPrintFingerprints(t *testing.T) {
	locations := []cert.Location{fixture(t, "cert.pem")}

	t.Run("given the flag is not set, then neither fingerprint is printed", func(t *testing.T) {
		output := captureStdout(t, func() { Locations(locations, Options{}) })

		assert.NotContains(t, output, "Fingerprint")
		assert.NotContains(t, output, "Public Key SHA-256")
	})

	t.Run("given the flag is set, then both are printed next to the serial number", func(t *testing.T) {
		output := captureStdout(t, func() { Locations(locations, Options{Fingerprint: true}) })

		assert.Contains(t, output, "CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F")
		assert.Contains(t, output, "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=")

		// they identify the certificate, so they belong with the serial number
		// rather than at the end of a long block
		serial := strings.Index(output, "Serial Number")
		fingerprint := strings.Index(output, "Fingerprint SHA-256")
		issuer := strings.Index(output, "Issuer")
		require.Positive(t, fingerprint)
		assert.Less(t, serial, fingerprint)
		assert.Less(t, fingerprint, issuer)
	})
}

func TestJSONAlwaysCarriesFingerprints(t *testing.T) {
	// json is read by something rather than someone, and a consumer would not
	// think to ask for a field it does not know about
	var out strings.Builder
	require.NoError(t, writeJSON(&out, []cert.Location{fixture(t, "cert.pem")}, Options{}))

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &document))

	locations := document["locations"].([]any)
	certificates := locations[0].(map[string]any)["certificates"].([]any)
	certificate := certificates[0].(map[string]any)

	assert.Equal(t, "CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F", certificate["fingerprint_sha256"])
	assert.Equal(t, "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", certificate["public_key_sha256"])
}

func TestJSONOmitsFingerprintsForUnreadableBlocks(t *testing.T) {
	raw, err := os.ReadFile("../cert/testdata/cert.pem")
	require.NoError(t, err)

	// the fixture has no trailing newline, and without one the blocks run
	// together and neither parses
	broken := append(append(raw, '\n'), []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")...)
	certificates, err := cert.FromBytes(broken, "")
	require.NoError(t, err)
	require.Len(t, certificates, 2)

	var out strings.Builder
	require.NoError(t, writeJSON(&out, []cert.Location{{Path: "mixed.pem", ContentType: cert.ContentTypeCertificate, Certificates: certificates}}, Options{}))

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &document))

	locations := document["locations"].([]any)
	entries := locations[0].(map[string]any)["certificates"].([]any)
	require.Len(t, entries, 2)

	assert.Contains(t, entries[0].(map[string]any), "fingerprint_sha256")
	assert.NotContains(t, entries[1].(map[string]any), "fingerprint_sha256", "there is nothing to fingerprint")
	assert.Contains(t, entries[1].(map[string]any), "error")
}
