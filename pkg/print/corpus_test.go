package print

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit tests check known certificates against known output, so they only
// cover the cases somebody thought to write down. A corpus check asks instead
// what has to hold for any certificate at all, and runs that over as many real
// ones as it can find. The awkward encodings nobody would think to invent are
// out there in the trust stores.
//
// This runs over the fixtures by default. Point CERTREADER_CORPUS_DIR at a
// directory of certificates for a wider sweep: scripts/corpus-check.sh fills
// one from the system trust store. A BMPString user notice printing as raw
// UTF-16 was found this way, and is now a fixture of its own.
const corpusDirEnv = "CERTREADER_CORPUS_DIR"

func corpusFiles(t *testing.T) []string {
	t.Helper()

	dir := os.Getenv(corpusDirEnv)
	if dir == "" {
		dir = filepath.Join("..", "cert", "testdata")
	}

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "corpus directory")

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	require.NotEmpty(t, files, "no certificates in %s", dir)
	return files
}

// assertPrintable reports where output stops being text a terminal can show.
// Raw bytes reaching the output is how the parsing faults in this tool have
// tended to show themselves: the certificate is read, something is printed,
// and it is not what the certificate says.
func assertPrintable(t *testing.T, file string, output []byte) {
	t.Helper()

	if !assert.True(t, utf8.Valid(output), "%s: output is not valid UTF-8", file) {
		return
	}
	for i, character := range string(output) {
		if character == '\n' || character == '\t' || character == '\r' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			around := string(output)
			from := max(0, i-40)
			assert.Failf(t, "control character in output",
				"%s: %#U at byte %d, after %q", file, character, i, around[from:i])
			return
		}
	}
}

// printed collects what a printer writes, since they print rather than return.
func printed(t *testing.T, print func()) []byte {
	t.Helper()

	return []byte(captureStdout(t, print))
}

func TestCorpusOutputIsPrintable(t *testing.T) {
	for _, file := range corpusFiles(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			location := cert.LoadFromFile(file, "")
			if location.Error != nil {
				t.Skipf("not readable as certificates or requests: %v", location.Error)
			}
			locations := []cert.Location{location}

			// every flag that adds to the output, since each is a chance to
			// print something that was never decoded
			assertPrintable(t, file, printed(t, func() {
				Locations(locations, Options{Pem: true, Extensions: true, Signature: true})
			}))
			assertPrintable(t, file, printed(t, func() {
				Expiry(locations)
			}))
			assertPrintable(t, file, printed(t, func() {
				Pem(locations, false)
			}))
		})
	}
}

func TestCorpusJSONIsValid(t *testing.T) {
	for _, file := range corpusFiles(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			location := cert.LoadFromFile(file, "")
			if location.Error != nil {
				t.Skipf("not readable as certificates or requests: %v", location.Error)
			}

			var out strings.Builder
			require.NoError(t, writeJSON(&out, []cert.Location{location}, Options{Pem: true, Extensions: true, Signature: true}))

			// json is UTF-8 by definition, so anything that was not decoded on
			// the way in makes a document nothing can read
			assert.True(t, utf8.ValidString(out.String()), "%s: json is not valid UTF-8", file)

			var document map[string]any
			require.NoError(t, json.Unmarshal([]byte(out.String()), &document), "%s: json does not parse", file)
			assert.Contains(t, document, "locations")
		})
	}
}
