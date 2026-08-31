package print

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestJSONWritesToStdout(t *testing.T) {
	// writeJSON was covered, but the exported wrapper that the command actually
	// calls was not, so nothing checked it reached stdout
	chain := newStapleTestChain(t)
	locations := []cert.Location{chain.location(nil, true)}

	output := captureStdout(t, func() {
		require.NoError(t, JSON(locations, Options{}))
	})

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &decoded), "stdout must carry the document")
	assert.Len(t, decoded["locations"], 1)
}

func TestJSONVerification(t *testing.T) {

	t.Run("given a verified location then it is reported", func(t *testing.T) {
		locations := []cert.Location{{
			Path:        "example.com:443",
			ContentType: cert.ContentTypeCertificate,
			Verification: &cert.VerificationResult{
				OK: true, Chains: 2, Hostname: "example.com",
			},
		}}

		verification := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["verification"].(map[string]any)

		assert.Equal(t, true, verification["ok"])
		assert.Equal(t, float64(2), verification["chains"])
		assert.Equal(t, "example.com", verification["hostname"])
		assert.NotContains(t, verification, "problems")
	})

	t.Run("given problems and chain warnings then both are reported separately", func(t *testing.T) {
		locations := []cert.Location{{
			Path:        "example.com:443",
			ContentType: cert.ContentTypeCertificate,
			Verification: &cert.VerificationResult{
				Hostname: "example.com",
				Problems: []cert.VerificationProblem{
					{Code: cert.VerifyUntrustedRoot, Message: "not trusted", Subject: "CN=leaf"},
				},
				ChainWarnings: []cert.Warning{
					{Code: cert.ChainWarningRootIncluded, Message: "the root is sent"},
				},
			},
		}}

		verification := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["verification"].(map[string]any)

		assert.Equal(t, false, verification["ok"])

		problems := verification["problems"].([]any)
		require.Len(t, problems, 1)
		assert.Equal(t, cert.VerifyUntrustedRoot, problems[0].(map[string]any)["code"])

		// a chain warning is not a problem, and must not be filed as one
		warnings := verification["chain_warnings"].([]any)
		require.Len(t, warnings, 1)
		assert.Equal(t, cert.ChainWarningRootIncluded, warnings[0].(map[string]any)["code"])
	})
}

func TestPrintVerificationOutput(t *testing.T) {

	t.Run("given a verified location then the result and chain count are shown", func(t *testing.T) {
		location := cert.Location{
			Path:         "example.com:443",
			ContentType:  cert.ContentTypeCertificate,
			Verification: &cert.VerificationResult{OK: true, Chains: 1, Hostname: "example.com"},
		}

		output := captureStdout(t, func() { printVerification(location) })

		assert.Contains(t, output, "Verification")
		assert.Contains(t, output, "verified")
		assert.Contains(t, output, "Chains")
		assert.Contains(t, output, "example.com")
	})

	t.Run("given problems then each reason and its certificate are shown", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Verification: &cert.VerificationResult{
				Hostname: "example.com",
				Problems: []cert.VerificationProblem{
					{Code: cert.VerifyExpired, Message: "expired on 2020-01-01T00:00:00Z", Subject: "CN=old"},
					{Code: cert.VerifyUntrustedRoot, Message: "not trusted", Subject: "CN=root"},
				},
			},
		}

		output := captureStdout(t, func() { printVerification(location) })

		assert.Contains(t, output, "not verified")
		assert.Contains(t, output, "expired on 2020-01-01")
		assert.Contains(t, output, "CN=old")
		assert.Contains(t, output, "not trusted")
		assert.Contains(t, output, "CN=root")
	})

	t.Run("given chain warnings then they are shown without failing the result", func(t *testing.T) {
		location := cert.Location{
			ContentType: cert.ContentTypeCertificate,
			Verification: &cert.VerificationResult{
				OK: true, Chains: 1,
				ChainWarnings: []cert.Warning{{Code: cert.ChainWarningRootIncluded, Message: "the root is sent"}},
			},
		}

		output := captureStdout(t, func() { printVerification(location) })

		assert.Contains(t, output, "verified")
		assert.Contains(t, output, "the root is sent")
	})

	t.Run("given no verification then nothing is printed", func(t *testing.T) {
		// the staple is a separate block, printed by printRevocation, so this
		// one has nothing to say
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)

		output := captureStdout(t, func() { printVerification(location) })

		assert.Empty(t, output)
	})

	t.Run("given both a verification and a staple then each has its own block", func(t *testing.T) {
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)
		location.Verification = &cert.VerificationResult{OK: true, Chains: 1}

		output := captureStdout(t, func() {
			printVerification(location)
			printRevocation(location)
		})

		assert.Contains(t, output, "Verification")
		assert.Contains(t, output, "OCSP Staple")
	})
}

func TestPemBranches(t *testing.T) {

	t.Run("given certificates then their pem blocks are printed", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{chain.location(nil, true)}

		output := captureStdout(t, func() { Pem(locations, false) })

		assert.Equal(t, 2, strings.Count(output, "BEGIN CERTIFICATE"))
	})

	t.Run("given csrs then their pem blocks are printed", func(t *testing.T) {
		locations := []cert.Location{{
			Path:        "request.csr",
			ContentType: cert.ContentTypeCSR,
			CSRs:        loadTestCSRs(t, "csr.pem"),
		}}

		output := captureStdout(t, func() { Pem(locations, false) })

		assert.Contains(t, output, "BEGIN CERTIFICATE REQUEST")
	})

	t.Run("given a location that failed to load then the error is printed", func(t *testing.T) {
		locations := []cert.Location{{Path: "missing.pem", Error: errors.New("no such file")}}

		output := captureStdout(t, func() { Pem(locations, false) })

		assert.Contains(t, output, "missing.pem")
		assert.Contains(t, output, "no such file")
	})

	t.Run("given chains are asked for and cannot be built then it says so", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{chain.location(nil, true)}

		output := captureStdout(t, func() { Pem(locations, true) })

		// the test CA is not trusted, so no chain can be built
		assert.Contains(t, output, "chains for")
	})
}

func TestLocationsBranches(t *testing.T) {

	t.Run("given chains are asked for and cannot be built then it says so", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := cert.Locations{chain.location(nil, true)}

		output := captureStdout(t, func() { Locations(locations, Options{Chains: true}) })

		assert.Contains(t, output, "chains for")
	})

	t.Run("given a certificate that failed to parse then its error is printed", func(t *testing.T) {
		locations := cert.Locations{{
			Path:         "bundle.pem",
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.Certificates{{}},
		}}

		output := captureStdout(t, func() { Locations(locations, Options{}) })

		assert.Contains(t, output, "bundle.pem")
		assert.NotContains(t, output, "Serial Number", "nothing else is safe to read")
	})
}

func TestExpiryBranches(t *testing.T) {

	t.Run("given a location that failed to load then the error is printed", func(t *testing.T) {
		locations := cert.Locations{{Path: "missing.pem", Error: errors.New("no such file")}}

		output := captureStdout(t, func() { Expiry(locations) })

		assert.Contains(t, output, "missing.pem")
		assert.Contains(t, output, "ERROR")
	})

	t.Run("given a certificate that failed to parse then its error is printed", func(t *testing.T) {
		locations := cert.Locations{{
			Path:         "bundle.pem",
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.Certificates{{}},
		}}

		output := captureStdout(t, func() { Expiry(locations) })

		assert.Contains(t, output, "bundle.pem")
	})

	t.Run("given a certificate with no common name then the full subject is used", func(t *testing.T) {
		certificates := loadTestCertificates(t, "bundle.pem")
		locations := cert.Locations{{Path: "bundle.pem", Certificates: certificates}}

		output := captureStdout(t, func() { Expiry(locations) })

		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			assert.Regexp(t, `bundle\.pem: .+  \S`, line)
		}
	})
}

// loadTestCertificates reads certificates from the cert package's fixtures.
func loadTestCertificates(t *testing.T, file string) cert.Certificates {
	t.Helper()

	raw, err := os.ReadFile("../cert/testdata/" + file)
	require.NoError(t, err)

	certificates, err := cert.FromBytes(raw, "")
	require.NoError(t, err)
	require.NotEmpty(t, certificates)
	return certificates
}

func TestPrintCertificateVerboseSections(t *testing.T) {
	certificates := loadTestCertificates(t, "sct.pem")

	output := captureStdout(t, func() { printCertificates(certificates, Options{Pem: true, Extensions: true, Signature: true}) })

	assert.Contains(t, output, "Extensions")
	assert.Contains(t, output, "CT Precertificate SCTs")
	assert.Contains(t, output, "Signature Value")
	assert.Contains(t, output, "BEGIN CERTIFICATE")
	assert.Contains(t, output, "[critical]", "a critical extension should be marked")
}

func Test_expirySubjectFallsBackToSubject(t *testing.T) {
	// a certificate with no common name still has to be named, or the line is
	// the ambiguous one this was meant to fix
	certificates := loadTestCertificates(t, "no_common_name.pem")
	require.NotEmpty(t, certificates)
	require.Empty(t, certificates[0].CommonName())

	assert.NotEmpty(t, expirySubject(certificates[0]))
	assert.Equal(t, certificates[0].SubjectString(), expirySubject(certificates[0]))
}
