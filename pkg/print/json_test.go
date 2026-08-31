package print

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// decodeJSON renders the locations and unmarshals the result into a generic
// structure, so the tests assert on the document a consumer actually receives
// rather than on the Go types used to build it.
func decodeJSON(t *testing.T, locations []cert.Location, printChains, printPem, printExtensions, printSignature bool) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, writeJSON(&buf, locations, Options{
		Chains:     printChains,
		Pem:        printPem,
		Extensions: printExtensions,
		Signature:  printSignature,
	}))

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out), "output must be valid json")
	return out
}

func firstLocation(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()

	locations, ok := doc["locations"].([]any)
	require.True(t, ok, "locations must be an array")
	require.NotEmpty(t, locations)
	return locations[0].(map[string]any)
}

func TestJSONCertificate(t *testing.T) {

	t.Run("given a certificate location then the core fields are present", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{{
			Path:         "certreader.test:443",
			TLSVersion:   0x0304,
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.FromX509Certificates([]*x509.Certificate{chain.leaf, chain.issuer}),
		}}

		location := firstLocation(t, decodeJSON(t, locations, false, false, false, false))

		assert.Equal(t, "certreader.test:443", location["path"])
		assert.Equal(t, "TLS 1.3", location["tls_version"])
		assert.Equal(t, "certificate", location["type"])

		certificates := location["certificates"].([]any)
		require.Len(t, certificates, 2)

		leaf := certificates[0].(map[string]any)
		assert.Equal(t, float64(1), leaf["position"])
		assert.Equal(t, float64(3), leaf["version"])
		assert.Equal(t, "end-entity", leaf["type"])
		assert.Equal(t, false, leaf["is_ca"])
		assert.Equal(t, false, leaf["expired"])
		assert.NotEmpty(t, leaf["serial_number"])
		assert.NotEmpty(t, leaf["subject"])

		// timestamps must be machine readable
		_, err := time.Parse(time.RFC3339, leaf["not_after"].(string))
		assert.NoError(t, err)

		issuer := certificates[1].(map[string]any)
		assert.Equal(t, float64(2), issuer["position"])
		assert.Equal(t, true, issuer["is_ca"])
	})

	t.Run("given verbose flags are off then their fields are absent", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{{
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.FromX509Certificates([]*x509.Certificate{chain.leaf}),
		}}

		leaf := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["certificates"].([]any)[0].(map[string]any)

		assert.NotContains(t, leaf, "extensions")
		assert.NotContains(t, leaf, "signature")
		assert.NotContains(t, leaf, "pem")
	})

	t.Run("given verbose flags are on then their fields are included", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{{
			ContentType:  cert.ContentTypeCertificate,
			Certificates: cert.FromX509Certificates([]*x509.Certificate{chain.leaf}),
		}}

		leaf := firstLocation(t, decodeJSON(t, locations, false, true, true, true))["certificates"].([]any)[0].(map[string]any)

		assert.NotEmpty(t, leaf["extensions"])
		assert.NotEmpty(t, leaf["signature"])
		assert.Contains(t, leaf["pem"], "BEGIN CERTIFICATE")

		extension := leaf["extensions"].([]any)[0].(map[string]any)
		assert.Contains(t, extension, "name")
		assert.Contains(t, extension, "oid")
		assert.Contains(t, extension, "critical")
	})
}

func TestJSONLocationError(t *testing.T) {

	t.Run("given a location that failed to load then the error is reported", func(t *testing.T) {
		locations := []cert.Location{{Path: "missing.pem", Error: errors.New("no such file")}}

		location := firstLocation(t, decodeJSON(t, locations, false, false, false, false))

		assert.Equal(t, "missing.pem", location["path"])
		assert.Equal(t, "no such file", location["error"])
		assert.NotContains(t, location, "certificates")
	})

	t.Run("given a certificate that failed to parse then only its error is reported", func(t *testing.T) {
		// a well formed PEM envelope holding bytes that are not a certificate,
		// which is how a real damaged bundle reaches the printer
		damaged := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
		certificates, err := cert.FromBytes(damaged, "")
		require.NoError(t, err)
		require.Len(t, certificates, 1)
		require.Error(t, certificates[0].Error())

		locations := []cert.Location{{
			Path:         "bundle.pem",
			ContentType:  cert.ContentTypeCertificate,
			Certificates: certificates,
		}}

		certificate := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["certificates"].([]any)[0].(map[string]any)

		assert.Equal(t, float64(1), certificate["position"])
		assert.NotEmpty(t, certificate["error"])
		// the accessors are unsafe on an unparsed certificate, so nothing else
		// should have been read from it
		assert.NotContains(t, certificate, "subject")
		assert.NotContains(t, certificate, "is_ca")
		assert.NotContains(t, certificate, "expired")
	})
}

func TestJSONRevocation(t *testing.T) {

	t.Run("given a revocation result then it is reported with its attempts", func(t *testing.T) {
		locations := []cert.Location{{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:            cert.RevocationSourceCRL,
				URL:               "http://crl.example.com/a.crl",
				Status:            "revoked",
				SerialNumber:      "01:02:03",
				RevokedAt:         time.Now().Add(-time.Hour),
				RevocationReason:  "key compromise",
				SignatureVerified: true,
				Attempts: []cert.RevocationAttempt{
					{Source: cert.RevocationSourceOCSP, URL: "http://ocsp.example.com", Err: errors.New("connection refused")},
				},
			},
		}}

		revocation := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["revocation"].(map[string]any)

		assert.Equal(t, "revoked", revocation["status"])
		assert.Equal(t, "CRL", revocation["source"])
		assert.Equal(t, "http://crl.example.com/a.crl", revocation["url"])
		assert.Equal(t, "key compromise", revocation["revocation_reason"])
		assert.Equal(t, true, revocation["signature_verified"])
		assert.Equal(t, false, revocation["stale"])

		attempts := revocation["not_answered"].([]any)
		require.Len(t, attempts, 1)
		assert.Equal(t, "OCSP responder", attempts[0].(map[string]any)["source"])
		assert.Equal(t, "connection refused", attempts[0].(map[string]any)["error"])
	})

	t.Run("given a stale verdict then it is flagged", func(t *testing.T) {
		locations := []cert.Location{{
			ContentType: cert.ContentTypeCertificate,
			Revocation: &cert.RevocationStatus{
				Source:     cert.RevocationSourceCRL,
				Status:     "good",
				NextUpdate: time.Now().Add(-time.Hour),
			},
		}}

		revocation := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["revocation"].(map[string]any)
		assert.Equal(t, true, revocation["stale"])
	})

	t.Run("given a staple and no check then the staple is reported instead", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)}

		location := firstLocation(t, decodeJSON(t, locations, false, false, false, false))

		staple := location["ocsp_staple"].(map[string]any)
		assert.Equal(t, "good", staple["status"])
		assert.Equal(t, true, staple["signature_verified"])
		assert.NotContains(t, location, "revocation")
	})

	t.Run("given a check was run then it supersedes the staple", func(t *testing.T) {
		chain := newStapleTestChain(t)
		location := chain.location(chain.response(t, ocsp.Response{Status: ocsp.Good}), true)
		location.Revocation = &cert.RevocationStatus{Source: cert.RevocationSourceStaple, Status: "good"}

		decoded := firstLocation(t, decodeJSON(t, []cert.Location{location}, false, false, false, false))

		assert.Contains(t, decoded, "revocation")
		assert.NotContains(t, decoded, "ocsp_staple", "reporting both would be ambiguous")
	})

	t.Run("given a malformed staple then the error is carried", func(t *testing.T) {
		chain := newStapleTestChain(t)
		locations := []cert.Location{chain.location([]byte("garbage"), true)}

		staple := firstLocation(t, decodeJSON(t, locations, false, false, false, false))["ocsp_staple"].(map[string]any)

		assert.Equal(t, "unknown", staple["status"])
		assert.Contains(t, staple["error"], "parse OCSP response")
	})
}

func TestJSONCSR(t *testing.T) {
	locations := []cert.Location{{
		Path:        "request.csr",
		ContentType: cert.ContentTypeCSR,
	}}

	location := firstLocation(t, decodeJSON(t, locations, false, false, false, false))
	assert.Equal(t, "csr", location["type"])
}

func TestJSONEmptyAndShape(t *testing.T) {

	t.Run("given no locations then an empty array is emitted, not null", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, writeJSON(&buf, nil, Options{}))
		assert.Contains(t, buf.String(), `"locations": []`)
	})

	t.Run("given output then it is indented and ends with a newline", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, writeJSON(&buf, []cert.Location{{Path: "a.pem"}}, Options{}))
		assert.Contains(t, buf.String(), "\n  ")
		assert.True(t, bytes.HasSuffix(buf.Bytes(), []byte("\n")))
	})

	t.Run("given a subject with html characters then they are not escaped", func(t *testing.T) {
		var buf bytes.Buffer
		locations := []cert.Location{{Path: "a<b>.pem", Error: errors.New("x & y")}}
		require.NoError(t, writeJSON(&buf, locations, Options{}))
		assert.Contains(t, buf.String(), "a<b>.pem")
		assert.Contains(t, buf.String(), "x & y")
		// go escapes these by default, which would corrupt subjects and DNs
		assert.NotContains(t, buf.String(), `\u003c`)
		assert.NotContains(t, buf.String(), `\u0026`)
	})
}

func Test_contentTypeName(t *testing.T) {
	assert.Equal(t, "csr", contentTypeName(cert.Location{ContentType: cert.ContentTypeCSR}))
	assert.Equal(t, "mixed", contentTypeName(cert.Location{ContentType: cert.ContentTypeMixed}))
	assert.Equal(t, "certificate", contentTypeName(cert.Location{ContentType: cert.ContentTypeCertificate}))
}

func Test_timeOrNil(t *testing.T) {
	assert.Nil(t, timeOrNil(time.Time{}))
	now := time.Now()
	require.NotNil(t, timeOrNil(now))
	assert.Equal(t, now, *timeOrNil(now))
}
