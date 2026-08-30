package print

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintCertificate(t *testing.T) {
	t.Run("given valid certificate, when printCertificate called, then certificate info is printed", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		certs := createTestCertificates(t, 1)
		printCertificate(certs[0], false, false)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		// Verify output contains certificate information
		assert.Contains(t, string(output), "Version")
	})
}

func TestValidityFormat(t *testing.T) {
	t.Run("given time, when validityFormat called, then formatted string returned", func(t *testing.T) {
		testTime := time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC)
		formatted := validityFormat(testTime)
		assert.Contains(t, formatted, "Jan")
		assert.Contains(t, formatted, "15")
		assert.Contains(t, formatted, "2024")
	})
}

func TestSplitString(t *testing.T) {
	t.Run("given string shorter than size, when splitString called, then single line returned", func(t *testing.T) {
		result := splitString("short", "    ", 10)
		require.Len(t, result, 1)
		assert.Equal(t, "    short", result[0])
	})

	t.Run("given string longer than size, when splitString called, then multiple lines returned", func(t *testing.T) {
		longString := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		result := splitString(longString, "    ", 10)
		assert.Greater(t, len(result), 1)
		for _, line := range result {
			assert.Contains(t, line, "    ")
		}
	})

	t.Run("given string exactly size, when splitString called, then properly chunked", func(t *testing.T) {
		exactString := "1234567890"
		result := splitString(exactString, "", 10)
		require.Len(t, result, 1)
		assert.Equal(t, "1234567890", result[0])
	})
}

func TestLocationUnified(t *testing.T) {
	t.Run("given valid locations, when LocationsUnified called, then output generated", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		certs := createTestCertificates(t, 1)
		locations := cert.Locations{
			{
				Path:         "test.pem",
				Certificates: certs,
			},
		}

		LocationsUnified(locations, false, false, false, false)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.Contains(t, string(output), "test.pem")
	})

	t.Run("given location with error, when LocationsUnified called, then error shown", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		locations := cert.Locations{
			{
				Path:  "error.pem",
				Error: assert.AnError,
			},
		}

		LocationsUnified(locations, false, false, false, false)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.Contains(t, string(output), "error.pem")
	})
}

func TestPemUnified(t *testing.T) {
	t.Run("given valid locations, when PemUnified called, then PEM output generated", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		certs := createTestCertificates(t, 1)
		locations := cert.Locations{
			{
				Path:         "test.pem",
				Certificates: certs,
			},
		}

		PemUnified(locations, false)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.Contains(t, string(output), "BEGIN CERTIFICATE")
	})

	t.Run("given location with error, when PemUnified called, then error shown", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		locations := cert.Locations{
			{
				Path:  "error.pem",
				Error: assert.AnError,
			},
		}

		PemUnified(locations, false)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.Contains(t, string(output), "error.pem")
	})
}

func TestExpiryUnifiedNamesEachCertificate(t *testing.T) {
	// every line shares the location prefix, so without a name the
	// certificates in a chain cannot be told apart
	certs := createTestCertificates(t, 2)
	locations := cert.Locations{{Path: "test.pem", Certificates: certs}}

	output := captureStdout(t, func() { ExpiryUnified(locations) })

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		assert.Contains(t, line, "test.pem:")
		assert.Regexp(t, `test\.pem: .+  \S`, line, "the line should end with a name")
	}
}

func Test_expirySubject(t *testing.T) {
	certs := createTestCertificates(t, 1)
	require.NotEmpty(t, certs)

	// the common name is enough, and keeps the line short
	assert.Equal(t, certs[0].CommonName(), expirySubject(certs[0]))
	assert.NotContains(t, expirySubject(certs[0]), "CN=", "the full distinguished name would be too long")
}

func TestExpiryUnified(t *testing.T) {
	t.Run("given valid locations, when ExpiryUnified called, then expiry output generated", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		certs := createTestCertificates(t, 1)
		locations := cert.Locations{
			{
				Path:         "test.pem",
				Certificates: certs,
			},
		}

		ExpiryUnified(locations)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.NotEmpty(t, output)
	})

	t.Run("given location with error, when ExpiryUnified called, then handled gracefully", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		locations := cert.Locations{
			{
				Path:  "error.pem",
				Error: assert.AnError,
			},
		}

		ExpiryUnified(locations)

		w.Close()
		os.Stdout = oldStdout
		output, _ := io.ReadAll(r)

		assert.NotNil(t, output)
	})
}

func createTestCertificates(t *testing.T, count int) cert.Certificates {
	var certs cert.Certificates
	for i := 0; i < count; i++ {
		cert := createTestCertificate(t, i+1)
		certs = append(certs, cert)
	}
	return certs
}

func createTestCertificate(t *testing.T, serialNum int) cert.Certificate {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serialNum)),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	return cert.FromX509Certificates([]*x509.Certificate{x509Cert})[0]
}
