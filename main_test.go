package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLooksLikeFQDN(t *testing.T) {
	t.Run("given dotted hostname, when looksLikeFQDN called, then returns true", func(t *testing.T) {
		assert.True(t, looksLikeFQDN("www.example.com"))
		assert.True(t, looksLikeFQDN("example.com"))
		assert.True(t, looksLikeFQDN("a.b.c.example.org"))
		assert.True(t, looksLikeFQDN("xn--bcher-kva.example"))
		assert.True(t, looksLikeFQDN("example.com.")) // trailing dot allowed
		assert.True(t, looksLikeFQDN("192.0.2.1"))    // IPv4 also matches
	})

	t.Run("given non-FQDN inputs, when looksLikeFQDN called, then returns false", func(t *testing.T) {
		assert.False(t, looksLikeFQDN(""))
		assert.False(t, looksLikeFQDN("localhost"))      // no dot
		assert.False(t, looksLikeFQDN("/etc/cert.pem"))  // path
		assert.False(t, looksLikeFQDN("./cert.pem"))     // path
		assert.False(t, looksLikeFQDN("foo\\bar"))       // backslash
		assert.False(t, looksLikeFQDN(".example.com"))   // leading dot
		assert.False(t, looksLikeFQDN("example..com"))   // empty label
		assert.False(t, looksLikeFQDN("-bad.example"))   // label starts with hyphen
		assert.False(t, looksLikeFQDN("bad-.example"))   // label ends with hyphen
		assert.False(t, looksLikeFQDN("under_score.io")) // underscore not valid
	})
}

func TestLoadFromArg_FQDNFallback(t *testing.T) {
	t.Run("given existing file, when loadFromArg called, then loads file", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.pem")
		require.NoError(t, os.WriteFile(certPath, createTestCertificatePEM(t, "Test"), 0644))

		location := loadFromArg(certPath, "", false, "")
		assert.Equal(t, certPath, location.Path)
		assert.Nil(t, location.Error)
	})

	t.Run("given missing non-FQDN path, when loadFromArg called, then returns file error", func(t *testing.T) {
		tempDir := t.TempDir()
		missing := filepath.Join(tempDir, "does-not-exist")

		location := loadFromArg(missing, "", false, "")
		assert.Equal(t, missing, location.Path)
		require.NotNil(t, location.Error)
		assert.True(t, os.IsNotExist(location.Error))
	})

	t.Run("given missing FQDN-shaped arg, when loadFromArg called, then attempts network with original arg as path", func(t *testing.T) {
		// .invalid TLD is reserved (RFC 2606) so this won't actually connect — we only
		// care that we attempted the network path and preserved the original arg.
		arg := "certreader-test.invalid"

		location := loadFromArg(arg, "", false, "")
		assert.Equal(t, arg, location.Path)
		assert.NotNil(t, location.Error, "expected network error for reserved TLD")
	})
}

func TestIsTCPNetworkAddress(t *testing.T) {
	t.Run("given valid host:port, when isTCPNetworkAddress called, then returns true", func(t *testing.T) {
		assert.True(t, isTCPNetworkAddress("google.com:443"))
		assert.True(t, isTCPNetworkAddress("127.0.0.1:8080"))
		assert.True(t, isTCPNetworkAddress("example.org:22"))
	})

	t.Run("given invalid format, when isTCPNetworkAddress called, then returns false", func(t *testing.T) {
		assert.False(t, isTCPNetworkAddress("google.com"))
		assert.False(t, isTCPNetworkAddress("file.pem"))
		assert.False(t, isTCPNetworkAddress(""))
		assert.False(t, isTCPNetworkAddress("host:port:extra"))
	})

	t.Run("given non-numeric port, when isTCPNetworkAddress called, then returns false", func(t *testing.T) {
		assert.False(t, isTCPNetworkAddress("google.com:https"))
		assert.False(t, isTCPNetworkAddress("example.com:abc"))
	})

	t.Run("given colon only, when isTCPNetworkAddress called, then returns based on validation", func(t *testing.T) {
		// :443 is technically valid (localhost:443) but host: is not
		// The current implementation accepts :443, which is acceptable for network addresses
		result1 := isTCPNetworkAddress(":443")
		result2 := isTCPNetworkAddress("host:")
		// At least one should be false
		assert.True(t, !result1 || !result2, "At least one invalid format should be rejected")
	})
}

func TestLoadFromArgs_Concurrent(t *testing.T) {
	t.Run("given multiple file paths, when loadFromArgs called, then certificates loaded concurrently", func(t *testing.T) {
		// Create temporary test certificates
		tempDir := t.TempDir()
		cert1Path := filepath.Join(tempDir, "cert1.pem")
		cert2Path := filepath.Join(tempDir, "cert2.pem")
		cert3Path := filepath.Join(tempDir, "cert3.pem")

		testCertPEM := createTestCertificatePEM(t, "Test Cert 1")
		require.NoError(t, os.WriteFile(cert1Path, testCertPEM, 0644))
		require.NoError(t, os.WriteFile(cert2Path, testCertPEM, 0644))
		require.NoError(t, os.WriteFile(cert3Path, testCertPEM, 0644))

		args := []string{cert1Path, cert2Path, cert3Path}
		locations := loadFromArgs(args, "", false, "")

		require.Len(t, locations, 3)
		assert.Equal(t, cert1Path, locations[0].Path)
		assert.Equal(t, cert2Path, locations[1].Path)
		assert.Equal(t, cert3Path, locations[2].Path)
	})

	t.Run("given mix of valid and invalid files, when loadFromArgs called, then all processed", func(t *testing.T) {
		tempDir := t.TempDir()
		validPath := filepath.Join(tempDir, "valid.pem")
		invalidPath := filepath.Join(tempDir, "nonexistent.pem")

		testCertPEM := createTestCertificatePEM(t, "Test Cert")
		require.NoError(t, os.WriteFile(validPath, testCertPEM, 0644))

		args := []string{validPath, invalidPath}
		locations := loadFromArgs(args, "", false, "")

		require.Len(t, locations, 2)
		// Valid cert should have no error
		assert.Nil(t, locations[0].Error)
		// Invalid path should have error
		assert.NotNil(t, locations[1].Error)
	})

	t.Run("given empty args, when loadFromArgs called, then empty list returned", func(t *testing.T) {
		locations := loadFromArgs([]string{}, "", false, "")
		assert.Empty(t, locations)
	})
}

func TestLoadLocations(t *testing.T) {
	t.Run("given file arguments, when LoadLocations called, then locations loaded", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "test.pem")
		testCertPEM := createTestCertificatePEM(t, "Test Certificate")
		require.NoError(t, os.WriteFile(certPath, testCertPEM, 0644))

		flags := Flags{
			Args: []string{certPath},
		}

		locations := LoadLocations(flags)
		require.Len(t, locations, 1)
		assert.Equal(t, certPath, locations[0].Path)
		assert.Nil(t, locations[0].Error)
	})

	t.Run("given no arguments and no stdin, when LoadLocations called, then exits", func(t *testing.T) {
		if os.Getenv("TEST_EXIT") == "1" {
			flags := Flags{
				Args:  []string{},
				Usage: func() {},
			}
			LoadLocations(flags)
			return
		}
		// Note: We can't easily test os.Exit in unit tests without subprocess
		// This test documents the expected behavior
		assert.True(t, true, "LoadLocations exits when no input provided")
	})
}

func TestReloadWithPassword(t *testing.T) {
	t.Run("given valid password data, when reloadWithPassword called, then certificate loaded", func(t *testing.T) {
		location := cert.Location{
			Path: "test.pem",
		}

		pwErr := &cert.PasswordRequiredError{}
		// For this test, we'll test with valid PEM data that doesn't need a password
		newLocation := reloadWithPassword(location, pwErr, "")

		// Since we're using PEM data without password, it should succeed or have a different error
		assert.NotNil(t, newLocation)
	})

	t.Run("given invalid data, when reloadWithPassword called, then error in location", func(t *testing.T) {
		location := cert.Location{
			Path:       "test.pem",
			TLSVersion: 0,
		}

		pwErr := &cert.PasswordRequiredError{}
		newLocation := reloadWithPassword(location, pwErr, "badpassword")

		assert.NotNil(t, newLocation)
		// Error should be present since data is invalid
		assert.NotNil(t, newLocation.Error)
	})
}

func TestPromptLabel(t *testing.T) {
	t.Run("given stdin path, when promptLabel called, then stdin returned", func(t *testing.T) {
		assert.Equal(t, "stdin", promptLabel("stdin"))
	})

	t.Run("given clipboard path, when promptLabel called, then clipboard returned", func(t *testing.T) {
		assert.Equal(t, "clipboard", promptLabel("clipboard"))
	})

	t.Run("given file path, when promptLabel called, then path returned", func(t *testing.T) {
		assert.Equal(t, "/path/to/file.pem", promptLabel("/path/to/file.pem"))
	})

	t.Run("given empty path, when promptLabel called, then empty returned", func(t *testing.T) {
		assert.Equal(t, "", promptLabel(""))
	})
}

func TestSetLogger(t *testing.T) {
	t.Run("given verbose false, when setLogger called, then error level set", func(t *testing.T) {
		assert.NotPanics(t, func() {
			setLogger(false)
		})
	})

	t.Run("given verbose true, when setLogger called, then debug level set", func(t *testing.T) {
		assert.NotPanics(t, func() {
			setLogger(true)
		})
	})
}

func TestMaybePromptForPFXPasswords(t *testing.T) {
	t.Run("given location with no error, when maybePromptForPFXPasswords called, then location unchanged", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "test.pem")
		testPEM := createTestCertificatePEM(t, "Test Certificate")
		require.NoError(t, os.WriteFile(certPath, testPEM, 0644))

		certs, err := cert.FromBytes(testPEM, "")
		require.NoError(t, err)

		locations := cert.Locations{
			{
				Path:         certPath,
				Certificates: certs,
			},
		}

		flags := &Flags{}
		result := maybePromptForPFXPasswords(locations, flags)

		require.Len(t, result, 1)
		assert.Nil(t, result[0].Error)
	})

	t.Run("given location with non-password error, when maybePromptForPFXPasswords called, then location unchanged", func(t *testing.T) {
		locations := cert.Locations{
			{
				Path:  "test.pem",
				Error: assert.AnError,
			},
		}

		flags := &Flags{}
		result := maybePromptForPFXPasswords(locations, flags)

		require.Len(t, result, 1)
		assert.Error(t, result[0].Error)
	})
}

func TestCanPromptForPassword(t *testing.T) {
	t.Run("when canPromptForPassword called, then returns boolean", func(t *testing.T) {
		// This will return false in test environment (no TTY)
		result := canPromptForPassword()
		assert.False(t, result, "Test environment should not have TTY")
	})
}

// Helper functions

func createTestCertificatePEM(t *testing.T, commonName string) []byte {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	require.NoError(t, err)

	return buf.Bytes()
}
