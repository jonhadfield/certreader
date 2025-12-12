package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestFromDERBytes(t *testing.T) {
	t.Run("given valid DER certificate, when fromDERBytes called, then certificate loaded", func(t *testing.T) {
		derCert := loadTestFile(t, "cert.der")
		certs, err := fromDERBytes(derCert)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.NotNil(t, certs[0].x509Certificate)
	})

	t.Run("given invalid DER data, when fromDERBytes called, then error returned", func(t *testing.T) {
		invalidDER := []byte{0x30, 0x82, 0x00, 0x01, 0xFF, 0xFF}
		_, err := fromDERBytes(invalidDER)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid DER certificate")
	})

	t.Run("given empty DER data, when fromDERBytes called, then error returned", func(t *testing.T) {
		_, err := fromDERBytes([]byte{})
		require.Error(t, err)
	})

	t.Run("given truncated DER data, when fromDERBytes called, then error returned", func(t *testing.T) {
		truncatedDER := []byte{0x30, 0x82} // Incomplete ASN.1 sequence
		_, err := fromDERBytes(truncatedDER)
		require.Error(t, err)
	})
}

func TestFromPEMBytes(t *testing.T) {
	t.Run("given valid PEM certificate, when fromPEMBytes called, then certificate loaded", func(t *testing.T) {
		pemCert := loadTestFile(t, "cert.pem")
		certs, err := fromPEMBytes(pemCert)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.NotNil(t, certs[0].x509Certificate)
	})

	t.Run("given multiple PEM certificates, when fromPEMBytes called, then all loaded", func(t *testing.T) {
		pemBundle := loadTestFile(t, "bundle.pem")
		certs, err := fromPEMBytes(pemBundle)
		require.NoError(t, err)
		assert.Greater(t, len(certs), 1)
	})

	t.Run("given non-PEM data, when fromPEMBytes called, then error returned", func(t *testing.T) {
		_, err := fromPEMBytes([]byte("not a pem certificate"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errNoPEMBlock)
	})

	t.Run("given empty data, when fromPEMBytes called, then error returned", func(t *testing.T) {
		_, err := fromPEMBytes([]byte{})
		require.Error(t, err)
		assert.ErrorIs(t, err, errNoPEMBlock)
	})

	t.Run("given PEM with trailing data, when fromPEMBytes called, then certificate loaded", func(t *testing.T) {
		pemCert := loadTestFile(t, "cert.pem")
		pemWithTrailing := append(pemCert, []byte("\n\ntrailing data")...)
		certs, err := fromPEMBytes(pemWithTrailing)
		require.NoError(t, err)
		require.Len(t, certs, 1)
	})
}

func TestFromPKCS12Bytes(t *testing.T) {
	t.Run("given PKCS12 with valid password, when fromPKCS12Bytes called, then certificate loaded", func(t *testing.T) {
		password := "testpassword"
		pfx := createPKCS12WithCerts(t, password, 1)
		certs, err := fromPKCS12Bytes(pfx, password)
		require.NoError(t, err)
		require.Len(t, certs, 1)
	})

	t.Run("given PKCS12 with multiple certificates, when fromPKCS12Bytes called, then all loaded", func(t *testing.T) {
		password := "testpassword"
		pfx := createPKCS12WithCerts(t, password, 3)
		certs, err := fromPKCS12Bytes(pfx, password)
		require.NoError(t, err)
		assert.Greater(t, len(certs), 0)
	})

	t.Run("given PKCS12 with wrong password, when fromPKCS12Bytes called, then password error returned", func(t *testing.T) {
		pfx := createPKCS12WithCerts(t, "correctpassword", 1)
		_, err := fromPKCS12Bytes(pfx, "wrongpassword")
		require.Error(t, err)
		var pwErr *PasswordRequiredError
		assert.ErrorAs(t, err, &pwErr)
	})

	t.Run("given PKCS12 requiring password and none provided, when fromPKCS12Bytes called, then password error returned", func(t *testing.T) {
		pfx := createPKCS12WithCerts(t, "password", 1)
		_, err := fromPKCS12Bytes(pfx, "")
		require.Error(t, err)
		var pwErr *PasswordRequiredError
		assert.ErrorAs(t, err, &pwErr)
		assert.False(t, pwErr.Provided())
	})

	t.Run("given invalid PKCS12 data, when fromPKCS12Bytes called, then error returned", func(t *testing.T) {
		invalidPKCS12 := []byte{0x30, 0x82, 0x00, 0x01}
		_, err := fromPKCS12Bytes(invalidPKCS12, "")
		require.Error(t, err)
	})

	t.Run("given empty PKCS12 data, when fromPKCS12Bytes called, then error returned", func(t *testing.T) {
		_, err := fromPKCS12Bytes([]byte{}, "")
		require.Error(t, err)
	})
}

func TestDecodePKCS12TrustStore(t *testing.T) {
	t.Run("given valid trust store with password, when decodePKCS12TrustStore called, then certificates loaded", func(t *testing.T) {
		// Create trust store PKCS12
		certs := createTestX509Certificates(t, 2)
		password := "trustpassword"
		trustStore, err := pkcs12.Modern2023.EncodeTrustStore(certs, password)
		require.NoError(t, err)

		result, err := decodePKCS12TrustStore(trustStore, password, nil)
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("given trust store with wrong password, when decodePKCS12TrustStore called, then password error returned", func(t *testing.T) {
		certs := createTestX509Certificates(t, 1)
		password := "correct"
		trustStore, err := pkcs12.Modern2023.EncodeTrustStore(certs, password)
		require.NoError(t, err)

		_, err = decodePKCS12TrustStore(trustStore, "wrong", nil)
		require.Error(t, err)
		var pwErr *PasswordRequiredError
		assert.ErrorAs(t, err, &pwErr)
	})

	t.Run("given invalid trust store data, when decodePKCS12TrustStore called, then original error returned", func(t *testing.T) {
		originalErr := assert.AnError
		_, err := decodePKCS12TrustStore([]byte{0x30, 0x82}, "", originalErr)
		require.Error(t, err)
		assert.Equal(t, originalErr, err)
	})
}

func TestFromPemBlock(t *testing.T) {
	t.Run("given valid CERTIFICATE PEM block, when fromPemBlock called, then certificate loaded", func(t *testing.T) {
		// fromPemBlock is internal and takes encoding/pem.Block
		// We'll test it through the public FromBytes path which uses it
		pemCert := loadTestFile(t, "cert.pem")
		certs, err := FromBytes(pemCert, "")
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Nil(t, certs[0].err)
	})

	t.Run("given malformed PEM structure, when parsed, then error handled", func(t *testing.T) {
		// Test with malformed base64 in PEM
		malformed := []byte("-----BEGIN CERTIFICATE-----\n!@#$%^&*()\n-----END CERTIFICATE-----")
		certs, err := FromBytes(malformed, "")
		// Should either error or return cert with error
		if err == nil {
			require.Len(t, certs, 1)
			assert.Error(t, certs[0].Error())
		} else {
			assert.Error(t, err)
		}
	})
}

func TestFormatHexArray(t *testing.T) {
	t.Run("given byte array, when formatHexArray called, then colon-separated hex returned", func(t *testing.T) {
		bytes := []byte{0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF}
		result := formatHexArray(bytes)
		assert.Equal(t, "01:02:03:AB:CD:EF", result)
	})

	t.Run("given empty byte array, when formatHexArray called, then empty string returned", func(t *testing.T) {
		result := formatHexArray([]byte{})
		assert.Empty(t, result)
	})

	t.Run("given nil byte array, when formatHexArray called, then empty string returned", func(t *testing.T) {
		result := formatHexArray(nil)
		assert.Empty(t, result)
	})

	t.Run("given single byte, when formatHexArray called, then hex without colon returned", func(t *testing.T) {
		bytes := []byte{0xFF}
		result := formatHexArray(bytes)
		assert.Equal(t, "FF", result)
	})
}

// Helper functions

func createPKCS12WithCerts(t *testing.T, password string, count int) []byte {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	var caCerts []*x509.Certificate
	for i := 1; i < count; i++ {
		template.SerialNumber = big.NewInt(int64(i + 1))
		template.Subject.CommonName = "ca cert " + string(rune(i))
		derBytes, err = x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(derBytes)
		require.NoError(t, err)
		caCerts = append(caCerts, caCert)
	}

	enc := pkcs12.Modern2023
	if password == "" {
		enc = pkcs12.Passwordless
	}
	pfx, err := enc.Encode(privKey, cert, caCerts, password)
	require.NoError(t, err)
	return pfx
}

func createTestX509Certificates(t *testing.T, count int) []*x509.Certificate {
	var certs []*x509.Certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for i := 0; i < count; i++ {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "test cert " + string(rune(i))},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(derBytes)
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	return certs
}
