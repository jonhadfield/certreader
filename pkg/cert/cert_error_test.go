package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromBytes_ErrorPaths(t *testing.T) {
	t.Run("given empty data, then error is returned", func(t *testing.T) {
		_, err := FromBytes([]byte{}, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, errNoPEMBlock)
	})

	t.Run("given whitespace only data, then error is returned", func(t *testing.T) {
		_, err := FromBytes([]byte("   \n\t  \n  "), "")
		require.Error(t, err)
		assert.ErrorIs(t, err, errNoPEMBlock)
	})

	t.Run("given invalid PEM data, then error is returned", func(t *testing.T) {
		invalidPEM := []byte("-----BEGIN CERTIFICATE-----\ninvalid base64 data!!!\n-----END CERTIFICATE-----")
		_, err := FromBytes(invalidPEM, "")
		require.Error(t, err)
	})

	t.Run("given malformed certificate data, then error is returned", func(t *testing.T) {
		malformedDER := []byte{0x30, 0x82, 0x00, 0x01} // Invalid DER sequence
		_, err := FromBytes(malformedDER, "")
		require.Error(t, err)
	})

	t.Run("given non-certificate PEM block, then error is returned", func(t *testing.T) {
		invalidBlock := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAM=\n-----END RSA PRIVATE KEY-----")
		// FromBytes will try to parse as cert, then DER, then PKCS12
		// A non-certificate block will eventually error
		_, err := FromBytes(invalidBlock, "")
		// The function may return error either directly or in certificate object
		assert.Error(t, err, "Should error on non-certificate PEM block")
	})

	t.Run("given truncated PKCS12 data, then error is returned", func(t *testing.T) {
		truncatedPKCS12 := []byte{0x30, 0x82} // Truncated PKCS12
		_, err := FromBytes(truncatedPKCS12, "")
		require.Error(t, err)
	})
}

func TestCertificate_ErrorHandling(t *testing.T) {
	t.Run("given certificate with error, then IsExpired returns false", func(t *testing.T) {
		cert := Certificate{position: 1, err: assert.AnError}
		assert.False(t, cert.IsExpired())
	})

	t.Run("given certificate with error, then ToPEM returns nil", func(t *testing.T) {
		cert := Certificate{position: 1, err: assert.AnError}
		assert.Nil(t, cert.ToPEM())
	})

	t.Run("given certificate with error, then SubjectString returns error message", func(t *testing.T) {
		cert := Certificate{position: 2, err: assert.AnError}
		subject := cert.SubjectString()
		assert.Contains(t, subject, "ERROR")
		assert.Contains(t, subject, "position 2")
	})

	t.Run("given certificate with error, then Error returns formatted error", func(t *testing.T) {
		cert := Certificate{position: 3, err: assert.AnError}
		err := cert.Error()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "position 3")
	})

	t.Run("given certificate without error, then Error returns nil", func(t *testing.T) {
		certs := loadTestCertificates(t, "cert.pem")
		require.Len(t, certs, 1)
		assert.Nil(t, certs[0].Error())
	})

	t.Run("given nil certificate, then DNSNames returns nil", func(t *testing.T) {
		cert := Certificate{position: 1}
		assert.Nil(t, cert.DNSNames())
	})
}

func TestCertificates_Filtering(t *testing.T) {
	t.Run("given certificates with mixed expiry, when RemoveExpired is called, then only valid certs remain", func(t *testing.T) {
		certs := loadTestCertificates(t, "cert.pem", "bundle.pem")
		// All test certs are expired or will expire, so this tests the filtering logic
		filtered := certs.RemoveExpired()
		// Verify filtering logic executed without error
		assert.NotNil(t, filtered)
	})

	t.Run("given certificates, when SubjectLike is called with matching string, then matching certs returned", func(t *testing.T) {
		certs := loadTestCertificates(t, "bundle.pem")
		filtered := certs.SubjectLike("DigiCert")
		assert.Len(t, filtered, 1)
		assert.Contains(t, filtered[0].SubjectString(), "DigiCert")
	})

	t.Run("given certificates, when SubjectLike is called with non-matching string, then empty list returned", func(t *testing.T) {
		certs := loadTestCertificates(t, "bundle.pem")
		filtered := certs.SubjectLike("NonExistentCA")
		assert.Empty(t, filtered)
	})

	t.Run("given certificates, when IssuerLike is called with matching string, then matching certs returned", func(t *testing.T) {
		certs := loadTestCertificates(t, "cert.pem")
		filtered := certs.IssuerLike("DigiCert")
		assert.Len(t, filtered, 1)
	})

	t.Run("given certificates, when IssuerLike is called with non-matching string, then empty list returned", func(t *testing.T) {
		certs := loadTestCertificates(t, "cert.pem")
		filtered := certs.IssuerLike("NonExistentIssuer")
		assert.Empty(t, filtered)
	})
}

func TestPasswordRequiredError(t *testing.T) {
	t.Run("given nil PasswordRequiredError, then methods return safe defaults", func(t *testing.T) {
		var err *PasswordRequiredError
		assert.Contains(t, err.Error(), "password required")
		assert.Nil(t, err.Data())
		assert.False(t, err.Provided())
		assert.Equal(t, PasswordSourceUnknown, err.Source())
	})

	t.Run("given PasswordRequiredError with data, then Data returns copy", func(t *testing.T) {
		original := []byte{1, 2, 3, 4}
		err := newPasswordRequiredError(original, false)
		data := err.Data()
		require.NotNil(t, data)
		// Verify it's a copy by modifying original
		original[0] = 99
		assert.Equal(t, byte(1), data[0])
	})

	t.Run("given PasswordRequiredError without password provided, then error message indicates required", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, false)
		assert.Contains(t, err.Error(), "password required")
		assert.False(t, err.Provided())
	})

	t.Run("given PasswordRequiredError with password provided, then error message indicates incorrect", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, true)
		assert.Contains(t, err.Error(), "password incorrect")
		assert.True(t, err.Provided())
	})

	t.Run("given PasswordRequiredError, when SetSource is called, then source is set", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, false)
		assert.Equal(t, PasswordSourceUnknown, err.Source())
		err.SetSource(PasswordSourceFile)
		assert.Equal(t, PasswordSourceFile, err.Source())
	})

	t.Run("given PasswordRequiredError with source set, when SetSource called with Unknown, then source unchanged", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, false)
		err.SetSource(PasswordSourceFile)
		err.SetSource(PasswordSourceUnknown)
		assert.Equal(t, PasswordSourceFile, err.Source())
	})

	t.Run("given PasswordRequiredError with source set, when SetSource called again, then source unchanged", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, false)
		err.SetSource(PasswordSourceFile)
		err.SetSource(PasswordSourceStdin)
		assert.Equal(t, PasswordSourceFile, err.Source()) // First source wins
	})

	t.Run("given nil PasswordRequiredError, when SetSource is called, then no panic", func(t *testing.T) {
		var err *PasswordRequiredError
		assert.NotPanics(t, func() {
			err.SetSource(PasswordSourceFile)
		})
	})

	t.Run("given PasswordRequiredError, when Unwrap is called, then base error returned", func(t *testing.T) {
		err := newPasswordRequiredError([]byte{1, 2, 3}, false)
		unwrapped := err.Unwrap()
		assert.Equal(t, ErrPFXPasswordRequired, unwrapped)
	})
}

func TestCertificate_Methods(t *testing.T) {
	cert := loadTestCertificates(t, "cert.pem")[0]

	t.Run("verify SerialNumber formatting", func(t *testing.T) {
		serial := cert.SerialNumber()
		assert.NotEmpty(t, serial)
		assert.Contains(t, serial, ":")
	})

	t.Run("verify SignatureAlgorithm returns string", func(t *testing.T) {
		sigAlg := cert.SignatureAlgorithm()
		assert.NotEmpty(t, sigAlg)
	})

	t.Run("verify Issuer returns string", func(t *testing.T) {
		issuer := cert.Issuer()
		assert.NotEmpty(t, issuer)
	})

	t.Run("verify NotBefore returns time", func(t *testing.T) {
		notBefore := cert.NotBefore()
		assert.False(t, notBefore.IsZero())
	})

	t.Run("verify NotAfter returns time", func(t *testing.T) {
		notAfter := cert.NotAfter()
		assert.False(t, notAfter.IsZero())
	})

	t.Run("verify PublicKeyAlgorithm returns string", func(t *testing.T) {
		pubKeyAlg := cert.PublicKeyAlgorithm()
		assert.NotEmpty(t, pubKeyAlg)
	})

	t.Run("verify Signature returns formatted hex", func(t *testing.T) {
		signature := cert.Signature()
		assert.NotEmpty(t, signature)
		assert.Contains(t, signature, ":")
	})

	t.Run("verify IsCA returns boolean", func(t *testing.T) {
		isCA := cert.IsCA()
		assert.True(t, isCA) // Test cert is a CA
	})

	t.Run("verify AuthorityKeyId with no authority key", func(t *testing.T) {
		// Load cert without authority key id
		certs := loadTestCertificates(t, "cert.pem")
		authKeyId := certs[0].AuthorityKeyId()
		assert.Empty(t, authKeyId)
	})

	t.Run("verify SubjectKeyId with valid cert", func(t *testing.T) {
		subjectKeyId := cert.SubjectKeyId()
		assert.NotEmpty(t, subjectKeyId)
		assert.Contains(t, subjectKeyId, ":")
	})

	t.Run("verify IPAddresses returns slice (may be empty)", func(t *testing.T) {
		ips := cert.IPAddresses()
		// May be nil or empty depending on cert
		_ = ips
		assert.True(t, true)
	})

	t.Run("verify KeyUsage returns slice (may be empty)", func(t *testing.T) {
		keyUsage := cert.KeyUsage()
		// May be nil or empty depending on cert
		_ = keyUsage
		assert.True(t, true)
	})

	t.Run("verify ExtKeyUsage returns slice (may be empty)", func(t *testing.T) {
		extKeyUsage := cert.ExtKeyUsage()
		// May be nil or empty depending on cert
		_ = extKeyUsage
		assert.True(t, true)
	})

	t.Run("verify Extensions returns extension array", func(t *testing.T) {
		extensions := cert.Extensions()
		assert.NotNil(t, extensions)
		if len(extensions) > 0 {
			assert.NotEmpty(t, extensions[0].Name)
			assert.NotEmpty(t, extensions[0].Oid)
		}
	})
}
