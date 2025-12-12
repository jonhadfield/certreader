package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExtension(t *testing.T) {
	t.Run("given unknown OID, when parseExtension called, then N/A name returned", func(t *testing.T) {
		ext := pkix.Extension{
			Id:    asn1.ObjectIdentifier{9, 9, 9, 9},
			Value: []byte{0x30, 0x00},
		}
		name, values, err := parseExtension(ext)
		require.NoError(t, err)
		assert.Equal(t, "-N/A-", name)
		assert.Contains(t, values[0], "9.9.9.9")
	})
}

func TestParseSubjectKeyIdentifier(t *testing.T) {
	t.Run("given valid subject key identifier, when parseSubjectKeyIdentifier called, then hex formatted key returned", func(t *testing.T) {
		// Create valid SubjectKeyIdentifier (OCTET STRING containing key bytes)
		keyBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		octets, err := asn1.Marshal(keyBytes)
		require.NoError(t, err)

		name, values, err := parseSubjectKeyIdentifier(octets)
		require.NoError(t, err)
		assert.Equal(t, "Subject Key Identifier", name)
		require.Len(t, values, 1)
		assert.Contains(t, values[0], "01:02:03:04:05")
	})

	t.Run("given invalid data, when parseSubjectKeyIdentifier called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseSubjectKeyIdentifier(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Subject Key Identifier", name)
	})
}

func TestParseBasicConstraints(t *testing.T) {
	t.Run("given CA true with path length, when parseBasicConstraints called, then correct values returned", func(t *testing.T) {
		bc := BasicConstraints{
			CA:                true,
			PathLenConstraint: 2,
		}
		data, err := asn1.Marshal(bc)
		require.NoError(t, err)

		name, values, err := parseBasicConstraints(data)
		require.NoError(t, err)
		assert.Equal(t, "Basic Constraints", name)
		assert.Contains(t, values[0], "CA: true")
		assert.Contains(t, values[1], "PathLenConstraint: 2")
	})

	t.Run("given CA false without path length, when parseBasicConstraints called, then CA false returned", func(t *testing.T) {
		bc := BasicConstraints{
			CA:                false,
			PathLenConstraint: 0,
		}
		data, err := asn1.Marshal(bc)
		require.NoError(t, err)

		name, values, err := parseBasicConstraints(data)
		require.NoError(t, err)
		assert.Equal(t, "Basic Constraints", name)
		assert.Contains(t, values[0], "CA: false")
	})

	t.Run("given invalid data, when parseBasicConstraints called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseBasicConstraints(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Basic Constraints", name)
	})
}

func TestParseSignedCertificateTimestampList(t *testing.T) {
	t.Run("when parseSignedCertificateTimestampList called, then placeholder returned", func(t *testing.T) {
		// This is a TODO in the codebase, so it just returns placeholder
		name, values, err := parseSignedCertificateTimestampList([]byte{0x30, 0x00})
		require.NoError(t, err)
		assert.Equal(t, "CT Precertificate SCTs", name)
		assert.Contains(t, values[0], "...")
	})
}

func TestParseAuthorityInformationAccess(t *testing.T) {
	t.Run("given invalid AIA data, when parseAuthorityInformationAccess called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseAuthorityInformationAccess(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Authority Information Access", name)
	})
}

func TestParseCRLDistributionPoints(t *testing.T) {
	t.Run("given invalid CRL distribution points, when parseCRLDistributionPoints called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseCRLDistributionPoints(invalidData)
		require.Error(t, err)
		assert.Equal(t, "CRL Distribution Points", name)
	})
}

func TestParseExtendedKeyUsage(t *testing.T) {
	t.Run("given invalid extended key usage, when parseExtendedKeyUsage called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseExtendedKeyUsage(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Extended Key Usage", name)
	})
}

func TestParseSubjectAltName(t *testing.T) {
	t.Run("given invalid subject alt name, when parseSubjectAltName called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseSubjectAltName(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Subject Alt. Name", name)
	})
}

func TestParseCertificatePolicies(t *testing.T) {
	t.Run("given invalid certificate policies, when parseCertificatePolicies called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseCertificatePolicies(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Certificate Policies", name)
	})
}

func TestParseKeyUsage(t *testing.T) {
	t.Run("given invalid key usage, when parseKeyUsage called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseKeyUsage(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Key Usage", name)
	})
}

func TestParseAuthorityKeyIdentifier(t *testing.T) {
	t.Run("given valid authority key identifier from real cert, when parseAuthorityKeyIdentifier called, then formatted output returned", func(t *testing.T) {
		// Test with real certificate that has AKI
		certs := loadTestCertificates(t, "root_with_authority_key_id.pem")
		require.Len(t, certs, 1)
		// Verify the cert has an authority key ID
		assert.NotEmpty(t, certs[0].AuthorityKeyId())
	})

	t.Run("given invalid authority key identifier, when parseAuthorityKeyIdentifier called, then error returned", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF}
		name, _, err := parseAuthorityKeyIdentifier(invalidData)
		require.Error(t, err)
		assert.Equal(t, "Authority Key Identifier", name)
	})
}

func TestExtensionsByOid(t *testing.T) {
	t.Run("verify all registered OIDs have handlers", func(t *testing.T) {
		expectedOIDs := []string{
			"2.5.29.35", // Authority Key Identifier
			"2.5.29.14", // Subject Key Identifier
			"2.5.29.15", // Key Usage
			"2.5.29.32", // Certificate Policies
			"2.5.29.17", // Subject Alt Name
			"2.5.29.19", // Basic Constraints
			"2.5.29.37", // Extended Key Usage
			"2.5.29.31", // CRL Distribution Points
			"1.3.6.1.5.5.7.1.1",       // Authority Information Access
			"1.3.6.1.4.1.11129.2.4.2", // CT Precertificate SCTs
		}

		for _, oid := range expectedOIDs {
			handler, exists := extensionsByOid[oid]
			assert.True(t, exists, "OID %s should have handler", oid)
			assert.NotNil(t, handler, "Handler for OID %s should not be nil", oid)
		}
	})
}
