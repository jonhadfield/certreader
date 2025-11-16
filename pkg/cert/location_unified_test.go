package cert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromFile_AutoDetectCertificate(t *testing.T) {
	location := LoadFromFile("testdata/cert.pem", "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCertificate())
	assert.False(t, location.IsCSR())
	assert.Len(t, location.Certificates, 1)
	assert.Len(t, location.CSRs, 0)
}

func TestLoadFromFile_AutoDetectCSR(t *testing.T) {
	location := LoadFromFile("testdata/csr.pem", "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCSR())
	assert.False(t, location.IsCertificate())
	assert.Len(t, location.CSRs, 1)
	assert.Len(t, location.Certificates, 0)
}

func TestLoadFromFile_InvalidFile(t *testing.T) {
	location := LoadFromFile("testdata/nonexistent.pem", "")
	assert.Error(t, location.Error)
}

func TestLoadContent_CertificateTakesPrecedence(t *testing.T) {
	// Read certificate content
	data, err := os.ReadFile("testdata/cert.pem")
	require.NoError(t, err)

	location := loadContent("test", data, "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCertificate())
	assert.False(t, location.IsCSR())
}

func TestLoadContent_CSRDetection(t *testing.T) {
	// Read CSR content
	data, err := os.ReadFile("testdata/csr.pem")
	require.NoError(t, err)

	location := loadContent("test", data, "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCSR())
	assert.False(t, location.IsCertificate())
}

func TestLoadContent_InvalidContent(t *testing.T) {
	invalidData := []byte("this is not a valid PEM")
	location := loadContent("test", invalidData, "")
	assert.Error(t, location.Error)
}

func TestLocations_Operations(t *testing.T) {
	loc1 := LoadFromFile("testdata/cert.pem", "")
	loc2 := LoadFromFile("testdata/csr.pem", "")

	locations := Locations{loc1, loc2}
	assert.Len(t, locations, 2)

	// Test that operations don't crash with mixed content
	filtered := locations.RemoveDuplicates()
	assert.Len(t, filtered, 2)

	sorted := locations.SortByExpiry()
	assert.Len(t, sorted, 2)
}
