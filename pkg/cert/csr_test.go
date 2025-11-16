package cert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromCSRBytes(t *testing.T) {
	data, err := os.ReadFile("testdata/csr.pem")
	require.NoError(t, err)

	csrs, err := FromCSRBytes(data)
	require.NoError(t, err)
	require.Len(t, csrs, 1)

	csr := csrs[0]
	assert.NoError(t, csr.Error())
	assert.Equal(t, 0, csr.Version())
	assert.Contains(t, csr.SubjectString(), "CN=test.example.com")
	assert.Contains(t, csr.SubjectString(), "O=Test Org")
}

func TestCSRToPEM(t *testing.T) {
	data, err := os.ReadFile("testdata/csr.pem")
	require.NoError(t, err)

	csrs, err := FromCSRBytes(data)
	require.NoError(t, err)
	require.Len(t, csrs, 1)

	pem := csrs[0].ToPEM()
	assert.NotNil(t, pem)
	assert.Contains(t, string(pem), "BEGIN CERTIFICATE REQUEST")
	assert.Contains(t, string(pem), "END CERTIFICATE REQUEST")
}

func TestCSRSignatureAlgorithm(t *testing.T) {
	data, err := os.ReadFile("testdata/csr.pem")
	require.NoError(t, err)

	csrs, err := FromCSRBytes(data)
	require.NoError(t, err)
	require.Len(t, csrs, 1)

	assert.NotEmpty(t, csrs[0].SignatureAlgorithm())
	assert.NotEmpty(t, csrs[0].PublicKeyAlgorithm())
}

func TestCSRInvalidPEM(t *testing.T) {
	invalidData := []byte("not a valid PEM")
	_, err := FromCSRBytes(invalidData)
	assert.Error(t, err)
}

func TestCSRMultipleBlocks(t *testing.T) {
	// Create test data with multiple CSR blocks
	data, err := os.ReadFile("testdata/csr.pem")
	require.NoError(t, err)

	// Duplicate the CSR
	multipleCSRs := append(data, data...)

	csrs, err := FromCSRBytes(multipleCSRs)
	require.NoError(t, err)
	assert.Len(t, csrs, 2)
}
