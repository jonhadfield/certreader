package cert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromDERBytes_Certificate(t *testing.T) {
	data, err := os.ReadFile("testdata/cert.der")
	require.NoError(t, err)

	certificates, err := fromDERBytes(data)
	require.NoError(t, err)
	require.Len(t, certificates, 1)

	cert := certificates[0]
	assert.NoError(t, cert.Error())
	assert.Equal(t, 3, cert.Version())
	assert.Contains(t, cert.SubjectString(), "CN=DigiCert Global Root G2")
}

func TestFromBytes_DER_Certificate(t *testing.T) {
	data, err := os.ReadFile("testdata/cert.der")
	require.NoError(t, err)

	certificates, err := FromBytes(data, "")
	require.NoError(t, err)
	require.Len(t, certificates, 1)

	cert := certificates[0]
	assert.NoError(t, cert.Error())
	assert.Equal(t, 3, cert.Version())
}

func TestFromCSRDERBytes(t *testing.T) {
	data, err := os.ReadFile("testdata/csr.der")
	require.NoError(t, err)

	csrs, err := fromCSRDERBytes(data)
	require.NoError(t, err)
	require.Len(t, csrs, 1)

	csr := csrs[0]
	assert.NoError(t, csr.Error())
	assert.Equal(t, 0, csr.Version())
	assert.Contains(t, csr.SubjectString(), "CN=test.example.com")
}

func TestFromCSRBytes_DER(t *testing.T) {
	data, err := os.ReadFile("testdata/csr.der")
	require.NoError(t, err)

	csrs, err := FromCSRBytes(data)
	require.NoError(t, err)
	require.Len(t, csrs, 1)

	csr := csrs[0]
	assert.NoError(t, csr.Error())
	assert.Equal(t, 0, csr.Version())
}

func TestLoadFromFile_DER_Certificate(t *testing.T) {
	location := LoadFromFile("testdata/cert.der", "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCertificate())
	assert.False(t, location.IsCSR())
	assert.Len(t, location.Certificates, 1)
	assert.Contains(t, location.Certificates[0].SubjectString(), "CN=DigiCert Global Root G2")
}

func TestLoadFromFile_DER_CSR(t *testing.T) {
	location := LoadFromFile("testdata/csr.der", "")
	require.NoError(t, location.Error)
	assert.True(t, location.IsCSR())
	assert.False(t, location.IsCertificate())
	assert.Len(t, location.CSRs, 1)
	assert.Contains(t, location.CSRs[0].SubjectString(), "CN=test.example.com")
}

func TestDER_InvalidData(t *testing.T) {
	invalidData := []byte{0x00, 0x01, 0x02, 0x03}

	_, err := fromDERBytes(invalidData)
	assert.Error(t, err)

	_, err = fromCSRDERBytes(invalidData)
	assert.Error(t, err)
}
