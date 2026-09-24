package cert

import (
	"crypto/tls"
	"io"
	"os"
	"testing"
	"time"

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

func Test_nameFormat(t *testing.T) {
	t.Run("given no tls version then name is returned", func(t *testing.T) {
		name := nameFormat("test name", 0)
		assert.Equal(t, "test name", name)
	})

	t.Run("given unknown tls version then name and 'unknown' version is returned", func(t *testing.T) {
		name := nameFormat("test name", 67)
		assert.Equal(t, "test name TLS Version 67 (unknown)", name)
	})

	t.Run("given TLS 1.2 tls version then name and 1.2 version is returned", func(t *testing.T) {
		name := nameFormat("test name", tls.VersionTLS12)
		assert.Equal(t, "test name TLS 1.2", name)
	})
}

// A connection was never closed once its certificates were read, so every
// socket stayed open until the program exited and -concurrency bounded how
// many were being made at once but not how many were held.
func TestLoadFromNetworkClosesTheConnection(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", newTestServerTLSConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	closed := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			closed <- acceptErr
			return
		}
		defer conn.Close()
		if handshakeErr := conn.(*tls.Conn).Handshake(); handshakeErr != nil {
			closed <- handshakeErr
			return
		}
		// the client sends nothing, so the read ends only when it hangs up
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, readErr := conn.Read(make([]byte, 1))
		closed <- readErr
	}()

	location := LoadFromNetwork(listener.Addr().String(), NetworkOptions{InsecureSkipVerify: true})
	require.NoError(t, location.Error)

	select {
	case readErr := <-closed:
		assert.ErrorIs(t, readErr, io.EOF, "the server should see the client hang up, not time out waiting")
	case <-time.After(10 * time.Second):
		t.Fatal("the server never finished reading")
	}
}
