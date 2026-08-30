package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBareHost(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "a hostname is the host", arg: "google.com", want: "google.com"},
		{name: "an IPv4 address is the host", arg: "1.1.1.1", want: "1.1.1.1"},
		{name: "an IPv6 address is the host", arg: "::1", want: "::1"},
		{name: "brackets around an IPv6 address are not part of it", arg: "[2606:2800:21f::1]", want: "2606:2800:21f::1"},
		{name: "an address with a port is not bare", arg: "google.com:443"},
		// A dotted name that is not a file on disk reads as a hostname: that is
		// the fallback that lets a bare hostname be given without a port.
		{name: "a name that is not there reads as a hostname", arg: "cert.pem", want: "cert.pem"},
		{name: "a name with no dot is not a hostname", arg: "bundle"},
		{name: "half a bracket is not an address", arg: "[::1"},
		{name: "nothing is not a host", arg: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, ok := bareHost(test.arg)
			assert.Equal(t, test.want != "", ok)
			assert.Equal(t, test.want, host)
		})
	}
}

// TestLoadFromArgOverIPv6 completes a real handshake over the IPv6 loopback,
// which is the whole point: the address has to survive being classified, dialled
// and reported.
func TestLoadFromArgOverIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}

	certificate := serverCertificate(t)
	served := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	t.Cleanup(func() { _ = served.Close() })

	go func() {
		for {
			conn, err := served.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	addr := served.Addr().String()
	require.True(t, isTCPNetworkAddress(addr), "the listener's own address has to read as an address")

	location := loadFromArg(addr, Flags{Insecure: true})
	require.Nil(t, location.Error)
	require.Len(t, location.Certificates, 1)
	assert.Equal(t, addr, location.Path)
	assert.Contains(t, location.Certificates[0].SubjectString(), "ipv6-loopback")
}

// serverCertificate is a self-signed certificate for the test listener, built
// in memory so the handshake has something to present.
func serverCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ipv6-loopback"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
