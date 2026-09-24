package main

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLAddress(t *testing.T) {
	t.Run("given an https url, when urlAddress called, then returns its host and port", func(t *testing.T) {
		tests := map[string]string{
			"https://example.com":                    "example.com:443",
			"https://example.com/":                   "example.com:443",
			"https://example.com:8443":               "example.com:8443",
			"https://example.com/some/page?q=1#frag": "example.com:443",
			"HTTPS://Example.com":                    "Example.com:443",
			"https://user@example.com":               "example.com:443",
			"https://192.0.2.1:8443/":                "192.0.2.1:8443",
			"https://[2606:2800:21f::1]/":            "[2606:2800:21f::1]:443",
			"https://[::1]:8443":                     "[::1]:8443",
		}
		for arg, want := range tests {
			address, ok, err := urlAddress(arg, cert.StartTLSNone)
			require.NoError(t, err, arg)
			assert.True(t, ok, arg)
			assert.Equal(t, want, address, arg)
		}
	})

	t.Run("given an argument that is not a url, when urlAddress called, then leaves it alone", func(t *testing.T) {
		for _, arg := range []string{"example.com", "example.com:443", "[::1]:443", "cert.pem", `C:\certs\bundle.pem`, "/etc/ssl/cert.pem"} {
			_, ok, err := urlAddress(arg, cert.StartTLSNone)
			assert.NoError(t, err, arg)
			assert.False(t, ok, arg)
		}
	})

	t.Run("given a scheme that is not https, when urlAddress called, then says to give host:port", func(t *testing.T) {
		// http is not tls, and neither is ssh; the services that upgrade to tls
		// are read with -starttls, which a url cannot say
		for _, arg := range []string{"http://example.com", "ssh://example.com", "smtp://mail.example.com", "file:///etc/ssl/cert.pem"} {
			_, ok, err := urlAddress(arg, cert.StartTLSNone)
			assert.True(t, ok, arg)
			require.Error(t, err, arg)
			assert.Contains(t, err.Error(), "host:port", arg)
		}
	})

	t.Run("given an https url with -starttls, when urlAddress called, then refuses the combination", func(t *testing.T) {
		_, ok, err := urlAddress("https://mail.example.com", cert.StartTLSSMTP)
		assert.True(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-starttls")
	})

	t.Run("given an https url with no host or a bad port, when urlAddress called, then returns an error", func(t *testing.T) {
		for _, arg := range []string{"https://", "https:///path", "https://example.com:port"} {
			_, ok, err := urlAddress(arg, cert.StartTLSNone)
			assert.True(t, ok, arg)
			assert.Error(t, err, arg)
		}
	})
}

func TestLoadFromArgURL(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	served := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{serverCertificate(t)}})
	t.Cleanup(func() { _ = served.Close() })

	go func() {
		for {
			conn, acceptErr := served.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	addr := served.Addr().String()

	t.Run("given an https url for a listening server, when loadFromArg called, then reads its certificate", func(t *testing.T) {
		location := loadFromArg("https://"+addr+"/some/page", Flags{Insecure: true})
		require.Nil(t, location.Error)
		require.Len(t, location.Certificates, 1)
		// named by the address, which -verify takes the hostname from
		assert.Equal(t, addr, location.Path)
	})

	t.Run("given an http url, when loadFromArg called, then reports the error against the argument", func(t *testing.T) {
		arg := "http://" + addr
		location := loadFromArg(arg, Flags{})
		require.Error(t, location.Error)
		assert.Equal(t, arg, location.Path)
	})
}
