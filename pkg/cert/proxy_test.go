package cert

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordedConnect is what a proxy was asked for, so a test can show the tunnel
// was opened to the target rather than to the proxy itself.
type recordedConnect struct {
	target string
	auth   string
}

// startTunnelProxy runs an http proxy that pipes each CONNECT to backend. A non
// empty refuse status is returned instead of opening the tunnel.
func startTunnelProxy(t *testing.T, backend string, refuse string) (string, <-chan recordedConnect) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	recorded := make(chan recordedConnect, 4)

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveTunnel(conn, backend, refuse, recorded)
		}
	}()

	return listener.Addr().String(), recorded
}

func serveTunnel(client net.Conn, backend string, refuse string, recorded chan<- recordedConnect) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(client)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	recorded <- recordedConnect{target: request.Host, auth: request.Header.Get("Proxy-Authorization")}

	if refuse != "" || request.Method != http.MethodConnect {
		if refuse == "" {
			refuse = "405 Method Not Allowed"
		}
		_, _ = fmt.Fprintf(client, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", refuse)
		return
	}

	server, dialErr := net.Dial("tcp", backend)
	if dialErr != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// the reader rather than the connection, so that anything it buffered while
	// reading the request is still carried through
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(server, reader)
		close(done)
	}()
	_, _ = io.Copy(client, server)
	<-done
}

// startGreetingTunnelProxy opens the tunnel and sends the target's greeting in
// the same write as the CONNECT response, which is what a proxy in front of a
// server that speaks first may do. The greeting is then in the client's buffer
// before anything asks for it, which is the case a timing race would otherwise
// only sometimes produce.
func startGreetingTunnelProxy(t *testing.T, backend string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		client, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))

		reader := bufio.NewReader(client)
		if _, err = http.ReadRequest(reader); err != nil {
			return
		}

		server, dialErr := net.Dial("tcp", backend)
		if dialErr != nil {
			return
		}
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(10 * time.Second))

		greeting := make([]byte, 512)
		read, readErr := server.Read(greeting)
		if readErr != nil {
			return
		}

		response := append([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), greeting[:read]...)
		if _, err = client.Write(response); err != nil {
			return
		}

		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(server, reader)
			close(done)
		}()
		_, _ = io.Copy(client, server)
		<-done
	}()

	return listener.Addr().String()
}

// startTLSTunnelProxy runs the same proxy behind tls, which is what an
// https:// proxy url names: the CONNECT exchange itself is encrypted.
func startTLSTunnelProxy(t *testing.T, backend string) (string, <-chan recordedConnect) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", newTestServerTLSConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	recorded := make(chan recordedConnect, 4)

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveTunnel(conn, backend, "", recorded)
		}
	}()

	return listener.Addr().String(), recorded
}

// startTLSBackend serves the test certificate directly, recording the name each
// client asked for so a test can show sni survived the tunnel.
func startTLSBackend(t *testing.T) (string, <-chan string) {
	t.Helper()

	config := newTestServerTLSConfig(t)
	names := make(chan string, 4)
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		names <- hello.ServerName
		return nil, nil
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return listener.Addr().String(), names
}

func TestLoadFromNetworkThroughProxy(t *testing.T) {

	t.Run("given HTTPS_PROXY then the certificate comes from the target through the tunnel", func(t *testing.T) {
		backend, names := startTLSBackend(t)
		proxy, connects := startTunnelProxy(t, backend, "")
		t.Setenv("HTTPS_PROXY", "http://"+proxy)

		// self signed and named for the backend, so verification is skipped;
		// the point is that the tunnel carried the handshake
		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		require.NoError(t, location.Error)
		require.Len(t, location.Certificates, 1)
		assert.Equal(t, "CN=certreader starttls test", location.Certificates[0].SubjectString())
		assert.NotZero(t, location.TLSVersion, "the handshake must actually have happened")

		connect := <-connects
		assert.Equal(t, "example.test:443", connect.target, "the tunnel is opened to the target")
		assert.Empty(t, connect.auth)
		assert.Equal(t, "example.test", <-names, "sni names the target, not the proxy")
	})

	t.Run("given an https proxy then the connect exchange is itself encrypted", func(t *testing.T) {
		backend, names := startTLSBackend(t)
		proxy, connects := startTLSTunnelProxy(t, backend)
		t.Setenv("HTTPS_PROXY", "https://"+proxy)

		// the proxy's own certificate is self signed too, so verification is
		// skipped for both hops
		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		require.NoError(t, location.Error)
		require.Len(t, location.Certificates, 1)
		assert.Equal(t, "example.test:443", (<-connects).target)
		assert.Equal(t, "example.test", <-names, "the target's handshake is the one the certificate came from")
	})

	t.Run("given credentials in the proxy url then they are offered to the proxy", func(t *testing.T) {
		backend, _ := startTLSBackend(t)
		proxy, connects := startTunnelProxy(t, backend, "")
		t.Setenv("HTTPS_PROXY", "http://someone:s3cret@"+proxy)

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		require.NoError(t, location.Error)
		assert.Equal(t, "Basic c29tZW9uZTpzM2NyZXQ=", (<-connects).auth)
	})

	t.Run("given a server name then it overrides the name taken from the address", func(t *testing.T) {
		backend, names := startTLSBackend(t)
		proxy, connects := startTunnelProxy(t, backend, "")
		t.Setenv("HTTPS_PROXY", "http://"+proxy)

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true, ServerName: "other.test"})

		require.NoError(t, location.Error)
		assert.Equal(t, "example.test:443", (<-connects).target, "the tunnel still goes to the address")
		assert.Equal(t, "other.test", <-names)
	})

	t.Run("given starttls then the negotiation happens with the target through the tunnel", func(t *testing.T) {
		backend := startPlaintextServer(t, smtpExchange)
		proxy, connects := startTunnelProxy(t, backend, "")
		t.Setenv("HTTPS_PROXY", "http://"+proxy)

		location := LoadFromNetwork("mail.example.test:587", NetworkOptions{InsecureSkipVerify: true, StartTLS: StartTLSSMTP})

		require.NoError(t, location.Error)
		require.Len(t, location.Certificates, 1)
		assert.Equal(t, "mail.example.test:587", (<-connects).target)
	})

	t.Run("given the greeting arrives with the connect response then the negotiation still sees it", func(t *testing.T) {
		backend := startPlaintextServer(t, smtpExchange)
		proxy := startGreetingTunnelProxy(t, backend)
		t.Setenv("HTTPS_PROXY", "http://"+proxy)

		location := LoadFromNetwork("mail.example.test:587", NetworkOptions{InsecureSkipVerify: true, StartTLS: StartTLSSMTP})

		require.NoError(t, location.Error)
		require.Len(t, location.Certificates, 1)
	})

	t.Run("given NO_PROXY covers the address then the proxy is not used", func(t *testing.T) {
		// a proxy that opens the tunnel to a working backend, so reaching it
		// would succeed and only a direct connection can fail
		backend, _ := startTLSBackend(t)
		proxy, connects := startTunnelProxy(t, backend, "")
		t.Setenv("HTTPS_PROXY", "http://"+proxy)
		t.Setenv("NO_PROXY", "example.test")

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		// the name does not resolve, which it never had to when the proxy was
		// the one being dialled
		require.Error(t, location.Error)
		assert.Empty(t, connects, "the proxy was never asked for a tunnel")
	})

	t.Run("given the proxy refuses then the status is reported", func(t *testing.T) {
		proxy, _ := startTunnelProxy(t, "", "407 Proxy Authentication Required")
		t.Setenv("HTTPS_PROXY", "http://"+proxy)

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "407 Proxy Authentication Required")
		assert.Contains(t, location.Error.Error(), "example.test:443")
	})

	t.Run("given the proxy cannot be reached then the error says so", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		unused := listener.Addr().String()
		require.NoError(t, listener.Close())

		t.Setenv("HTTPS_PROXY", "http://"+unused)

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true, Timeout: 2 * time.Second})

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "connecting to proxy "+unused)
	})

	t.Run("given an unsupported proxy scheme then the address is rejected", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "socks5://127.0.0.1:1080")

		location := LoadFromNetwork("example.test:443", NetworkOptions{InsecureSkipVerify: true})

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "unsupported proxy scheme")
	})
}

func TestProxyForAddress(t *testing.T) {

	t.Run("given no proxy in the environment then the connection is direct", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "")
		t.Setenv("https_proxy", "")

		proxy, err := proxyForAddress("example.com:443")

		require.NoError(t, err)
		assert.Nil(t, proxy)
	})

	t.Run("given only the lowercase variable then it is still read", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "")
		t.Setenv("https_proxy", "http://proxy.example.com:3128")
		t.Setenv("NO_PROXY", "")

		proxy, err := proxyForAddress("example.com:443")

		require.NoError(t, err)
		require.NotNil(t, proxy)
		assert.Equal(t, "proxy.example.com:3128", proxy.Host)
	})

	t.Run("given both variables then the uppercase one wins", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://upper.example.com:3128")
		t.Setenv("https_proxy", "http://lower.example.com:3128")
		t.Setenv("NO_PROXY", "")

		proxy, err := proxyForAddress("example.com:443")

		require.NoError(t, err)
		require.NotNil(t, proxy)
		assert.Equal(t, "upper.example.com:3128", proxy.Host)
	})

	t.Run("given a loopback target then the proxy is skipped", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
		t.Setenv("NO_PROXY", "")

		proxy, err := proxyForAddress("127.0.0.1:8443")

		require.NoError(t, err)
		assert.Nil(t, proxy)
	})
}

func TestParseProxyURL(t *testing.T) {

	tests := []struct {
		name  string
		value string
		host  string
		error string
	}{
		{name: "an http url", value: "http://proxy.example.com:3128", host: "proxy.example.com:3128"},
		{name: "an https url", value: "https://proxy.example.com:8443", host: "proxy.example.com:8443"},
		{name: "a bare host and port, which means http", value: "proxy.example.com:3128", host: "proxy.example.com:3128"},
		{name: "a bare address without a port", value: "proxy.example.com", host: "proxy.example.com"},
		{name: "an unsupported scheme", value: "socks5://proxy.example.com:1080", error: "unsupported proxy scheme"},
		{name: "a scheme and nothing else", value: "http://", error: "expected a host"},
		{name: "an https scheme and nothing else", value: "https://", error: "expected a host"},
		{name: "a port with no host", value: "http://:3128", error: "expected a host"},
		{name: "a separator with no scheme", value: "://proxy.example.com:3128", error: "invalid proxy address"},
		{name: "nothing at all", value: "", error: "expected a host"},
	}

	for _, test := range tests {
		t.Run("given "+test.name, func(t *testing.T) {
			proxy, err := parseProxyURL(test.value)

			if test.error != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.error)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.host, proxy.Host)
		})
	}
}

func TestProxyAddress(t *testing.T) {

	tests := []struct {
		value string
		want  string
	}{
		{"http://proxy.example.com:3128", "proxy.example.com:3128"},
		{"http://proxy.example.com", "proxy.example.com:80"},
		{"https://proxy.example.com", "proxy.example.com:443"},
		{"http://[::1]:3128", "[::1]:3128"},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			proxy, err := parseProxyURL(test.value)
			require.NoError(t, err)
			assert.Equal(t, test.want, proxyAddress(proxy))
		})
	}
}

func TestUseProxy(t *testing.T) {

	tests := []struct {
		name    string
		addr    string
		noProxy string
		want    bool
	}{
		{name: "an ordinary host with no exclusions", addr: "example.com:443", want: true},
		{name: "localhost", addr: "localhost:8443", want: false},
		{name: "a loopback address", addr: "127.0.0.1:8443", want: false},
		{name: "an ipv6 loopback address", addr: "[::1]:8443", want: false},
		{name: "everything excluded", addr: "example.com:443", noProxy: "*", want: false},
		{name: "the named host", addr: "example.com:443", noProxy: "example.com", want: false},
		{name: "a subdomain of a named zone", addr: "www.example.com:443", noProxy: "example.com", want: false},
		{name: "a zone named with a leading dot", addr: "www.example.com:443", noProxy: ".example.com", want: false},
		{name: "the zone itself, named with a leading dot", addr: "example.com:443", noProxy: ".example.com", want: true},
		{name: "a host that merely ends with the entry", addr: "notexample.com:443", noProxy: "example.com", want: true},
		{name: "one entry in a list", addr: "example.com:443", noProxy: "other.com, example.com ,third.com", want: false},
		{name: "an excluded ip address", addr: "203.0.113.5:443", noProxy: "203.0.113.5", want: false},
		{name: "an ip address in an excluded block", addr: "10.1.2.3:443", noProxy: "10.0.0.0/8", want: false},
		{name: "an ip address outside an excluded block", addr: "11.1.2.3:443", noProxy: "10.0.0.0/8", want: true},
		{name: "a matching host and port", addr: "example.com:443", noProxy: "example.com:443", want: false},
		{name: "a matching host on another port", addr: "example.com:8443", noProxy: "example.com:443", want: true},
		{name: "a name in a different case", addr: "EXAMPLE.com:443", noProxy: "example.COM", want: false},
		{name: "an address with no port", addr: "example.com", noProxy: "example.com", want: false},
	}

	for _, test := range tests {
		t.Run("given "+test.name, func(t *testing.T) {
			assert.Equal(t, test.want, useProxy(test.addr, test.noProxy))
		})
	}
}

func TestProxyName(t *testing.T) {

	t.Run("given no proxy then the name is empty", func(t *testing.T) {
		assert.Empty(t, proxyName(nil))
	})

	t.Run("given credentials then the password is not named", func(t *testing.T) {
		proxy, err := parseProxyURL("http://someone:s3cret@proxy.example.com:3128")
		require.NoError(t, err)

		assert.Equal(t, "http://someone:xxxxx@proxy.example.com:3128", proxyName(proxy))
	})
}
