package cert

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// proxyForAddress returns the proxy a connection to addr should be tunnelled
// through, or nil to connect directly.
//
// The environment is read on each call rather than once for the process, since
// a single run reads many addresses and NO_PROXY may exclude only some of them.
func proxyForAddress(addr string) (*url.URL, error) {

	value := firstEnv("HTTPS_PROXY", "https_proxy")
	if value == "" {
		return nil, nil
	}
	if !useProxy(addr, firstEnv("NO_PROXY", "no_proxy")) {
		return nil, nil
	}
	return parseProxyURL(value)
}

// firstEnv is the value of the first of the named variables that is set to
// something, empty when none is.
func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

// parseProxyURL reads the value of a proxy environment variable. A bare
// host:port is accepted, and means http, as it does for go's own http client.
//
// A value that names a scheme is held to being a whole url, rather than being
// retried as a bare address: "http://" read that way yields the host "http:",
// which is not what anyone who wrote it meant, and is better refused than
// dialled.
func parseProxyURL(value string) (*url.URL, error) {

	if !strings.Contains(value, "://") {
		// a value such as "proxy.example.com:3128" parses as a scheme rather
		// than as a host, so it is read as the address it plainly is
		bare, err := url.Parse("http://" + value)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy address %q: %w", value, err)
		}
		if bare.Hostname() == "" {
			return nil, fmt.Errorf("invalid proxy address %q, expected a host", value)
		}
		return bare, nil
	}

	proxy, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %w", value, err)
	}
	if proxy.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy address %q, expected a host", value)
	}

	switch proxy.Scheme {
	case "http", "https":
		return proxy, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q in %q, expected http or https", proxy.Scheme, value)
	}
}

// useProxy reports whether addr should be reached through the proxy, given the
// value of NO_PROXY. The rules are the ones go's own client follows: localhost
// and loopback addresses are never proxied, "*" excludes everything else, and
// an entry may name a host, a domain suffix, an ip address or a cidr block,
// optionally with a port that must match as well.
func useProxy(addr string, noProxy string) bool {

	if addr == "" {
		return true
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}
	host = strings.ToLower(strings.Trim(host, "[]"))

	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return false
	}

	for _, entry := range strings.Split(noProxy, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return false
		}

		entryHost := entry
		if splitHost, entryPort, splitErr := net.SplitHostPort(entry); splitErr == nil {
			if entryPort != port {
				continue
			}
			entryHost = splitHost
		}
		entryHost = strings.Trim(entryHost, "[]")

		if _, network, cidrErr := net.ParseCIDR(entryHost); cidrErr == nil {
			if ip != nil && network.Contains(ip) {
				return false
			}
			continue
		}
		if ip != nil {
			if entryIP := net.ParseIP(entryHost); entryIP != nil && entryIP.Equal(ip) {
				return false
			}
			continue
		}

		// a leading dot excludes the subdomains of a zone but not the zone
		// itself, a bare name excludes both
		if strings.HasPrefix(entryHost, ".") {
			if strings.HasSuffix(host, entryHost) {
				return false
			}
			continue
		}
		if host == entryHost || strings.HasSuffix(host, "."+entryHost) {
			return false
		}
	}
	return true
}

// dialProxyTunnel opens a connection to addr through an http proxy. The tunnel
// is asked for with CONNECT, so that the handshake, and the certificates it
// carries, are the target's own rather than the proxy's.
//
// insecure applies to the connection to an https proxy, not to the target: it
// is the same instruction not to verify, followed one hop earlier.
func dialProxyTunnel(addr string, proxy *url.URL, timeout time.Duration, insecure bool) (net.Conn, error) {

	proxyAddr := proxyAddress(proxy)
	raw, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy %s: %w", proxyAddr, err)
	}

	// one budget for reaching the proxy and for it reaching the target, so a
	// proxy that answers slowly cannot hang the whole run
	if err = raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = raw.Close()
		return nil, err
	}

	// an https proxy is itself spoken to over tls; what it then tunnels is a
	// second, independent handshake with the target
	conn := net.Conn(raw)
	if proxy.Scheme == "https" {
		tlsConn := tls.Client(raw, &tls.Config{ServerName: proxy.Hostname(), InsecureSkipVerify: insecure})
		if err = tlsConn.Handshake(); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake with proxy %s: %w", proxyAddr, err)
		}
		conn = tlsConn
	}

	reader, err := proxyConnect(conn, addr, proxy)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &proxyConn{Conn: conn, reader: reader}, nil
}

// proxyConn carries whatever was read past the end of the CONNECT response.
//
// A target that speaks first, as smtp and imap do, can have its greeting
// arrive on the heels of the response and land in the same buffer. Reading the
// connection directly after that would lose it, and the negotiation would then
// wait for a greeting that had already been sent.
type proxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *proxyConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// proxyAddress is the address to dial the proxy on, defaulting the port to the
// one its scheme implies.
func proxyAddress(proxy *url.URL) string {
	if proxy.Port() != "" {
		return proxy.Host
	}
	port := "80"
	if proxy.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(proxy.Hostname(), port)
}

// proxyConnect asks for the tunnel and waits for the proxy to say it is open,
// returning the buffer the answer was read through, since the target's own
// first bytes may already be sitting in it.
//
// The request is written to the connection rather than issued through a client,
// because what follows on it belongs to the target and is not more http.
func proxyConnect(conn net.Conn, addr string, proxy *url.URL) (*bufio.Reader, error) {

	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if user := proxy.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}

	if err := request.Write(conn); err != nil {
		return nil, fmt.Errorf("sending CONNECT to proxy %s: %w", proxy.Host, err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("reading the CONNECT response from proxy %s: %w", proxy.Host, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy %s refused to connect to %s: %s", proxy.Host, addr, response.Status)
	}
	return reader, nil
}

// proxyName describes a proxy for a log line, without its password.
func proxyName(proxy *url.URL) string {
	if proxy == nil {
		return ""
	}
	return proxy.Redacted()
}
