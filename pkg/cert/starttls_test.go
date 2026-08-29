package cert

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServerTLSConfig returns a config serving a self signed certificate for
// localhost, so the handshake after negotiation is a real one.
func newTestServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certreader starttls test"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	return &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}}}
}

// startPlaintextServer accepts one connection, runs the given plaintext
// exchange, and then serves TLS over the same connection.
func startPlaintextServer(t *testing.T, exchange func(t *testing.T, conn net.Conn) bool) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	config := newTestServerTLSConfig(t)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if !exchange(t, conn) {
			return
		}

		server := tls.Server(conn, config)
		_ = server.Handshake()
		// the client only needs the certificate, so a close here is fine
		_ = server.Close()
	}()

	return listener.Addr().String()
}

func smtpExchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	io.WriteString(conn, "220 test ESMTP ready\r\n")
	r.ReadString('\n') // EHLO
	io.WriteString(conn, "250-test greets you\r\n250 STARTTLS\r\n")
	r.ReadString('\n') // STARTTLS
	io.WriteString(conn, "220 ready to start tls\r\n")
	return true
}

func imapExchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	io.WriteString(conn, "* OK test IMAP4rev1 ready\r\n")
	r.ReadString('\n')
	// an untagged line before the tagged completion, as servers may send
	io.WriteString(conn, "* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK begin tls\r\n")
	return true
}

func pop3Exchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	io.WriteString(conn, "+OK test POP3 ready\r\n")
	r.ReadString('\n')
	io.WriteString(conn, "+OK begin tls\r\n")
	return true
}

func ftpExchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	io.WriteString(conn, "220-welcome\r\n220 test FTP\r\n")
	r.ReadString('\n')
	io.WriteString(conn, "234 proceed with negotiation\r\n")
	return true
}

func nntpExchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	io.WriteString(conn, "200 test NNTP ready\r\n")
	r.ReadString('\n')
	io.WriteString(conn, "382 continue with tls\r\n")
	return true
}

func postgresExchange(_ *testing.T, conn net.Conn) bool {
	request := make([]byte, 8)
	if _, err := io.ReadFull(conn, request); err != nil {
		return false
	}
	conn.Write([]byte{'S'})
	return true
}

func ldapExchange(_ *testing.T, conn net.Conn) bool {
	r := bufio.NewReader(conn)
	if _, err := readBERElement(r, 0x30); err != nil {
		return false
	}
	// ExtendedResponse with resultCode 0, empty matchedDN and diagnostic
	response := []byte{0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	body := append([]byte{0x02, 0x01, 0x01}, response...)
	conn.Write(append([]byte{0x30, byte(len(body))}, body...))
	return true
}

func TestLoadFromNetworkStartTLS(t *testing.T) {

	tests := []struct {
		protocol StartTLSProtocol
		exchange func(*testing.T, net.Conn) bool
	}{
		{StartTLSSMTP, smtpExchange},
		{StartTLSIMAP, imapExchange},
		{StartTLSPOP3, pop3Exchange},
		{StartTLSFTP, ftpExchange},
		{StartTLSNNTP, nntpExchange},
		{StartTLSPostgres, postgresExchange},
		{StartTLSLDAP, ldapExchange},
	}

	for _, test := range tests {
		t.Run(string(test.protocol)+" negotiates and retrieves the certificate", func(t *testing.T) {
			addr := startPlaintextServer(t, test.exchange)

			// self signed, so verification is skipped; the point is the upgrade
			location := LoadFromNetwork(addr, "", true, test.protocol)

			require.NoError(t, location.Error)
			require.Len(t, location.Certificates, 1)
			assert.Equal(t, "CN=certreader starttls test", location.Certificates[0].SubjectString())
			assert.NotZero(t, location.TLSVersion, "the handshake must actually have happened")
		})
	}
}

func TestLoadFromNetworkStartTLSFailures(t *testing.T) {

	t.Run("given a server that refuses tls then the error explains why", func(t *testing.T) {
		addr := startPlaintextServer(t, func(_ *testing.T, conn net.Conn) bool {
			request := make([]byte, 8)
			io.ReadFull(conn, request)
			conn.Write([]byte{'N'})
			return false
		})

		location := LoadFromNetwork(addr, "", true, StartTLSPostgres)

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "refused tls")
	})

	t.Run("given an unexpected greeting then it is reported", func(t *testing.T) {
		addr := startPlaintextServer(t, func(_ *testing.T, conn net.Conn) bool {
			io.WriteString(conn, "554 no service here\r\n")
			return false
		})

		location := LoadFromNetwork(addr, "", true, StartTLSSMTP)

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "smtp greeting")
	})

	t.Run("given the server rejects starttls then it is reported", func(t *testing.T) {
		addr := startPlaintextServer(t, func(_ *testing.T, conn net.Conn) bool {
			r := bufio.NewReader(conn)
			io.WriteString(conn, "220 test ESMTP\r\n")
			r.ReadString('\n')
			io.WriteString(conn, "250 test\r\n")
			r.ReadString('\n')
			io.WriteString(conn, "454 tls unavailable\r\n")
			return false
		})

		location := LoadFromNetwork(addr, "", true, StartTLSSMTP)

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "smtp starttls")
	})

	t.Run("given an ldap server returning a failure code then it is reported", func(t *testing.T) {
		addr := startPlaintextServer(t, func(_ *testing.T, conn net.Conn) bool {
			r := bufio.NewReader(conn)
			if _, err := readBERElement(r, 0x30); err != nil {
				return false
			}
			// resultCode 53, unwillingToPerform
			response := []byte{0x78, 0x07, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x00}
			body := append([]byte{0x02, 0x01, 0x01}, response...)
			conn.Write(append([]byte{0x30, byte(len(body))}, body...))
			return false
		})

		location := LoadFromNetwork(addr, "", true, StartTLSLDAP)

		require.Error(t, location.Error)
		assert.Contains(t, location.Error.Error(), "result code 53")
	})

	t.Run("given nothing listening then the dial error is returned", func(t *testing.T) {
		location := LoadFromNetwork("127.0.0.1:1", "", true, StartTLSSMTP)
		require.Error(t, location.Error)
	})
}

func TestParseStartTLSProtocol(t *testing.T) {

	for _, name := range StartTLSProtocols() {
		protocol, err := ParseStartTLSProtocol(name)
		require.NoError(t, err)
		assert.Equal(t, StartTLSProtocol(name), protocol)
	}

	t.Run("given empty then no protocol is selected", func(t *testing.T) {
		protocol, err := ParseStartTLSProtocol("")
		require.NoError(t, err)
		assert.Equal(t, StartTLSNone, protocol)
	})

	t.Run("given mixed case and padding then it is accepted", func(t *testing.T) {
		protocol, err := ParseStartTLSProtocol("  SMTP ")
		require.NoError(t, err)
		assert.Equal(t, StartTLSSMTP, protocol)
	})

	t.Run("given an unknown protocol then the error lists the supported ones", func(t *testing.T) {
		_, err := ParseStartTLSProtocol("telnet")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "smtp")
		assert.Contains(t, err.Error(), "postgres")
	})
}

func TestStartTLSDefaultPort(t *testing.T) {
	assert.Equal(t, "587", StartTLSSMTP.DefaultPort(), "submission, where a certificate is usually inspected")
	assert.Equal(t, "143", StartTLSIMAP.DefaultPort())
	assert.Equal(t, "5432", StartTLSPostgres.DefaultPort())
	assert.Empty(t, StartTLSNone.DefaultPort())
}

func Test_negotiateStartTLS_unsupported(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	err := negotiateStartTLS(client, StartTLSProtocol("telnet"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func Test_readBERElement(t *testing.T) {

	t.Run("given a long form length then it is read", func(t *testing.T) {
		contents := make([]byte, 300)
		message := append([]byte{0x30, 0x82, 0x01, 0x2c}, contents...)
		out, err := readBERElement(bufio.NewReader(strings.NewReader(string(message))), 0x30)
		require.NoError(t, err)
		assert.Len(t, out, 300)
	})

	t.Run("given the wrong tag then it is rejected", func(t *testing.T) {
		_, err := readBERElement(bufio.NewReader(strings.NewReader("\x31\x00")), 0x30)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected tag")
	})

	t.Run("given an implausible length then it is rejected", func(t *testing.T) {
		_, err := readBERElement(bufio.NewReader(strings.NewReader("\x30\x84\x7f\xff\xff\xff")), 0x30)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "implausible")
	})
}

func Test_ldapResultCode(t *testing.T) {

	t.Run("given a success response then zero is returned", func(t *testing.T) {
		body := []byte{0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
		code, err := ldapResultCode(body)
		require.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("given a truncated response then it is rejected", func(t *testing.T) {
		_, err := ldapResultCode([]byte{0x02, 0x01})
		require.Error(t, err)
	})

	t.Run("given the wrong inner tag then it is rejected", func(t *testing.T) {
		body := []byte{0x02, 0x01, 0x01, 0x65, 0x02, 0x0a, 0x00}
		_, err := ldapResultCode(body)
		require.Error(t, err)
	})
}
