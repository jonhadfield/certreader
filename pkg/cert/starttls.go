package cert

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// StartTLSProtocol names a protocol that begins in plaintext and upgrades to
// TLS on request, rather than handshaking immediately.
type StartTLSProtocol string

const (
	// StartTLSNone connects with TLS directly, as https does.
	StartTLSNone     StartTLSProtocol = ""
	StartTLSSMTP     StartTLSProtocol = "smtp"
	StartTLSIMAP     StartTLSProtocol = "imap"
	StartTLSPOP3     StartTLSProtocol = "pop3"
	StartTLSFTP      StartTLSProtocol = "ftp"
	StartTLSNNTP     StartTLSProtocol = "nntp"
	StartTLSLDAP     StartTLSProtocol = "ldap"
	StartTLSPostgres StartTLSProtocol = "postgres"
)

// startTLSPorts is the port assumed when a bare hostname is given. For smtp
// that is the submission port rather than 25, since that is where a certificate
// is usually being inspected.
var startTLSPorts = map[StartTLSProtocol]string{
	StartTLSSMTP:     "587",
	StartTLSIMAP:     "143",
	StartTLSPOP3:     "110",
	StartTLSFTP:      "21",
	StartTLSNNTP:     "119",
	StartTLSLDAP:     "389",
	StartTLSPostgres: "5432",
}

// StartTLSProtocols lists the supported protocols in a stable order, for help
// text and validation.
func StartTLSProtocols() []string {
	return []string{
		string(StartTLSSMTP), string(StartTLSIMAP), string(StartTLSPOP3),
		string(StartTLSFTP), string(StartTLSNNTP), string(StartTLSLDAP),
		string(StartTLSPostgres),
	}
}

// ParseStartTLSProtocol validates a protocol name.
func ParseStartTLSProtocol(in string) (StartTLSProtocol, error) {

	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		return StartTLSNone, nil
	}
	for _, known := range StartTLSProtocols() {
		if in == known {
			return StartTLSProtocol(in), nil
		}
	}
	return StartTLSNone, fmt.Errorf("unsupported protocol %q, expected one of %s", in, strings.Join(StartTLSProtocols(), ", "))
}

// DefaultPort is the port to assume for a bare hostname, empty when the
// protocol has none.
func (p StartTLSProtocol) DefaultPort() string {
	return startTLSPorts[p]
}

// negotiateStartTLS performs the plaintext exchange that asks the server to
// begin TLS. On return the connection is ready to be handed to tls.Client.
func negotiateStartTLS(conn net.Conn, protocol StartTLSProtocol) error {

	switch protocol {
	case StartTLSSMTP:
		return negotiateSMTP(conn)
	case StartTLSIMAP:
		return negotiateIMAP(conn)
	case StartTLSPOP3:
		return negotiatePOP3(conn)
	case StartTLSFTP:
		return negotiateFTP(conn)
	case StartTLSNNTP:
		return negotiateNNTP(conn)
	case StartTLSLDAP:
		return negotiateLDAP(conn)
	case StartTLSPostgres:
		return negotiatePostgres(conn)
	default:
		return fmt.Errorf("unsupported starttls protocol %q", protocol)
	}
}

// readReplyLine reads one CRLF terminated line.
func readReplyLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readCodeReply reads a reply that may span several lines. SMTP, FTP and NNTP
// share the convention that a continued line has a hyphen in the fourth column.
func readCodeReply(r *bufio.Reader) (string, error) {

	for {
		line, err := readReplyLine(r)
		if err != nil {
			return "", err
		}
		if len(line) < 4 || line[3] != '-' {
			return line, nil
		}
	}
}

// expectCode reads a reply and checks it begins with one of the given codes.
func expectCode(r *bufio.Reader, step string, codes ...string) error {

	line, err := readCodeReply(r)
	if err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	for _, code := range codes {
		if strings.HasPrefix(line, code) {
			return nil
		}
	}
	return fmt.Errorf("%s: unexpected response %q", step, line)
}

func negotiateSMTP(conn net.Conn) error {

	r := bufio.NewReader(conn)
	if err := expectCode(r, "smtp greeting", "220"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "EHLO certreader\r\n"); err != nil {
		return err
	}
	if err := expectCode(r, "smtp ehlo", "250"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	return expectCode(r, "smtp starttls", "220")
}

func negotiateFTP(conn net.Conn) error {

	r := bufio.NewReader(conn)
	if err := expectCode(r, "ftp greeting", "220"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}
	return expectCode(r, "ftp auth tls", "234")
}

func negotiateNNTP(conn net.Conn) error {

	r := bufio.NewReader(conn)
	if err := expectCode(r, "nntp greeting", "200", "201"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	return expectCode(r, "nntp starttls", "382")
}

func negotiateIMAP(conn net.Conn) error {

	r := bufio.NewReader(conn)
	greeting, err := readReplyLine(r)
	if err != nil {
		return fmt.Errorf("imap greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("imap greeting: unexpected response %q", greeting)
	}

	const tag = "a001"
	if _, err := io.WriteString(conn, tag+" STARTTLS\r\n"); err != nil {
		return err
	}
	for {
		line, err := readReplyLine(r)
		if err != nil {
			return fmt.Errorf("imap starttls: %w", err)
		}
		// untagged lines may precede the tagged completion
		if !strings.HasPrefix(line, tag+" ") {
			continue
		}
		if strings.HasPrefix(line, tag+" OK") {
			return nil
		}
		return fmt.Errorf("imap starttls: unexpected response %q", line)
	}
}

func negotiatePOP3(conn net.Conn) error {

	r := bufio.NewReader(conn)
	greeting, err := readReplyLine(r)
	if err != nil {
		return fmt.Errorf("pop3 greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("pop3 greeting: unexpected response %q", greeting)
	}

	if _, err := io.WriteString(conn, "STLS\r\n"); err != nil {
		return err
	}
	line, err := readReplyLine(r)
	if err != nil {
		return fmt.Errorf("pop3 stls: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("pop3 stls: unexpected response %q", line)
	}
	return nil
}

// negotiatePostgres sends the SSLRequest packet, which is a fixed eight bytes:
// a length followed by the magic version number reserved for it.
func negotiatePostgres(conn net.Conn) error {

	const sslRequestCode = 80877103

	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request[0:4], 8)
	binary.BigEndian.PutUint32(request[4:8], sslRequestCode)
	if _, err := conn.Write(request); err != nil {
		return err
	}

	reply := make([]byte, 1)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("postgres sslrequest: %w", err)
	}
	switch reply[0] {
	case 'S':
		return nil
	case 'N':
		return fmt.Errorf("postgres sslrequest: server refused tls")
	default:
		return fmt.Errorf("postgres sslrequest: unexpected response %q", reply[0])
	}
}

// ldapStartTLSOID is the extended request that asks an LDAP server to begin TLS.
const ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"

// negotiateLDAP sends a StartTLS extended request and checks the result code.
// The message is short enough to build by hand rather than pull in a library.
func negotiateLDAP(conn net.Conn) error {

	oid := []byte(ldapStartTLSOID)

	// ExtendedRequest ::= [APPLICATION 23] SEQUENCE { requestName [0] LDAPOID }
	request := []byte{0x80, byte(len(oid))}
	request = append(request, oid...)
	extended := append([]byte{0x77, byte(len(request))}, request...)

	// LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp }
	body := append([]byte{0x02, 0x01, 0x01}, extended...)
	message := append([]byte{0x30, byte(len(body))}, body...)

	if _, err := conn.Write(message); err != nil {
		return err
	}

	r := bufio.NewReader(conn)
	response, err := readBERElement(r, 0x30)
	if err != nil {
		return fmt.Errorf("ldap starttls: %w", err)
	}

	code, err := ldapResultCode(response)
	if err != nil {
		return fmt.Errorf("ldap starttls: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("ldap starttls: server returned result code %d", code)
	}
	return nil
}

// readBERElement reads one BER element with the expected tag and returns its
// contents.
func readBERElement(r *bufio.Reader, wantTag byte) ([]byte, error) {

	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != wantTag {
		return nil, fmt.Errorf("expected tag 0x%02x, got 0x%02x", wantTag, tag)
	}

	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	length := int(first)
	if first&0x80 != 0 {
		count := int(first & 0x7f)
		if count == 0 || count > 4 {
			return nil, fmt.Errorf("unsupported length encoding")
		}
		length = 0
		for i := 0; i < count; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > 1<<20 {
		return nil, fmt.Errorf("implausible message length %d", length)
	}

	contents := make([]byte, length)
	if _, err := io.ReadFull(r, contents); err != nil {
		return nil, err
	}
	return contents, nil
}

// ldapResultCode digs the result code out of an LDAPMessage body: a messageID
// integer, then an ExtendedResponse whose first field is the enumerated code.
func ldapResultCode(body []byte) (int, error) {

	rest, err := skipBERElement(body, 0x02) // messageID
	if err != nil {
		return 0, err
	}

	response, err := berContents(rest, 0x78) // ExtendedResponse
	if err != nil {
		return 0, err
	}

	code, err := berContents(response, 0x0a) // resultCode, ENUMERATED
	if err != nil {
		return 0, err
	}
	if len(code) != 1 {
		return 0, fmt.Errorf("unexpected result code length %d", len(code))
	}
	return int(code[0]), nil
}

// berHeader returns the contents length and the offset contents start at.
func berHeader(in []byte, wantTag byte) (length, offset int, err error) {

	if len(in) < 2 {
		return 0, 0, fmt.Errorf("truncated element")
	}
	if in[0] != wantTag {
		return 0, 0, fmt.Errorf("expected tag 0x%02x, got 0x%02x", wantTag, in[0])
	}

	first := in[1]
	offset = 2
	length = int(first)
	if first&0x80 != 0 {
		count := int(first & 0x7f)
		if count == 0 || count > 4 || len(in) < 2+count {
			return 0, 0, fmt.Errorf("unsupported length encoding")
		}
		length = 0
		for i := 0; i < count; i++ {
			length = length<<8 | int(in[2+i])
		}
		offset = 2 + count
	}
	if length < 0 || offset+length > len(in) {
		return 0, 0, fmt.Errorf("element runs past the end of the message")
	}
	return length, offset, nil
}

func berContents(in []byte, wantTag byte) ([]byte, error) {
	length, offset, err := berHeader(in, wantTag)
	if err != nil {
		return nil, err
	}
	return in[offset : offset+length], nil
}

func skipBERElement(in []byte, wantTag byte) ([]byte, error) {
	length, offset, err := berHeader(in, wantTag)
	if err != nil {
		return nil, err
	}
	return in[offset+length:], nil
}
