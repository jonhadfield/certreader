package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extensionValue returns the raw value of one extension from a fixture.
func extensionValue(t *testing.T, file, oid string) []byte {
	t.Helper()

	for _, certificate := range loadTestCertificates(t, file) {
		for _, extension := range certificate.x509Certificate.Extensions {
			if extension.Id.String() == oid {
				return extension.Value
			}
		}
	}
	t.Fatalf("%s has no extension %s", file, oid)
	return nil
}

func TestToCertificatePoliciesQualifiers(t *testing.T) {

	// openssl reports "CPS: http://www.digicert.com/CPS" for this certificate,
	// which is the qualifier that used to be dropped
	policies, err := ToCertificatePolicies(extensionValue(t, "sct.pem", "2.5.29.32"))
	require.NoError(t, err)
	require.NotEmpty(t, policies)

	joined := strings.Join(policies, "\n")
	assert.Contains(t, joined, "CPS: http://www.digicert.com/CPS")
	assert.Contains(t, joined, "ev guidelines (2.23.140.1.1)")
}

func Test_toPolicyQualifiers(t *testing.T) {

	t.Run("given no qualifiers then there are none", func(t *testing.T) {
		assert.Empty(t, toPolicyQualifiers(asn1.RawValue{}))
	})

	t.Run("given a user notice then its text is rendered", func(t *testing.T) {
		notice, err := asn1.Marshal(struct {
			ExplicitText string `asn1:"utf8"`
		}{ExplicitText: "Use at your own risk"})
		require.NoError(t, err)

		qualifier, err := asn1.Marshal(struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}{
			ID:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2},
			Value: asn1.RawValue{FullBytes: notice},
		})
		require.NoError(t, err)

		out := toPolicyQualifiers(asn1.RawValue{Bytes: qualifier})
		require.Len(t, out, 1)
		assert.Contains(t, out[0], "User Notice")
		assert.Contains(t, out[0], "Use at your own risk")
	})

	t.Run("given an unknown qualifier then its identifier is shown", func(t *testing.T) {
		qualifier, err := asn1.Marshal(struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}{
			ID:    asn1.ObjectIdentifier{1, 2, 3, 4},
			Value: asn1.RawValue{FullBytes: []byte{0x05, 0x00}},
		})
		require.NoError(t, err)

		out := toPolicyQualifiers(asn1.RawValue{Bytes: qualifier})
		require.Len(t, out, 1)
		assert.Equal(t, "1.2.3.4", out[0])
	})

	t.Run("given rubbish then it is skipped rather than failing the extension", func(t *testing.T) {
		// the policy identifier is the part that matters, so a qualifier that
		// cannot be read should not lose it
		assert.Empty(t, toPolicyQualifiers(asn1.RawValue{Bytes: []byte{0xff, 0xff, 0xff}}))
	})
}

func Test_toIPAddress(t *testing.T) {

	tests := []struct {
		name     string
		in       []byte
		expected string
		ok       bool
	}{
		{"ipv4", net.ParseIP("1.1.1.1").To4(), "1.1.1.1", true},
		{"ipv6", net.ParseIP("2606:4700:4700::1111").To16(), "2606:4700:4700::1111", true},
		{"ipv4 with mask, as a name constraint carries", append(net.ParseIP("10.0.0.0").To4(), net.ParseIP("255.0.0.0").To4()...), "10.0.0.0/255.0.0.0", true},
		{"wrong length", []byte{1, 2, 3}, "", false},
		{"empty", nil, "", false},
	}
	for _, test := range tests {
		out, ok := toIPAddress(test.in)
		assert.Equal(t, test.ok, ok, test.name)
		assert.Equal(t, test.expected, out, test.name)
	}
}

func TestGeneralNameDecoding(t *testing.T) {

	t.Run("given an ip address then it is rendered as one rather than as bytes", func(t *testing.T) {
		// printing the octet string as text put raw binary on the terminal
		address := net.ParseIP("1.1.1.1").To4()
		name := toGeneralName(asn1.RawValue{Tag: generalNameIPAddress, Bytes: address})

		assert.Equal(t, "IP Address", name.Type)
		assert.Equal(t, "1.1.1.1", name.Value)
	})

	t.Run("given an unreadable ip address then the value is left alone", func(t *testing.T) {
		name := toGeneralName(asn1.RawValue{Tag: generalNameIPAddress, Bytes: []byte{1, 2, 3}})
		assert.Equal(t, "IP Address", name.Type)
	})

	t.Run("given a registered id then the oid is rendered", func(t *testing.T) {
		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99}
		encoded, err := asn1.MarshalWithParams(oid, "tag:8")
		require.NoError(t, err)

		name := toGeneralName(asn1.RawValue{Tag: generalNameRegisteredID, FullBytes: encoded, Bytes: encoded[2:]})

		assert.Equal(t, "Registered ID", name.Type)
		assert.Equal(t, "1.3.6.1.4.1.99", name.Value)
	})

	t.Run("given a directory name then the distinguished name is rendered", func(t *testing.T) {
		var sequence pkix.RDNSequence
		encoded, err := asn1.Marshal(pkix.Name{CommonName: "a name", Organization: []string{"an org"}}.ToRDNSequence())
		require.NoError(t, err)
		_, err = asn1.Unmarshal(encoded, &sequence)
		require.NoError(t, err)

		name := toGeneralName(asn1.RawValue{Tag: generalNameDirectoryName, Bytes: encoded})

		assert.Equal(t, "Directory Name", name.Type)
		assert.Contains(t, name.Value, "CN=a name")
		assert.Contains(t, name.Value, "O=an org")
	})

	t.Run("given a dns name then it is unchanged", func(t *testing.T) {
		name := toGeneralName(asn1.RawValue{Tag: 2, Bytes: []byte("example.com")})
		assert.Equal(t, "DNS Name", name.Type)
		assert.Equal(t, "example.com", name.Value)
	})

	t.Run("given a tag beyond the choice then nothing is returned", func(t *testing.T) {
		assert.Equal(t, GeneralName{}, toGeneralName(asn1.RawValue{Tag: 99}))
	})
}

func TestAuthorityInformationAccessGeneralNames(t *testing.T) {

	// the access location is a general name, and was already decoded as one;
	// this holds that
	accesses, err := ToAuthorityInformationAccess(extensionValue(t, "sct.pem", "1.3.6.1.5.5.7.1.1"))
	require.NoError(t, err)
	require.NotEmpty(t, accesses)

	for _, access := range accesses {
		assert.Contains(t, access.AccessLocation, "URI: http")
		assert.NotContains(t, access.AccessLocation, "\x00")
	}
}
