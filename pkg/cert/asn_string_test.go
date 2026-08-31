package cert

import (
	"encoding/asn1"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bmpString(t *testing.T, text string) asn1.RawValue {
	t.Helper()

	var encoded []byte
	for _, character := range text {
		require.LessOrEqual(t, character, rune(0xFFFF), "outside the basic plane needs a surrogate pair")
		encoded = append(encoded, byte(character>>8), byte(character))
	}
	return asn1.RawValue{Tag: asn1.TagBMPString, Bytes: encoded}
}

func TestASN1String(t *testing.T) {
	t.Run("given a UTF8String, then its bytes are the text", func(t *testing.T) {
		value := asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("Autoridad de Certificación")}
		assert.Equal(t, "Autoridad de Certificación", asn1String(value))
	})

	t.Run("given a BMPString, then the UTF-16 is decoded", func(t *testing.T) {
		// Taken as it lies, this reads "\x00A\x00u\x00t..." — NUL bytes on the
		// terminal, and invalid UTF-8 wherever the text has an accent.
		assert.Equal(t, "Autoridad de Certificación Raíz", asn1String(bmpString(t, "Autoridad de Certificación Raíz")))
	})

	t.Run("given a BMPString outside the basic plane, then the surrogate pair is decoded", func(t *testing.T) {
		// U+1F512, a padlock, as the surrogate pair D83D DD12.
		value := asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0xD8, 0x3D, 0xDD, 0x12}}
		assert.Equal(t, "\U0001F512", asn1String(value))
	})

	t.Run("given a UniversalString, then the UTF-32 is decoded", func(t *testing.T) {
		value := asn1.RawValue{Tag: tagUniversalString, Bytes: []byte{
			0x00, 0x00, 0x00, 0x52, // R
			0x00, 0x00, 0x00, 0x61, // a
			0x00, 0x00, 0x00, 0xED, // í
			0x00, 0x00, 0x00, 0x7A, // z
		}}
		assert.Equal(t, "Raíz", asn1String(value))
	})

	t.Run("given bytes that do not divide evenly, then they are left as they are", func(t *testing.T) {
		// Not UTF-16, whatever the tag says, so there is nothing to decode.
		assert.Equal(t, "odd", asn1String(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte("odd")}))
		assert.Equal(t, "five!", asn1String(asn1.RawValue{Tag: tagUniversalString, Bytes: []byte("five!")}))
	})

	t.Run("given a code point that is not a character, then it is replaced rather than emitted", func(t *testing.T) {
		beyondUnicode := asn1.RawValue{Tag: tagUniversalString, Bytes: []byte{0x7F, 0xFF, 0xFF, 0xFF}}
		decoded := asn1String(beyondUnicode)
		assert.Equal(t, "�", decoded)
		assert.True(t, utf8.ValidString(decoded))
	})

	t.Run("given nothing, then nothing comes back", func(t *testing.T) {
		assert.Empty(t, asn1String(asn1.RawValue{Tag: asn1.TagBMPString}))
		assert.Empty(t, asn1String(asn1.RawValue{}))
	})
}

func TestUserNoticeWithBMPStringText(t *testing.T) {
	// ACCVRAIZ1, a Spanish root, carries its explicit text as a BMPString. It
	// used to print as UTF-16 bytes: NUL separated, and invalid UTF-8 at every
	// accent. openssl 3.6 prints an empty "Explicit Text:" for this one.
	policies, err := ToCertificatePolicies(extensionValue(t, "bmpstring_user_notice.pem", "2.5.29.32"))
	require.NoError(t, err)
	require.NotEmpty(t, policies)

	joined := strings.Join(policies, "\n")
	assert.Contains(t, joined, "Autoridad de Certificación Raíz de la ACCV")
	assert.NotContains(t, joined, "\x00")
	assert.True(t, utf8.ValidString(joined), "the text has to be printable")
}

func TestRelativeDistinguishedNameWithBMPStringValue(t *testing.T) {
	// The same reading applies to an attribute value in a name.
	name, err := ToRelativeDistinguishedName(relativeNameWithValue(t, bmpString(t, "Raíz")))
	require.NoError(t, err)
	require.Len(t, name, 1)
	assert.Equal(t, "2.5.4.3: Raíz", name[0])
}

// relativeNameWithValue encodes a RelativeDistinguishedName holding a single
// commonName attribute with the given value.
func relativeNameWithValue(t *testing.T, value asn1.RawValue) []byte {
	t.Helper()

	encodedValue, err := asn1.Marshal(value)
	require.NoError(t, err)

	commonName, err := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 4, 3})
	require.NoError(t, err)

	attribute, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(commonName, encodedValue...),
	})
	require.NoError(t, err)

	set, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attribute,
	})
	require.NoError(t, err)

	return set
}

func TestGeneralNamesKeepTheirOrder(t *testing.T) {
	// The types were collected in a map and printed by ranging it, so Go's
	// randomised order reached the output: two runs over the same certificate
	// printed the same names in a different order. That defeats diffing one run
	// against another, and golden output of any kind.
	raw := csrExtensionValue(t, "csr_san.pem", "2.5.29.17")

	first, err := ToGeneralNames(raw)
	require.NoError(t, err)
	require.Len(t, first, 2)

	// the certificate lists its DNS names before its IP address, and so does
	// openssl reading the same file
	assert.Contains(t, first[0], "DNS Name")
	assert.Contains(t, first[1], "IP Address")

	// a map with two keys lands in the same order roughly half the time by
	// chance, so once proves nothing
	for i := 0; i < 50; i++ {
		again, err := ToGeneralNames(raw)
		require.NoError(t, err)
		assert.Equal(t, first, again, "the same bytes have to give the same answer")
	}
}

// csrExtensionValue reads an extension out of a certificate request fixture.
// extensionValue reads certificates, and a request is not one.
func csrExtensionValue(t *testing.T, file, oid string) []byte {
	t.Helper()

	for _, csr := range loadTestCSRs(t, file) {
		for _, extension := range csr.x509CSR.Extensions {
			if extension.Id.String() == oid {
				return extension.Value
			}
		}
	}
	t.Fatalf("%s has no extension %s", file, oid)
	return nil
}
