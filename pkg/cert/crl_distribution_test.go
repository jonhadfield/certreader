package cert

import (
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two forms a distribution point name can take. Real certificates use
// fullName almost exclusively, which is why the other went unexercised.
//
//	DistributionPointName ::= CHOICE {
//	    fullName                [0] GeneralNames,
//	    nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
var (
	// [0] { [0] { [6] "http://crl.example.com/a.crl" } }
	fullNamePoint = func() []byte {
		uri := append([]byte{0x86, 0x1c}, []byte("http://crl.example.com/a.crl")...)
		fullName := append([]byte{0xa0, byte(len(uri))}, uri...)
		distributionPoint := append([]byte{0xa0, byte(len(fullName))}, fullName...)
		point := append([]byte{0x30, byte(len(distributionPoint))}, distributionPoint...)
		return append([]byte{0x30, byte(len(point))}, point...)
	}()

	// [0] { [1] SET OF { SEQUENCE { OID 2.5.4.3, "crl1" } } }
	relativeNamePoint = []byte{
		0x30, 0x13, // CRLDistributionPoints
		0x30, 0x11, // DistributionPoint
		0xa0, 0x0f, // distributionPoint [0]
		0xa1, 0x0d, // nameRelativeToCRLIssuer [1]
		0x30, 0x0b, // AttributeTypeAndValue
		0x06, 0x03, 0x55, 0x04, 0x03, // 2.5.4.3, common name
		0x13, 0x04, 'c', 'r', 'l', '1',
	}
)

func TestToCRLDistributionPoints(t *testing.T) {

	t.Run("given a full name then the url is read", func(t *testing.T) {
		points, err := ToCRLDistributionPoints(fullNamePoint)
		require.NoError(t, err)
		require.Len(t, points, 1)

		assert.Equal(t, []string{"URI: http://crl.example.com/a.crl"}, points[0].DistributionPoint)
	})

	t.Run("given a name relative to the crl issuer then it is read", func(t *testing.T) {
		// this used to come back as ": ", because the choice was decided on the
		// tag of the field wrapping it rather than the tag of the name itself,
		// so it always took the full name branch and parsed a set as if it
		// were a list of general names
		points, err := ToCRLDistributionPoints(relativeNamePoint)
		require.NoError(t, err)
		require.Len(t, points, 1)

		require.Len(t, points[0].DistributionPoint, 1)
		assert.Contains(t, points[0].DistributionPoint[0], "crl1")
		assert.NotEqual(t, ": ", points[0].DistributionPoint[0])
	})

	t.Run("given the extension from a real certificate then it is read", func(t *testing.T) {
		points, err := ToCRLDistributionPoints(extensionValue(t, "sct.pem", "2.5.29.31"))
		require.NoError(t, err)
		require.NotEmpty(t, points)

		joined := strings.Join(points[0].DistributionPoint, " ")
		assert.Contains(t, joined, "URI: http")
	})

	t.Run("given a reason then it is named", func(t *testing.T) {
		// DistributionPoint { [0] fullName, [1] reasons }
		uri := append([]byte{0x86, 0x0b}, []byte("http://a/b/c")[:11]...)
		fullName := append([]byte{0xa0, byte(len(uri))}, uri...)
		distributionPoint := append([]byte{0xa0, byte(len(fullName))}, fullName...)
		// reasons [1] BIT STRING, keyCompromise is bit 1
		reasons := []byte{0x81, 0x02, 0x06, 0x40}
		body := append(distributionPoint, reasons...)
		point := append([]byte{0x30, byte(len(body))}, body...)
		encoded := append([]byte{0x30, byte(len(point))}, point...)

		points, err := ToCRLDistributionPoints(encoded)
		require.NoError(t, err)
		require.Len(t, points, 1)

		assert.Contains(t, points[0].Reasons, "keyCompromise")
	})

	t.Run("given an unsupported name tag then it is refused rather than guessed at", func(t *testing.T) {
		// [0] { [3] ... }, which is not a choice the standard defines
		unknown := []byte{
			0x30, 0x09, 0x30, 0x07, 0xa0, 0x05, 0x83, 0x03, 'a', 'b', 'c',
		}
		_, err := ToCRLDistributionPoints(unknown)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported distribution point name tag")
	})

	t.Run("given rubbish then it is refused", func(t *testing.T) {
		_, err := ToCRLDistributionPoints([]byte{0xff, 0xff})
		assert.Error(t, err)
	})
}

func TestToRelativeDistinguishedName(t *testing.T) {

	t.Run("given a set of attributes then each is rendered", func(t *testing.T) {
		// SET OF { CN=crl1, O=example }
		commonName := []byte{0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 'c', 'r', 'l', '1'}
		organisation := []byte{0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}
		body := append(commonName, organisation...)
		encoded := append([]byte{0x31, byte(len(body))}, body...)

		out, err := ToRelativeDistinguishedName(encoded)
		require.NoError(t, err)
		require.Len(t, out, 2)

		assert.Equal(t, "2.5.4.3: crl1", out[0])
		assert.Equal(t, "2.5.4.10: example", out[1])
	})

	t.Run("given rubbish then it is refused", func(t *testing.T) {
		_, err := ToRelativeDistinguishedName([]byte{0xff, 0xff})
		assert.Error(t, err)
	})

	t.Run("given a truncated attribute then it is refused", func(t *testing.T) {
		_, err := ToRelativeDistinguishedName([]byte{0x31, 0x02, 0x30, 0x0b})
		assert.Error(t, err)
	})
}

func Test_toReasonFlag(t *testing.T) {

	t.Run("given no bits then there are no reasons", func(t *testing.T) {
		assert.Empty(t, toReasonFlag(asn1.BitString{}))
	})

	t.Run("given a bit then its reason is named", func(t *testing.T) {
		// bit 1 is keyCompromise
		out := toReasonFlag(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2})
		assert.Equal(t, []string{"keyCompromise"}, out)
	})

	t.Run("given several bits then each is named in order", func(t *testing.T) {
		// bits 1 and 4, keyCompromise and superseded
		out := toReasonFlag(asn1.BitString{Bytes: []byte{0x48}, BitLength: 5})
		assert.Equal(t, []string{"keyCompromise", "superseded"}, out)
	})
}
