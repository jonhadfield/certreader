package cert

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_formatSerialNumber(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{
			// big.Int.Bytes returns nothing for zero, so this printed as an
			// empty field: the number naming the certificate simply absent.
			name:   "zero is a byte, not nothing",
			serial: big.NewInt(0),
			want:   "00",
		},
		{name: "one byte", serial: big.NewInt(1), want: "01"},
		{name: "several bytes", serial: big.NewInt(0x0100FF), want: "01:00:FF"},
		{name: "negative keeps its sign", serial: big.NewInt(-1), want: "-01"},
		{name: "nothing at all", serial: nil, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, formatSerialNumber(test.serial))
		})
	}
}

func TestCertificateWithZeroSerial(t *testing.T) {
	// Go Daddy's root, which openssl reports as serial=00. RFC 5280 wants a
	// positive serial; eight of the roots in a system trust store have this
	// one anyway, so the tool has to show what is there.
	certificates := loadTestCertificates(t, "zero_serial.pem")
	require.Len(t, certificates, 1)

	assert.Equal(t, "00", certificates[0].SerialNumber())
	assert.Contains(t, certificates[0].SubjectString(), "Go Daddy Root")
}
