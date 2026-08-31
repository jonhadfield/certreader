package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The expected values are what openssl prints for the same files:
//
//	openssl x509 -in cert.pem -noout -fingerprint -sha256
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
//
// A fingerprint nobody else agrees with is worse than none, since the whole
// use of one is comparing it against a value from somewhere else.
func TestFingerprints(t *testing.T) {
	tests := []struct {
		file        string
		certificate string
		publicKey   string
	}{
		{
			file:        "cert.pem",
			certificate: "CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F",
			publicKey:   "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
		},
		{
			file:        "sct.pem",
			certificate: "73:10:E1:6F:8F:F7:12:79:89:20:B3:0F:F9:5F:0D:46:F4:EC:07:1E:40:25:37:59:04:D9:8E:BB:5D:D5:D2:82",
			publicKey:   "Jl+etsAilOKaO8/Xp2l6GFVlJ3yJh0/vSvkaM0Z0OG0=",
		},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			certificates := loadTestCertificates(t, test.file)
			require.NotEmpty(t, certificates)

			assert.Equal(t, test.certificate, certificates[0].Fingerprint())
			assert.Equal(t, test.publicKey, certificates[0].PublicKeyFingerprint())
		})
	}
}

func TestFingerprintsNameDifferentThings(t *testing.T) {
	first := loadTestCertificates(t, "cert.pem")[0]
	second := loadTestCertificates(t, "sct.pem")[0]

	t.Run("given different certificates, then both fingerprints differ", func(t *testing.T) {
		assert.NotEqual(t, first.Fingerprint(), second.Fingerprint())
		assert.NotEqual(t, first.PublicKeyFingerprint(), second.PublicKeyFingerprint())
	})

	t.Run("given the same certificate read twice, then both are the same", func(t *testing.T) {
		again := loadTestCertificates(t, "cert.pem")[0]
		assert.Equal(t, first.Fingerprint(), again.Fingerprint())
		assert.Equal(t, first.PublicKeyFingerprint(), again.PublicKeyFingerprint())
	})

	t.Run("given a block that did not parse, then there is nothing to fingerprint", func(t *testing.T) {
		// as with every other accessor, the guard is Error rather than a panic
		assert.Empty(t, unparseable(1).Fingerprint())
		assert.Empty(t, unparseable(1).PublicKeyFingerprint())
		assert.Empty(t, emptyCertificate(2).Fingerprint())
		assert.Empty(t, emptyCertificate(2).PublicKeyFingerprint())
	})
}
