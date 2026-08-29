package cert

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sctExtension returns the raw SCT extension value from the fixture, which is a
// real certificate carrying three timestamps.
func sctExtension(t *testing.T) []byte {
	t.Helper()

	certificates := loadTestCertificates(t, "sct.pem")
	require.Len(t, certificates, 1)

	for _, extension := range certificates[0].x509Certificate.Extensions {
		if extension.Id.String() == "1.3.6.1.4.1.11129.2.4.2" {
			return extension.Value
		}
	}
	t.Fatal("fixture has no sct extension")
	return nil
}

func TestToSignedCertificateTimestamps(t *testing.T) {

	// values confirmed against openssl x509 -text on the same fixture
	scts, err := ToSignedCertificateTimestamps(sctExtension(t))
	require.NoError(t, err)
	require.Len(t, scts, 3)

	t.Run("given the first timestamp then it matches openssl", func(t *testing.T) {
		first := scts[0]

		assert.Equal(t, uint8(0), first.Version)
		assert.Equal(t, "v1 (0x0)", first.VersionName())
		assert.Equal(t,
			"c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd",
			hex.EncodeToString(first.LogID))
		assert.Equal(t, "Aug 10 06:13:28.444 2026 UTC",
			first.Timestamp.Format("Jan _2 15:04:05.000 2006 MST"))
		assert.Empty(t, first.Extensions)
		assert.Equal(t, "ECDSA-SHA256", first.SignatureAlgorithmName())
		assert.True(t, strings.HasPrefix(hex.EncodeToString(first.Signature), "3044022030d033288f49a6b2"))
	})

	t.Run("given every timestamp then each is well formed", func(t *testing.T) {
		for i, sct := range scts {
			assert.Len(t, sct.LogID, logIDLength, "sct %d", i)
			assert.False(t, sct.Timestamp.IsZero(), "sct %d", i)
			assert.NotEmpty(t, sct.Signature, "sct %d", i)
			assert.NotContains(t, sct.SignatureAlgorithmName(), "unknown", "sct %d", i)
		}
	})

	t.Run("given distinct logs then the ids differ", func(t *testing.T) {
		// the point of submitting to several logs
		seen := map[string]bool{}
		for _, sct := range scts {
			id := hex.EncodeToString(sct.LogID)
			assert.False(t, seen[id], "log id %s appears twice", id)
			seen[id] = true
		}
	})
}

func TestParseSignedCertificateTimestampListExtension(t *testing.T) {

	name, values, err := parseSignedCertificateTimestampList(sctExtension(t))
	require.NoError(t, err)
	assert.Equal(t, "CT Precertificate SCTs", name)

	joined := strings.Join(values, "\n")
	assert.Contains(t, joined, "Signed Certificate Timestamp:")
	assert.Contains(t, joined, "Version   : v1 (0x0)")
	assert.Contains(t, joined, "Log ID    : C2:31:7E:57")
	assert.Contains(t, joined, "Timestamp : Aug 10 06:13:28.444 2026 UTC")
	assert.Contains(t, joined, "Extensions: none")
	assert.Contains(t, joined, "Signature : ECDSA-SHA256")

	assert.Equal(t, 3, strings.Count(joined, "Signed Certificate Timestamp:"))
	assert.NotContains(t, joined, "...", "the placeholder must be gone")
}

func TestParseSCTMalformed(t *testing.T) {

	valid := sctExtension(t)

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"not asn1", []byte{0xff, 0xff, 0xff}},
		{"truncated mid list", valid[:len(valid)-10]},
		{"truncated to the octet string header", valid[:4]},
	}
	for _, test := range tests {
		t.Run(test.name+" is rejected", func(t *testing.T) {
			_, err := ToSignedCertificateTimestamps(test.in)
			assert.Error(t, err)
		})
	}

	t.Run("given a list length longer than the data then it is rejected", func(t *testing.T) {
		_, err := parseSCTList([]byte{0x01, 0x00, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sct list")
	})

	t.Run("given an empty list then it is rejected", func(t *testing.T) {
		_, err := parseSCTList([]byte{0x00, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("given trailing data after the list then it is rejected", func(t *testing.T) {
		_, err := parseSCTList([]byte{0x00, 0x00, 0xff})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing data")
	})

	t.Run("given an sct shorter than a log id then it is rejected", func(t *testing.T) {
		_, err := parseSCT([]byte{0x00, 0x01, 0x02})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "log id")
	})
}

func TestSCTSignatureAlgorithmName(t *testing.T) {
	tests := []struct {
		hash, signature uint8
		expected        string
	}{
		{4, 3, "ECDSA-SHA256"},
		{5, 3, "ECDSA-SHA384"},
		{4, 1, "SHA256-RSA"},
		{6, 1, "SHA512-RSA"},
		{2, 1, "SHA1-RSA"},
		{9, 9, "unknown (hash 9, signature 9)"},
		{4, 9, "unknown (hash 4, signature 9)"},
	}
	for _, test := range tests {
		sct := SignedCertificateTimestamp{HashAlgorithm: test.hash, SignatureAlgorithm: test.signature}
		assert.Equal(t, test.expected, sct.SignatureAlgorithmName())
	}

	assert.Equal(t, "unknown (0x3)", SignedCertificateTimestamp{Version: 3}.VersionName())
}

func Test_hexLines(t *testing.T) {

	in := []byte{1, 2, 3, 4, 5}

	t.Run("given a value longer than a line then it is split and continued", func(t *testing.T) {
		lines := hexLines(in, 2)
		require.Len(t, lines, 3)
		assert.Equal(t, "01:02:", lines[0], "a continued line keeps its separator")
		assert.Equal(t, "03:04:", lines[1])
		assert.Equal(t, "05", lines[2], "the last line does not")
	})

	t.Run("given a value that fits then it is one line", func(t *testing.T) {
		assert.Equal(t, []string{"01:02:03:04:05"}, hexLines(in, 16))
	})

	t.Run("given nothing then there are no lines", func(t *testing.T) {
		assert.Empty(t, hexLines(nil, 16))
	})
}

func Test_sctExtensions(t *testing.T) {
	assert.Equal(t, "none", sctExtensions(nil))
	assert.Equal(t, "none", sctExtensions([]byte{}))
	assert.Equal(t, "AA:BB", sctExtensions([]byte{0xaa, 0xbb}))
}

func Test_tlsReader(t *testing.T) {

	r := &tlsReader{data: []byte{0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 3, 0x00, 0x01, 0xff}}

	v8, err := r.uint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(1), v8)

	v16, err := r.uint16()
	require.NoError(t, err)
	assert.Equal(t, uint16(2), v16)

	v64, err := r.uint64()
	require.NoError(t, err)
	assert.Equal(t, uint64(3), v64)

	vector, err := r.vector16()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff}, vector)

	assert.Zero(t, r.remaining())

	_, err = r.uint8()
	require.Error(t, err, "reading past the end must fail rather than panic")

	t.Run("given a vector longer than the data then it fails", func(t *testing.T) {
		short := &tlsReader{data: []byte{0x00, 0x10, 0x01}}
		_, err := short.vector16()
		assert.Error(t, err)
	})
}

func TestSCTTimestampIsRealTime(t *testing.T) {
	// a millisecond epoch misread as seconds would land tens of thousands of
	// years out, so this catches the classic mistake
	scts, err := ToSignedCertificateTimestamps(sctExtension(t))
	require.NoError(t, err)

	for _, sct := range scts {
		assert.True(t, sct.Timestamp.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)))
		assert.True(t, sct.Timestamp.Before(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)))
	}
}
