package cert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestCSRs(t *testing.T, file string) CSRs {
	t.Helper()

	raw, err := os.ReadFile("testdata/" + file)
	require.NoError(t, err)

	csrs, err := FromCSRBytes(raw)
	require.NoError(t, err)
	return csrs
}

func TestCheckSelfSignature(t *testing.T) {
	t.Run("given a request signed by the key inside it, then the signature holds", func(t *testing.T) {
		csr := loadTestCSRs(t, "csr_san.pem")[0]

		assert.NoError(t, csr.CheckSelfSignature())
		assert.True(t, csr.SelfSignatureValid())
		assert.Empty(t, csr.Warnings())
	})

	t.Run("given a request with a bit flipped in its signature, then it does not", func(t *testing.T) {
		// The rest of the request still reads, which is the point: a subject
		// and a list of names are printed, and none of it is bound to the key
		// without this.
		csr := loadTestCSRs(t, "csr_bad_signature.pem")[0]
		require.Contains(t, csr.SubjectString(), "test.example.com")

		require.Error(t, csr.CheckSelfSignature())
		assert.False(t, csr.SelfSignatureValid())

		warnings := csr.Warnings()
		require.Len(t, warnings, 1)
		assert.Equal(t, WarningBadSelfSignature, warnings[0].Code)
		assert.Contains(t, warnings[0].Message, "does not verify")
	})

	t.Run("given a block that did not parse, then the parse error is what comes back", func(t *testing.T) {
		broken := CSR{position: 2, err: assert.AnError}

		require.Error(t, broken.CheckSelfSignature())
		assert.False(t, broken.SelfSignatureValid())
		// the parse failure is the thing to report, not a signature that was
		// never reached
		assert.Empty(t, broken.Warnings())
	})
}
