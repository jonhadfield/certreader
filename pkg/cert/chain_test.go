package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chainWarningCodes(warnings []Warning) []string {
	var out []string
	for _, warning := range warnings {
		out = append(out, warning.Code)
	}
	return out
}

// servedChain stands in for what a server sent, in the order it sent it.
func servedChain(certificates ...*x509.Certificate) Location {
	return Location{
		Path:         "example.com:443",
		TLSVersion:   0x0304,
		ContentType:  ContentTypeCertificate,
		Certificates: FromX509Certificates(certificates),
	}
}

func TestChainWarnings(t *testing.T) {

	t.Run("given a well formed chain then there is nothing to report", func(t *testing.T) {
		// leaf and intermediate, with the root withheld, which is what a
		// correctly configured server sends
		leaf, intermediate, _ := threeTierChain(t, "good.example.com")

		assert.Empty(t, servedChain(leaf, intermediate).ChainWarnings())
	})

	t.Run("given the root is sent then it is reported as unusable", func(t *testing.T) {
		// a client can only trust a root it already has, so sending one adds
		// bytes to every handshake and changes nothing
		leaf, intermediate, root := threeTierChain(t, "root.example.com")

		warnings := servedChain(leaf, intermediate, root).ChainWarnings()

		codes := chainWarningCodes(warnings)
		assert.Contains(t, codes, ChainWarningRootIncluded)
		assert.NotContains(t, codes, ChainWarningOutOfOrder, "the order is right, only the root is spare")
	})

	t.Run("given a certificate sent twice then it is reported", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "dup.example.com"},
			DNSNames: []string{"dup.example.com"},
		})

		warnings := servedChain(leaf, issuer, issuer).ChainWarnings()

		assert.Contains(t, chainWarningCodes(warnings), ChainWarningDuplicate)
		assert.Contains(t, strings.Join(messages(warnings), " "), "verify test CA")
	})

	t.Run("given the chain is out of order then it is reported", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "order.example.com"},
			DNSNames: []string{"order.example.com"},
		})
		unrelated, _ := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "stranger.example.com"},
			DNSNames: []string{"stranger.example.com"},
		})

		// a certificate that does not issue the one before it
		warnings := servedChain(leaf, unrelated, issuer).ChainWarnings()

		assert.Contains(t, chainWarningCodes(warnings), ChainWarningOutOfOrder)
	})

	t.Run("given an authority is sent first then it is reported", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "swapped.example.com"},
			DNSNames: []string{"swapped.example.com"},
		})

		warnings := servedChain(issuer, leaf).ChainWarnings()

		assert.Contains(t, chainWarningCodes(warnings), ChainWarningNoLeafFirst)
	})
}

func TestChainWarningsAvoidFalsePositives(t *testing.T) {

	t.Run("given a file then nothing is reported", func(t *testing.T) {
		// a bundle is expected to hold roots and to be in any order, so the
		// same checks there would report the file's purpose as a fault
		certificates := loadTestCertificates(t, "bundle.pem")
		location := Location{
			Path:         "bundle.pem",
			ContentType:  ContentTypeCertificate,
			Certificates: certificates,
		}

		assert.Empty(t, location.ChainWarnings(), "a bundle of roots is not a misconfigured server")
	})

	t.Run("given a self signed leaf then it is not called a served root", func(t *testing.T) {
		// verification reports it as self-signed; it is not a root sent
		// alongside a chain
		leaf := selfSignedCertificate(t, "solo.example.com")

		warnings := servedChain(leaf).ChainWarnings()

		assert.NotContains(t, chainWarningCodes(warnings), ChainWarningRootIncluded)
	})

	t.Run("given a certificate that failed to parse then it is skipped", func(t *testing.T) {
		location := Location{
			Path:         "example.com:443",
			TLSVersion:   0x0304,
			ContentType:  ContentTypeCertificate,
			Certificates: Certificates{{}},
		}

		assert.NotPanics(t, func() { assert.Empty(t, location.ChainWarnings()) })
	})

	t.Run("given nothing was served then nothing is reported", func(t *testing.T) {
		assert.Empty(t, servedChain().ChainWarnings())
	})
}

func TestVerifyCarriesChainWarnings(t *testing.T) {
	// they travel with the verification result, but must not change its verdict
	leaf, issuer := verifyChain(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "carried.example.com"},
		DNSNames: []string{"carried.example.com"},
	})

	result := servedChain(leaf, issuer, issuer).Verify()

	assert.NotEmpty(t, result.ChainWarnings)
	require.NotEmpty(t, result.Problems, "the test CA is untrusted, so it fails for that reason")
	assert.NotContains(t, problemCodes(result), ChainWarningRootIncluded,
		"a chain warning is not a verification problem")
}

func messages(warnings []Warning) []string {
	var out []string
	for _, warning := range warnings {
		out = append(out, warning.Message)
	}
	return out
}

// threeTierChain builds root -> intermediate -> leaf, which is the shape a real
// chain has and the only way to tell a served root from a served intermediate.
func threeTierChain(t *testing.T, commonName string) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chain test root"},
		SubjectKeyId:          []byte{1, 1, 1},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "chain test intermediate"},
		SubjectKeyId:          []byte{2, 2, 2},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
	require.NoError(t, err)
	intermediate, err = x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leaf, intermediate, root
}
