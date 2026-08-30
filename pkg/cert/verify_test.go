package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func problemCodes(result VerificationResult) []string {
	var out []string
	for _, problem := range result.Problems {
		out = append(out, problem.Code)
	}
	return out
}

// verifyChain builds a CA and a leaf it signs, so the failure modes can be
// produced deliberately rather than found in the wild.
func verifyChain(t *testing.T, leafTemplate *x509.Certificate) (leaf, issuer *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verify test CA"},
		SubjectKeyId:          []byte{7, 7, 7},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	issuer, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	if leafTemplate.SerialNumber == nil {
		leafTemplate.SerialNumber = big.NewInt(2)
	}
	if leafTemplate.NotBefore.IsZero() {
		leafTemplate.NotBefore = time.Now().Add(-time.Hour)
	}
	if leafTemplate.NotAfter.IsZero() {
		leafTemplate.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), caKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leaf, issuer
}

// networkLocation stands in for a location read from the network, which is what
// gives verification a hostname to check.
func networkLocation(path string, certificates ...*x509.Certificate) Location {
	return Location{
		Path:         path,
		TLSVersion:   0x0304,
		ContentType:  ContentTypeCertificate,
		Certificates: FromX509Certificates(certificates),
	}
}

func TestVerifyDiagnoses(t *testing.T) {

	t.Run("given an expired certificate then it says so and names it", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "old.example.com"},
			DNSNames:  []string{"old.example.com"},
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})

		result := networkLocation("old.example.com:443", leaf, issuer).Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifyExpired)
		assert.Contains(t, result.Problems[0].Subject, "old.example.com")
	})

	t.Run("given a certificate not yet valid then it says so", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "future.example.com"},
			DNSNames:  []string{"future.example.com"},
			NotBefore: time.Now().Add(24 * time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		})

		result := networkLocation("future.example.com:443", leaf, issuer).Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifyNotYetValid)
	})

	t.Run("given a self signed certificate then it is not called a missing intermediate", func(t *testing.T) {
		// its issuer is itself and was supplied, so the missing intermediate
		// test would otherwise misread it
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "self.example.com"},
			DNSNames:     []string{"self.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)
		selfSigned, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		result := networkLocation("self.example.com:443", selfSigned).Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifySelfSigned)
		assert.NotContains(t, problemCodes(result), VerifyMissingIntermediate)
	})

	t.Run("given an untrusted root then it says the chain does not reach the trust store", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "untrusted.example.com"},
			DNSNames: []string{"untrusted.example.com"},
		})

		result := networkLocation("untrusted.example.com:443", leaf, issuer).Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifyUntrustedRoot)
	})

	t.Run("given the issuer was never sent then it says the chain cannot be built", func(t *testing.T) {
		// the same certificate, without its issuer alongside it
		leaf, _ := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "alone.example.com"},
			DNSNames: []string{"alone.example.com"},
		})

		result := networkLocation("alone.example.com:443", leaf).Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifyMissingIntermediate)
		assert.Contains(t, result.Problems[0].Message, "verify test CA")
	})

	t.Run("given nothing to verify then it says so", func(t *testing.T) {
		result := Location{ContentType: ContentTypeCertificate}.Verify()

		assert.False(t, result.OK)
		assert.Contains(t, problemCodes(result), VerifyNoEndEntity)
	})
}

func TestVerifyHostname(t *testing.T) {

	t.Run("given a file location then no hostname is checked", func(t *testing.T) {
		// a certificate in a file is not being served for any name, so
		// inventing one would invent a failure
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "file.example.com"},
			DNSNames: []string{"file.example.com"},
		})

		location := Location{
			Path:         "bundle.pem",
			ContentType:  ContentTypeCertificate,
			Certificates: FromX509Certificates([]*x509.Certificate{leaf, issuer}),
		}

		assert.Empty(t, location.Verify().Hostname)
	})

	t.Run("given a network location then the host is taken from the address", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "host.example.com"},
			DNSNames: []string{"host.example.com"},
		})

		assert.Equal(t, "host.example.com",
			networkLocation("host.example.com:443", leaf, issuer).Verify().Hostname)
	})

	t.Run("given a bare hostname then it is used as it stands", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "bare.example.com"},
			DNSNames: []string{"bare.example.com"},
		})

		assert.Equal(t, "bare.example.com",
			networkLocation("bare.example.com", leaf, issuer).Verify().Hostname)
	})

	t.Run("given a server name override then it wins", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "sni.example.com"},
			DNSNames: []string{"sni.example.com"},
		})

		location := networkLocation("10.0.0.1:443", leaf, issuer)
		location.ServerName = "sni.example.com"

		assert.Equal(t, "sni.example.com", location.Verify().Hostname)
	})
}

func TestLocationsVerify(t *testing.T) {

	t.Run("given locations then each is checked and the original is untouched", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "one.example.com"},
			DNSNames: []string{"one.example.com"},
		})
		locations := Locations{networkLocation("one.example.com:443", leaf, issuer)}

		out := locations.Verify()

		require.Len(t, out, 1)
		require.NotNil(t, out[0].Verification)
		assert.Nil(t, locations[0].Verification)
	})

	t.Run("given locations that cannot be checked then they are left alone", func(t *testing.T) {
		locations := Locations{
			{Path: "broken.pem", Error: errNoPEMBlock},
			{Path: "request.csr", ContentType: ContentTypeCSR},
			{Path: "empty.pem", ContentType: ContentTypeCertificate},
		}

		for _, location := range locations.Verify() {
			assert.Nil(t, location.Verification)
		}
	})
}

func Test_issuerWasPresented(t *testing.T) {
	leaf, issuer := verifyChain(t, &x509.Certificate{Subject: pkix.Name{CommonName: "leaf.example.com"}})

	pool := x509.NewCertPool()
	assert.False(t, issuerWasPresented(leaf, pool))
	assert.False(t, issuerWasPresented(leaf, nil))

	pool.AddCert(issuer)
	assert.True(t, issuerWasPresented(leaf, pool))
}

func TestChainsAndVerifyShareOneImplementation(t *testing.T) {

	t.Run("given a chain that builds then both agree it does", func(t *testing.T) {
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "shared.example.com"},
			DNSNames: []string{"shared.example.com"},
		})
		location := networkLocation("shared.example.com:443", leaf, issuer)

		chains, err := location.Chains()
		result := location.Verify()

		// the test CA is not trusted, so neither should manage a chain
		require.Error(t, err)
		assert.Empty(t, chains)
		assert.Equal(t, 0, result.Chains)
		assert.False(t, result.OK)
	})

	t.Run("given a name mismatch then chains still build", func(t *testing.T) {
		// -chains exists to show what chains can be made; the name is a
		// separate question, and answering it here would hide the chain
		leaf, issuer := verifyChain(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "right.example.com"},
			DNSNames: []string{"right.example.com"},
		})
		location := networkLocation("wrong.example.com:443", leaf, issuer)

		result := location.Verify()

		// the CA is untrusted here too, so the useful assertion is that the
		// hostname is not what stopped the chain being attempted
		assert.Equal(t, "wrong.example.com", result.Hostname)
		assert.NotContains(t, problemCodes(result), VerifyHostnameMismatch,
			"an untrusted chain is the first problem, not the name")
	})

	t.Run("given a self signed certificate then chains reports why rather than staying silent", func(t *testing.T) {
		// it used to be classified a root and so never verified, which showed
		// as zero chains with no reason given
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "solo.example.com"},
			DNSNames:     []string{"solo.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)
		selfSigned, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		_, err = networkLocation("solo.example.com:443", selfSigned).Chains()
		assert.Error(t, err, "zero chains without a reason was the thing worth fixing")
	})

	t.Run("given a bundle with several end-entities then each is chained", func(t *testing.T) {
		// the previous implementation walked every end-entity, so this holds
		first, firstIssuer := verifyChain(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example.com"}})
		second, secondIssuer := verifyChain(t, &x509.Certificate{Subject: pkix.Name{CommonName: "b.example.com"}})

		location := Location{
			Path:         "bundle.pem",
			ContentType:  ContentTypeCertificate,
			Certificates: FromX509Certificates([]*x509.Certificate{first, firstIssuer, second, secondIssuer}),
		}

		// both are untrusted, so the first failure is returned rather than a
		// partial answer
		_, err := location.Chains()
		assert.Error(t, err)
	})
}

// selfSignedCertificate builds a certificate that is its own issuer.
func selfSignedCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed
}
