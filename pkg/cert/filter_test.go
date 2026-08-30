package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unparseable is a block that failed to parse, as fromPemBlock returns one.
func unparseable(position int) Certificate {
	return Certificate{position: position, err: errors.New("x509: malformed certificate")}
}

// emptyCertificate holds neither a certificate nor an error, the case
// Certificate.Error reports on rather than trusting the nil error.
func emptyCertificate(position int) Certificate {
	return Certificate{position: position}
}

func certificateExpiring(in time.Duration, issuer string) Certificate {
	subject := pkix.Name{CommonName: issuer + " leaf"}
	// SubjectString reads the raw subject rather than the parsed one, so a
	// hand-built certificate has to carry the encoding as a real one does.
	rawSubject, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		panic(err)
	}
	return Certificate{x509Certificate: &x509.Certificate{
		NotAfter:   time.Now().Add(in),
		Issuer:     pkix.Name{CommonName: issuer},
		Subject:    subject,
		RawSubject: rawSubject,
	}}
}

// certificateNamed builds a certificate whose subject and issuer are plainly
// different, so a filter matching the wrong one shows up.
func certificateNamed(t *testing.T, subjectCN, issuerCN string) Certificate {
	t.Helper()

	subject := pkix.Name{CommonName: subjectCN}
	rawSubject, err := asn1.Marshal(subject.ToRDNSequence())
	require.NoError(t, err)

	return Certificate{x509Certificate: &x509.Certificate{
		NotAfter:   time.Now().Add(24 * time.Hour),
		Subject:    subject,
		RawSubject: rawSubject,
		Issuer:     pkix.Name{CommonName: issuerCN},
	}}
}

func TestFiltersMatchTheFieldTheyAreNamedFor(t *testing.T) {
	// The help for these two flags described the other one's field for as long
	// as they existed. The filters themselves were right, and this is what
	// says so.
	certificates := Certificates{certificateNamed(t, "leaf.example.com", "Issuing CA")}

	t.Run("given a subject to match, when SubjectLike is called, then it matches on the subject alone", func(t *testing.T) {
		assert.Len(t, certificates.SubjectLike("leaf.example.com"), 1)
		assert.Empty(t, certificates.SubjectLike("Issuing CA"))
	})

	t.Run("given an issuer to match, when IssuerLike is called, then it matches on the issuer alone", func(t *testing.T) {
		assert.Len(t, certificates.IssuerLike("Issuing CA"), 1)
		assert.Empty(t, certificates.IssuerLike("leaf.example.com"))
	})
}

func TestFiltersTolerateUnparseableBlocks(t *testing.T) {
	// A bundle where one block failed to parse is read happily without a
	// filter, so every filter has to cope with one. Reaching for the issuer or
	// the expiry of a certificate that was never built panics.
	mixed := func() Certificates {
		return Certificates{
			certificateExpiring(48*time.Hour, "DigiCert"),
			unparseable(2),
			emptyCertificate(3),
		}
	}

	t.Run("given a block that did not parse, when IssuerLike is called, then it does not match and does not panic", func(t *testing.T) {
		filtered := mixed().IssuerLike("DigiCert")
		require.Len(t, filtered, 1)
		assert.Equal(t, "DigiCert", filtered[0].x509Certificate.Issuer.CommonName)
	})

	t.Run("given only blocks that did not parse, when IssuerLike is called, then nothing matches", func(t *testing.T) {
		assert.Empty(t, Certificates{unparseable(1), emptyCertificate(2)}.IssuerLike("DigiCert"))
	})

	t.Run("given a block that did not parse, when SortByExpiry is called, then it sorts last", func(t *testing.T) {
		certificates := Certificates{
			unparseable(1),
			certificateExpiring(72*time.Hour, "later"),
			emptyCertificate(2),
			certificateExpiring(24*time.Hour, "sooner"),
		}

		sorted := certificates.SortByExpiry()
		require.Len(t, sorted, 4)
		assert.Equal(t, "sooner", sorted[0].x509Certificate.Issuer.CommonName)
		assert.Equal(t, "later", sorted[1].x509Certificate.Issuer.CommonName)
		assert.Error(t, sorted[2].Error())
		assert.Error(t, sorted[3].Error())
	})

	t.Run("given blocks that did not parse, when SortByExpiry is called, then their order is kept", func(t *testing.T) {
		sorted := Certificates{unparseable(1), unparseable(2), unparseable(3)}.SortByExpiry()
		require.Len(t, sorted, 3)
		for i, position := range []int{1, 2, 3} {
			assert.Equal(t, position, sorted[i].position)
		}
	})

	t.Run("given a block that did not parse, when the other filters are called, then they do not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			mixed().RemoveExpired()
			mixed().RemoveDuplicates()
			mixed().SubjectLike("DigiCert")
		})
	})
}

func TestLocationFilters(t *testing.T) {
	location := func() Location {
		return Location{Path: "bundle.pem", Certificates: Certificates{
			certificateExpiring(72*time.Hour, "DigiCert"),
			certificateExpiring(24*time.Hour, "Other"),
			unparseable(3),
		}}
	}

	t.Run("given a location, when SubjectLike is called, then its certificates are filtered", func(t *testing.T) {
		filtered := location().SubjectLike("DigiCert")
		require.Len(t, filtered.Certificates, 1)
		assert.Equal(t, "bundle.pem", filtered.Path)
	})

	t.Run("given a location, when IssuerLike is called, then its certificates are filtered", func(t *testing.T) {
		filtered := location().IssuerLike("Other")
		require.Len(t, filtered.Certificates, 1)
		assert.Equal(t, "Other", filtered.Certificates[0].x509Certificate.Issuer.CommonName)
	})

	t.Run("given a location, when RemoveExpired is called, then unexpired certificates remain", func(t *testing.T) {
		filtered := location().RemoveExpired()
		assert.Len(t, filtered.Certificates, 3)
	})

	t.Run("given a location, when SortByExpiry is called, then the soonest expiry leads", func(t *testing.T) {
		sorted := location().SortByExpiry()
		require.Len(t, sorted.Certificates, 3)
		assert.Equal(t, "Other", sorted.Certificates[0].x509Certificate.Issuer.CommonName)
	})
}

func TestLocationsFilters(t *testing.T) {
	locations := func() Locations {
		return Locations{
			{Path: "later.pem", Certificates: Certificates{certificateExpiring(96*time.Hour, "DigiCert")}},
			{Path: "sooner.pem", Certificates: Certificates{certificateExpiring(24*time.Hour, "Other")}},
		}
	}

	t.Run("given locations, when SubjectLike is called, then every location is filtered", func(t *testing.T) {
		filtered := locations().SubjectLike("DigiCert")
		require.Len(t, filtered, 2)
		assert.Len(t, filtered[0].Certificates, 1)
		assert.Empty(t, filtered[1].Certificates)
	})

	t.Run("given locations, when IssuerLike is called, then every location is filtered", func(t *testing.T) {
		filtered := locations().IssuerLike("Other")
		require.Len(t, filtered, 2)
		assert.Empty(t, filtered[0].Certificates)
		assert.Len(t, filtered[1].Certificates, 1)
	})

	t.Run("given locations, when RemoveExpired is called, then every location is filtered", func(t *testing.T) {
		expired := Locations{{Path: "expired.pem", Certificates: Certificates{certificateExpiring(-24*time.Hour, "Old")}}}
		filtered := expired.RemoveExpired()
		require.Len(t, filtered, 1)
		assert.Empty(t, filtered[0].Certificates)
	})

	t.Run("given locations, when SortByExpiry is called, then the soonest to expire leads", func(t *testing.T) {
		sorted := locations().SortByExpiry()
		require.Len(t, sorted, 2)
		assert.Equal(t, "sooner.pem", sorted[0].Path)
		assert.Equal(t, "later.pem", sorted[1].Path)
	})

	t.Run("given a location holding nothing readable, when SortByExpiry is called, then it sorts last without panicking", func(t *testing.T) {
		mixed := Locations{
			{Path: "unreadable.pem", Certificates: Certificates{unparseable(1)}},
			{Path: "empty.pem"},
			{Path: "dated.pem", Certificates: Certificates{certificateExpiring(24*time.Hour, "DigiCert")}},
		}

		sorted := mixed.SortByExpiry()
		require.Len(t, sorted, 3)
		assert.Equal(t, "dated.pem", sorted[0].Path)
		assert.Equal(t, "unreadable.pem", sorted[1].Path)
		assert.Equal(t, "empty.pem", sorted[2].Path)
	})

	t.Run("given a location whose first certificate did not parse, when SortByExpiry is called, then a later expiry is still read", func(t *testing.T) {
		mixed := Locations{
			{Path: "later.pem", Certificates: Certificates{certificateExpiring(96*time.Hour, "DigiCert")}},
			{Path: "leading-error.pem", Certificates: Certificates{unparseable(1), certificateExpiring(24*time.Hour, "Other")}},
		}

		sorted := mixed.SortByExpiry()
		require.Len(t, sorted, 2)
		assert.Equal(t, "leading-error.pem", sorted[0].Path)
	})
}
