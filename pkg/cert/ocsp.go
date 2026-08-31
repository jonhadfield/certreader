package cert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrNoOCSPStaple is returned when a TLS server did not staple an OCSP response
// to the handshake, or when the source is not a network location at all.
var ErrNoOCSPStaple = errors.New("no OCSP response stapled to the handshake")

// StapledOCSP is the certificate status a TLS server volunteered during the
// handshake (RFC 6066 certificate status request, commonly "OCSP stapling").
// It is obtained without contacting the CA's responder.
type StapledOCSP struct {
	// Status is the responder verdict: "good", "revoked" or "unknown".
	Status string
	// SerialNumber is the serial the response covers, in the same colon
	// separated hex form used for certificates.
	SerialNumber string
	// RevokedAt and RevocationReason are only set when Status is "revoked".
	RevokedAt        time.Time
	RevocationReason string
	// ProducedAt is when the responder signed the response.
	ProducedAt time.Time
	// ThisUpdate and NextUpdate bound the validity of the status. NextUpdate
	// is zero when the responder omitted it.
	ThisUpdate time.Time
	NextUpdate time.Time
	// SignatureVerified reports whether the response signature was checked
	// against the issuing CA. It is false when the issuer certificate was not
	// available, in which case the status is unauthenticated.
	SignatureVerified bool
}

// IsRevoked reports whether the responder declared the certificate revoked.
func (s *StapledOCSP) IsRevoked() bool {
	return s != nil && s.Status == ocspStatusRevoked
}

// IsStale reports whether the response is past its NextUpdate and should no
// longer be relied upon. Responses without a NextUpdate are never stale.
func (s *StapledOCSP) IsStale() bool {
	if s == nil || s.NextUpdate.IsZero() {
		return false
	}
	return time.Now().After(s.NextUpdate)
}

const (
	ocspStatusGood    = "good"
	ocspStatusRevoked = "revoked"
	ocspStatusUnknown = "unknown"
)

// ParseStapledOCSP decodes a stapled OCSP response. When leaf is supplied the
// response must cover that certificate's serial; when issuer is supplied the
// response signature is verified against it.
func ParseStapledOCSP(raw []byte, leaf, issuer *x509.Certificate) (*StapledOCSP, error) {

	if len(raw) == 0 {
		return nil, ErrNoOCSPStaple
	}
	return parseOCSPResponse(raw, leaf, issuer)
}

// parseOCSPResponse decodes an OCSP response, whether it arrived stapled to a
// handshake or as the reply from a responder.
func parseOCSPResponse(raw []byte, leaf, issuer *x509.Certificate) (*StapledOCSP, error) {

	response, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP response: %w", err)
	}

	out := &StapledOCSP{
		Status:            ocspStatus(response.Status),
		ProducedAt:        response.ProducedAt,
		ThisUpdate:        response.ThisUpdate,
		NextUpdate:        response.NextUpdate,
		SignatureVerified: issuer != nil,
	}
	if response.SerialNumber != nil {
		out.SerialNumber = formatSerialNumber(response.SerialNumber)
	}
	if response.Status == ocsp.Revoked {
		out.RevokedAt = response.RevokedAt
		out.RevocationReason = revocationReasonName(response.RevocationReason)
	}
	return out, nil
}

func ocspStatus(in int) string {
	switch in {
	case ocsp.Good:
		return ocspStatusGood
	case ocsp.Revoked:
		return ocspStatusRevoked
	case ocsp.Unknown:
		return ocspStatusUnknown
	default:
		return fmt.Sprintf("unrecognised (%d)", in)
	}
}

// revocationReasonName renders an X.509 CRLReason code, which OCSP responses
// and CRL entries share.
func revocationReasonName(in int) string {
	switch in {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "key compromise"
	case ocsp.CACompromise:
		return "CA compromise"
	case ocsp.AffiliationChanged:
		return "affiliation changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation of operation"
	case ocsp.CertificateHold:
		return "certificate hold"
	case ocsp.RemoveFromCRL:
		return "remove from CRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilege withdrawn"
	case ocsp.AACompromise:
		return "AA compromise"
	default:
		return fmt.Sprintf("unrecognised (%d)", in)
	}
}
