package cert

import (
	"crypto/sha256"
	"encoding/base64"
)

// Fingerprint is the SHA-256 of the certificate as it was encoded, in the
// colon separated hex that openssl and the browsers show. It names this exact
// certificate: reissuing the same subject, even with the same key, gives a
// different one.
//
// It is what to compare when the question is whether two things are the same
// certificate. A serial number only answers that within one issuer.
func (c Certificate) Fingerprint() string {
	if c.Error() != nil {
		return ""
	}

	sum := sha256.Sum256(c.x509Certificate.Raw)
	return formatHexArray(sum[:])
}

// PublicKeyFingerprint is the SHA-256 of the subject public key info, base64
// encoded, which is the form a pin is written in.
//
// It names the key rather than the certificate, so it survives a reissue that
// keeps the key and changes when the key changes. That is the distinction a
// pin rests on, and the reason both are worth printing.
func (c Certificate) PublicKeyFingerprint() string {
	if c.Error() != nil {
		return ""
	}

	sum := sha256.Sum256(c.x509Certificate.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
