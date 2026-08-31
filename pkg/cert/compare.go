package cert

import "fmt"

// Comparison says whether two locations are serving the same thing, and where
// they differ if not.
//
// The question people bring to this is usually one of two: is the load
// balancer serving what I deployed, and has the key actually been rotated.
// Those have different answers when a certificate is reissued from the same
// key, which is why the key is compared as well as the certificate.
type Comparison struct {
	// Left and Right name what was compared, as the locations were given.
	Left, Right string
	// SameCertificate is whether the end-entity certificates are the same one.
	SameCertificate bool
	// SameKey is whether they carry the same public key. A reissue keeps it; a
	// rotation does not.
	SameKey bool
	// SameChain is whether the whole of what each location holds matches, in
	// order. Two hosts can serve the same leaf and a different chain.
	SameChain bool
	// LeftFingerprint and RightFingerprint are the end-entity certificates.
	LeftFingerprint, RightFingerprint string
	// LeftKeyFingerprint and RightKeyFingerprint are their public keys.
	LeftKeyFingerprint, RightKeyFingerprint string
	// LeftCount and RightCount are how many certificates each location holds.
	LeftCount, RightCount int
}

// Same reports whether both are serving the same certificate, which is the
// question a check is asking.
//
// The chain is not part of it. Deploying a leaf and serving it with the
// intermediates a client needs is normal and correct, so a file holding one
// certificate and a host sending three is not a difference worth failing on.
// It is still reported.
func (c Comparison) Same() bool {
	return c.SameCertificate
}

// Summary is the comparison in a sentence, for the reader who wants only the
// answer.
func (c Comparison) Summary() string {
	switch {
	case c.SameCertificate && c.SameChain:
		return "the same certificate and the same chain"
	case c.SameCertificate:
		return "the same certificate, sent with a different chain"
	case c.SameKey:
		return "different certificates carrying the same key, which is what a reissue looks like"
	default:
		return "different certificates, and different keys"
	}
}

// Compare reports how two locations differ. Both have to have been read: a
// location that failed to load is not something to compare, and saying which
// one and why is more use than saying it cannot be done.
func (l Locations) Compare() (Comparison, error) {
	if len(l) != 2 {
		return Comparison{}, fmt.Errorf("comparing needs two locations, given %d", len(l))
	}

	left, right := l[0], l[1]
	for _, location := range l {
		if location.Error != nil {
			return Comparison{}, fmt.Errorf("%s: %w", location.Name(), location.Error)
		}
	}

	leftLeaf, rightLeaf := left.comparableLeaf(), right.comparableLeaf()
	if leftLeaf == nil {
		return Comparison{}, fmt.Errorf("%s holds no certificate to compare", left.Name())
	}
	if rightLeaf == nil {
		return Comparison{}, fmt.Errorf("%s holds no certificate to compare", right.Name())
	}

	out := Comparison{
		Left:                left.Name(),
		Right:               right.Name(),
		LeftFingerprint:     leftLeaf.Fingerprint(),
		RightFingerprint:    rightLeaf.Fingerprint(),
		LeftKeyFingerprint:  leftLeaf.PublicKeyFingerprint(),
		RightKeyFingerprint: rightLeaf.PublicKeyFingerprint(),
		LeftCount:           len(left.Certificates),
		RightCount:          len(right.Certificates),
	}
	out.SameCertificate = out.LeftFingerprint == out.RightFingerprint
	out.SameKey = out.LeftKeyFingerprint == out.RightKeyFingerprint
	out.SameChain = sameChain(left.Certificates, right.Certificates)
	return out, nil
}

// comparableLeaf is the certificate a comparison is about: the end-entity one,
// or the only one there is when a file holds a single CA.
func (l Location) comparableLeaf() *Certificate {
	for i := range l.Certificates {
		if l.Certificates[i].Error() != nil {
			continue
		}
		if l.Certificates[i].Type() == "end-entity" {
			return &l.Certificates[i]
		}
	}
	for i := range l.Certificates {
		if l.Certificates[i].Error() == nil {
			return &l.Certificates[i]
		}
	}
	return nil
}

// sameChain reports whether both hold the same certificates in the same order.
func sameChain(left, right Certificates) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Error() != nil || right[i].Error() != nil {
			return false
		}
		if left[i].Fingerprint() != right[i].Fingerprint() {
			return false
		}
	}
	return true
}
