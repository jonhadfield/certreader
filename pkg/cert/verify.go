package cert

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// VerificationResult is the outcome of checking a certificate against the
// system trust store, and the hostname where there is one to check.
type VerificationResult struct {
	OK bool
	// Hostname is the name that was checked, empty when the source gave none:
	// a certificate read from a file is not being served for any particular
	// name.
	Hostname string
	// Chains is how many trusted chains were built.
	Chains int
	// Problems is why verification failed, empty when it succeeded.
	Problems []VerificationProblem
}

// VerificationProblem is one reason verification failed.
type VerificationProblem struct {
	// Code is stable, so a check can match on it rather than on the wording.
	Code string
	// Message explains the problem in a sentence.
	Message string
	// Subject names the certificate at fault, where one can be singled out.
	Subject string
}

// Verification problem codes. These are interface: add rather than rename.
const (
	VerifyNoEndEntity         = "no-end-entity"
	VerifyExpired             = "expired"
	VerifyNotYetValid         = "not-yet-valid"
	VerifyMissingIntermediate = "missing-intermediate"
	VerifySelfSigned          = "self-signed"
	VerifyUntrustedRoot       = "untrusted-root"
	VerifyHostnameMismatch    = "hostname-mismatch"
	VerifySystemRoots         = "system-roots-unavailable"
	VerifyFailed              = "not-verified"
)

// Verify checks the certificate against the system trust store, and against the
// hostname when the location was read from the network. It reports why
// verification failed rather than only that it did.
func (l Location) Verify() VerificationResult {

	var result VerificationResult

	leaf := l.verificationLeaf()
	if leaf == nil {
		result.Problems = append(result.Problems, VerificationProblem{
			Code:    VerifyNoEndEntity,
			Message: "no end-entity certificate to verify",
		})
		return result
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		result.Problems = append(result.Problems, VerificationProblem{
			Code:    VerifySystemRoots,
			Message: fmt.Sprintf("cannot read the system trust store: %v", err),
		})
		return result
	}

	intermediates := x509.NewCertPool()
	for i := range l.Certificates {
		candidate := l.Certificates[i].x509Certificate
		if candidate == nil || candidate.Equal(leaf) {
			continue
		}
		intermediates.AddCert(candidate)
	}

	result.Hostname = l.verificationHostname()
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       result.Hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leaf.Verify(opts)
	if err == nil {
		result.OK = true
		result.Chains = len(chains)
		return result
	}

	// Validity is reported on its own. An expired certificate fails everything
	// downstream, so adding guesses about the chain on top would be noise.
	if problems := l.validityProblems(); len(problems) != 0 {
		result.Problems = problems
		return result
	}

	result.Problems = diagnose(leaf, opts, err)
	return result
}

// diagnose works out which part of verification failed, by retrying without the
// hostname to separate a name mismatch from a chain that cannot be built.
func diagnose(leaf *x509.Certificate, opts x509.VerifyOptions, err error) []VerificationProblem {

	withoutHostname := opts
	withoutHostname.DNSName = ""

	if _, chainErr := leaf.Verify(withoutHostname); chainErr == nil {
		// the chain is sound, so the name is the only thing wrong
		var hostnameErr x509.HostnameError
		message := err.Error()
		if errors.As(err, &hostnameErr) {
			message = fmt.Sprintf("not valid for %s", hostnameErr.Host)
		}
		return []VerificationProblem{{
			Code:    VerifyHostnameMismatch,
			Message: message,
			Subject: leaf.Subject.String(),
		}}
	} else {
		err = chainErr
	}

	// A specific complaint from the verifier is worth repeating as it stands.
	// Expiry is excluded because it is reported separately, in full.
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason != x509.Expired {
		return []VerificationProblem{{
			Code:    VerifyFailed,
			Message: invalid.Error(),
			Subject: invalid.Cert.Subject.String(),
		}}
	}

	// Beyond that the error type is not a reliable guide: when the chain cannot
	// be built at all, some platforms return an untyped error rather than
	// x509.UnknownAuthorityError. Whether the issuer was supplied is a fact
	// about the certificates, so it is settled from those instead.
	switch {
	case bytes.Equal(leaf.RawIssuer, leaf.RawSubject):
		// self signed, so it is its own issuer and would otherwise look like an
		// intermediate that was never sent
		return []VerificationProblem{{
			Code:    VerifySelfSigned,
			Message: "self-signed, so it is not issued by any certificate authority",
			Subject: leaf.Subject.String(),
		}}
	case !issuerWasPresented(leaf, opts.Intermediates):
		return []VerificationProblem{{
			Code:    VerifyMissingIntermediate,
			Message: fmt.Sprintf("no certificate for the issuer %s was supplied, so the chain cannot be built", leaf.Issuer.String()),
			Subject: leaf.Subject.String(),
		}}
	default:
		return []VerificationProblem{{
			Code:    VerifyUntrustedRoot,
			Message: fmt.Sprintf("the chain does not lead to a certificate in the system trust store (%v)", err),
			Subject: leaf.Subject.String(),
		}}
	}
}

// validityProblems reports certificates that are outside their validity period.
func (l Location) validityProblems() []VerificationProblem {

	now := time.Now()
	var out []VerificationProblem
	for i := range l.Certificates {
		certificate := l.Certificates[i].x509Certificate
		if certificate == nil {
			continue
		}
		switch {
		case now.Before(certificate.NotBefore):
			out = append(out, VerificationProblem{
				Code:    VerifyNotYetValid,
				Message: fmt.Sprintf("not valid until %s", certificate.NotBefore.Format(time.RFC3339)),
				Subject: certificate.Subject.String(),
			})
		case now.After(certificate.NotAfter):
			out = append(out, VerificationProblem{
				Code:    VerifyExpired,
				Message: fmt.Sprintf("expired on %s", certificate.NotAfter.Format(time.RFC3339)),
				Subject: certificate.Subject.String(),
			})
		}
	}
	return out
}

// issuerWasPresented reports whether a certificate that could have issued the
// leaf was supplied alongside it.
func issuerWasPresented(leaf *x509.Certificate, intermediates *x509.CertPool) bool {

	if intermediates == nil {
		return false
	}
	for _, subject := range intermediates.Subjects() { //nolint:staticcheck // no alternative for pools we built ourselves
		if string(subject) == string(leaf.RawIssuer) {
			return true
		}
	}
	return false
}

// verificationLeaf is the certificate to verify. Type is the usual answer, but
// a self signed certificate looks like a root by that measure, so a network
// location falls back to the one the server sent first, which TLS defines as
// the end-entity certificate.
func (l Location) verificationLeaf() *x509.Certificate {

	for i := range l.Certificates {
		if l.Certificates[i].Error() != nil {
			continue
		}
		if l.Certificates[i].Type() == "end-entity" {
			return l.Certificates[i].x509Certificate
		}
	}

	if l.TLSVersion != 0 || len(l.Certificates) == 1 {
		for i := range l.Certificates {
			if l.Certificates[i].Error() == nil {
				return l.Certificates[i].x509Certificate
			}
		}
	}
	return nil
}

// verificationHostname is the name to check the certificate against. Only a
// network location has one: a certificate in a file is not being served for any
// particular name, and inventing one would invent a failure.
func (l Location) verificationHostname() string {

	if l.TLSVersion == 0 {
		return ""
	}
	if l.ServerName != "" {
		return l.ServerName
	}
	if host, _, err := net.SplitHostPort(l.Path); err == nil {
		return host
	}
	return l.Path
}

// Verify checks every certificate location and records the outcome, so that the
// result travels with the location to whatever renders it.
func (l Locations) Verify() Locations {

	out := make(Locations, len(l))
	copy(out, l)

	for i := range out {
		if out[i].Error != nil || !out[i].IsCertificate() || len(out[i].Certificates) == 0 {
			continue
		}
		result := out[i].Verify()
		out[i].Verification = &result
	}
	return out
}
