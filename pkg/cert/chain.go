package cert

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// Chain warning codes. These describe what a server sent rather than whether it
// verifies: a chain can be perfectly valid and still be built badly.
const (
	ChainWarningRootIncluded = "root-included"
	ChainWarningDuplicate    = "duplicate-certificate"
	ChainWarningOutOfOrder   = "chain-out-of-order"
	ChainWarningNoLeafFirst  = "leaf-not-first"
	// A missing intermediate is reported under the same code whether it is
	// found here or by verification, since it is the same fault either way.
	ChainWarningNoIssuer = VerifyMissingIntermediate
)

// ChainWarnings reports how the served chain is put together. These are not
// verification failures: every one of them can appear on a chain that verifies
// perfectly well, and none of them should stop a client connecting.
//
// Only network locations are considered. A bundle in a file is expected to hold
// roots and to be in whatever order suits it, so the same checks there would
// report the file's purpose as a fault.
func (l Location) ChainWarnings() []Warning {

	if l.TLSVersion == 0 {
		return nil
	}

	presented := make([]*x509.Certificate, 0, len(l.Certificates))
	for i := range l.Certificates {
		if l.Certificates[i].Error() == nil {
			presented = append(presented, l.Certificates[i].x509Certificate)
		}
	}
	if len(presented) == 0 {
		return nil
	}

	var out []Warning
	out = append(out, duplicateWarnings(presented)...)
	out = append(out, rootWarnings(presented)...)
	out = append(out, orderWarnings(presented)...)
	out = append(out, missingIntermediateWarnings(presented)...)
	return out
}

// missingIntermediateWarnings reports a server that does not send the
// certificate that issued its own.
//
// This is the misconfiguration that breaks clients, and the one hardest to
// notice: macOS and Windows keep intermediates they have seen before and fill
// the gap themselves, so the chain verifies on the machine it was tested from
// and fails for anyone whose store happens not to hold it. Verification cannot
// report this, because on such a machine there is nothing to report: this
// checks what the server sent rather than what this computer can make of it.
//
// A single-tier private CA that issues its leaves directly is warned about too.
// Whether that matters cannot be told from here without knowing what the client
// trusts, and the sentence is true either way: the issuer was not sent.
func missingIntermediateWarnings(presented []*x509.Certificate) []Warning {

	leaf := presented[0]
	if isCertificateAuthority(leaf) {
		return nil // already reported as not leaf first
	}
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return nil // self-signed, which verification reports on its own
	}

	for _, candidate := range presented[1:] {
		if bytes.Equal(candidate.RawSubject, leaf.RawIssuer) {
			return nil
		}
	}

	return []Warning{{
		Code: VerifyMissingIntermediate,
		Message: fmt.Sprintf("%s is not sent, so a client that does not already hold it cannot build the chain for %s",
			issuerName(leaf), nameOrSubject(leaf)),
	}}
}

// issuerName names the certificate that signed this one, as briefly as it can
// be told apart.
func issuerName(certificate *x509.Certificate) string {
	if certificate.Issuer.CommonName != "" {
		return certificate.Issuer.CommonName
	}
	return certificate.Issuer.String()
}

// duplicateWarnings reports a certificate sent more than once, which is wasted
// bandwidth on every handshake.
func duplicateWarnings(presented []*x509.Certificate) []Warning {

	var out []Warning
	seen := make(map[string]bool, len(presented))
	for _, certificate := range presented {
		key := string(certificate.Raw)
		if seen[key] {
			out = append(out, Warning{
				Code:    ChainWarningDuplicate,
				Message: fmt.Sprintf("%s is sent more than once", nameOrSubject(certificate)),
			})
			continue
		}
		seen[key] = true
	}
	return out
}

// rootWarnings reports a root sent alongside the chain. A client can only trust
// a root it already has, so sending one adds bytes to every handshake and
// changes nothing.
func rootWarnings(presented []*x509.Certificate) []Warning {

	var out []Warning
	for i, certificate := range presented {
		// the first certificate is the end-entity; a self-signed one there is a
		// different problem, and verification reports it
		if i == 0 || !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			continue
		}
		out = append(out, Warning{
			Code: ChainWarningRootIncluded,
			Message: fmt.Sprintf("the root %s is sent but cannot be used: a client either already trusts it or will not trust it now (%d bytes per handshake)",
				nameOrSubject(certificate), len(certificate.Raw)),
		})
	}
	return out
}

// orderWarnings reports a chain that is not leaf first, each certificate signed
// by the one after it. TLS 1.3 lets a client cope with any order, but older
// clients need not, and a chain out of order usually means it was assembled by
// hand and wrongly.
func orderWarnings(presented []*x509.Certificate) []Warning {

	var out []Warning
	if isCertificateAuthority(presented[0]) {
		out = append(out, Warning{
			Code:    ChainWarningNoLeafFirst,
			Message: fmt.Sprintf("the first certificate sent is %s, a certificate authority, where the end-entity certificate is expected", nameOrSubject(presented[0])),
		})
		return out
	}

	for i := 1; i < len(presented); i++ {
		if bytes.Equal(presented[i].Raw, presented[i-1].Raw) {
			continue // already reported as a duplicate
		}
		if err := presented[i-1].CheckSignatureFrom(presented[i]); err != nil {
			out = append(out, Warning{
				Code: ChainWarningOutOfOrder,
				Message: fmt.Sprintf("%s does not issue the certificate before it, so the chain is not in order",
					nameOrSubject(presented[i])),
			})
		}
	}
	return out
}

func isCertificateAuthority(certificate *x509.Certificate) bool {
	return certificate.IsCA && certificate.BasicConstraintsValid
}

// nameOrSubject names a certificate as briefly as it can be told apart.
func nameOrSubject(certificate *x509.Certificate) string {
	if certificate.Subject.CommonName != "" {
		return certificate.Subject.CommonName
	}
	return certificate.Subject.String()
}
