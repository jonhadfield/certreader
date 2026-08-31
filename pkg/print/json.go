package print

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
)

// The types below define the -json output. Field names are part of the tool's
// interface: add to them rather than renaming, so that consumers keep working.

type jsonOutput struct {
	Locations []jsonLocation `json:"locations"`
}

type jsonLocation struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// TLSVersion is set only for locations read over the network.
	TLSVersion string `json:"tls_version,omitempty"`
	// Type is "certificate", "csr" or "mixed".
	Type         string              `json:"type"`
	Error        string              `json:"error,omitempty"`
	Certificates []jsonCertificate   `json:"certificates,omitempty"`
	CSRs         []jsonCSR           `json:"csrs,omitempty"`
	Verification *jsonVerification   `json:"verification,omitempty"`
	OCSPStaple   *jsonOCSP           `json:"ocsp_staple,omitempty"`
	Revocation   *jsonRevocation     `json:"revocation,omitempty"`
	Chains       [][]jsonCertificate `json:"chains,omitempty"`
	ChainsError  string              `json:"chains_error,omitempty"`
}

type jsonCertificate struct {
	Position int    `json:"position"`
	Error    string `json:"error,omitempty"`
	// everything below is absent when the certificate failed to parse
	Version            int             `json:"version,omitempty"`
	SerialNumber       string          `json:"serial_number,omitempty"`
	Fingerprint        string          `json:"fingerprint_sha256,omitempty"`
	PublicKeyID        string          `json:"public_key_sha256,omitempty"`
	SignatureAlgorithm string          `json:"signature_algorithm,omitempty"`
	Type               string          `json:"type,omitempty"`
	Issuer             string          `json:"issuer,omitempty"`
	Subject            string          `json:"subject,omitempty"`
	NotBefore          *time.Time      `json:"not_before,omitempty"`
	NotAfter           *time.Time      `json:"not_after,omitempty"`
	Expired            *bool           `json:"expired,omitempty"`
	DNSNames           []string        `json:"dns_names,omitempty"`
	IPAddresses        []string        `json:"ip_addresses,omitempty"`
	AuthorityKeyID     string          `json:"authority_key_id,omitempty"`
	SubjectKeyID       string          `json:"subject_key_id,omitempty"`
	PublicKeyAlgorithm string          `json:"public_key_algorithm,omitempty"`
	KeyUsage           []string        `json:"key_usage,omitempty"`
	ExtKeyUsage        []string        `json:"ext_key_usage,omitempty"`
	IsCA               *bool           `json:"is_ca,omitempty"`
	Extensions         []jsonExtension `json:"extensions,omitempty"`
	// Warnings is present whenever the certificate has any, regardless of flags,
	// since a consumer would not think to ask for them.
	Warnings  []jsonWarning `json:"warnings,omitempty"`
	Signature string        `json:"signature,omitempty"`
	PEM       string        `json:"pem,omitempty"`
}

type jsonWarning struct {
	// Code is stable, so a check can match on it rather than on the message.
	Code    string `json:"code"`
	Message string `json:"message"`
}

type jsonCSR struct {
	Error string `json:"error,omitempty"`
	// the version people write, counting from one, so that it means what a
	// certificate's version field means in the same document
	Version            *int     `json:"version,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	// a pointer so that false is reported rather than omitted: a consumer
	// needs to tell "did not verify" from "was not checked"
	SelfSignatureValid *bool           `json:"self_signature_valid,omitempty"`
	Warnings           []jsonWarning   `json:"warnings,omitempty"`
	Extensions         []jsonExtension `json:"extensions,omitempty"`
	Signature          string          `json:"signature,omitempty"`
	PEM                string          `json:"pem,omitempty"`
}

type jsonExtension struct {
	Name     string   `json:"name"`
	OID      string   `json:"oid"`
	Critical bool     `json:"critical"`
	Values   []string `json:"values,omitempty"`
}

type jsonVerification struct {
	OK bool `json:"ok"`
	// Hostname is the name checked, absent when the source gave none.
	Hostname string              `json:"hostname,omitempty"`
	Chains   int                 `json:"chains"`
	Problems []jsonVerifyProblem `json:"problems,omitempty"`
	// ChainWarnings describe how the chain is built rather than whether it
	// verifies, so they do not affect ok.
	ChainWarnings []jsonWarning `json:"chain_warnings,omitempty"`
}

type jsonVerifyProblem struct {
	// Code is stable, so a check can match on it rather than on the message.
	Code    string `json:"code"`
	Message string `json:"message"`
	Subject string `json:"subject,omitempty"`
}

type jsonOCSP struct {
	Status            string     `json:"status"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	ProducedAt        *time.Time `json:"produced_at,omitempty"`
	ThisUpdate        *time.Time `json:"this_update,omitempty"`
	NextUpdate        *time.Time `json:"next_update,omitempty"`
	SignatureVerified bool       `json:"signature_verified"`
	Stale             bool       `json:"stale"`
	Error             string     `json:"error,omitempty"`
}

type jsonRevocation struct {
	Status string `json:"status"`
	// Source is "stapled OCSP", "OCSP responder" or "CRL", absent when no
	// source produced a verdict.
	Source            string     `json:"source,omitempty"`
	URL               string     `json:"url,omitempty"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	ProducedAt        *time.Time `json:"produced_at,omitempty"`
	ThisUpdate        *time.Time `json:"this_update,omitempty"`
	NextUpdate        *time.Time `json:"next_update,omitempty"`
	SignatureVerified bool       `json:"signature_verified"`
	Stale             bool       `json:"stale"`
	// IssuerFetchedFrom is set when the issuer was not presented alongside the
	// certificate and had to be downloaded.
	IssuerFetchedFrom string              `json:"issuer_fetched_from,omitempty"`
	Attempts          []jsonRevocationTry `json:"not_answered,omitempty"`
}

type jsonRevocationTry struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

// JSON writes every location to stdout as a single JSON document. Logging goes
// to stderr, so the document on stdout stays machine readable even with
// -verbose. The extension, signature and pem fields are included only when the
// corresponding flags are set, matching what the text output would show.
func JSON(locations []cert.Location, opts Options) error {
	return writeJSON(os.Stdout, locations, opts)
}

func writeJSON(w io.Writer, locations []cert.Location, opts Options) error {

	out := jsonOutput{Locations: make([]jsonLocation, 0, len(locations))}
	for _, location := range locations {
		out.Locations = append(out.Locations, buildLocation(location, opts))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// subjects and issuers routinely contain characters that would otherwise be
	// escaped into < and friends
	encoder.SetEscapeHTML(false)
	return encoder.Encode(out)
}

func buildLocation(location cert.Location, opts Options) jsonLocation {

	out := jsonLocation{
		Name:       location.Name(),
		Path:       location.Path,
		TLSVersion: location.TLSVersionName(),
		Type:       contentTypeName(location),
	}
	if location.Error != nil {
		out.Error = location.Error.Error()
		return out
	}

	for _, csr := range location.CSRs {
		out.CSRs = append(out.CSRs, buildCSR(csr, opts))
	}
	for _, certificate := range location.Certificates {
		out.Certificates = append(out.Certificates, buildCertificate(certificate, opts))
	}

	if location.Verification != nil {
		out.Verification = buildVerification(location.Verification)
	}

	if location.Revocation != nil {
		out.Revocation = buildRevocation(location.Revocation)
	} else if location.HasOCSPStaple() {
		out.OCSPStaple = buildStaple(location)
	}

	if opts.Chains && location.IsCertificate() {
		chains, err := location.Chains()
		if err != nil {
			out.ChainsError = err.Error()
		}
		for _, chain := range chains {
			built := make([]jsonCertificate, 0, len(chain))
			for _, certificate := range chain {
				built = append(built, buildCertificate(certificate, opts))
			}
			out.Chains = append(out.Chains, built)
		}
	}
	return out
}

func buildCertificate(certificate cert.Certificate, opts Options) jsonCertificate {

	out := jsonCertificate{Position: certificate.Position()}
	if certificate.Error() != nil {
		// the remaining accessors are not safe to call on a certificate that
		// failed to parse
		out.Error = certificate.Error().Error()
		return out
	}

	notBefore := certificate.NotBefore()
	notAfter := certificate.NotAfter()
	expired := certificate.IsExpired()
	isCA := certificate.IsCA()

	out.Version = certificate.Version()
	out.SerialNumber = certificate.SerialNumber()
	// json is read by something rather than someone, and a consumer would not
	// think to ask for these, so they are always here
	out.Fingerprint = certificate.Fingerprint()
	out.PublicKeyID = certificate.PublicKeyFingerprint()
	out.SignatureAlgorithm = certificate.SignatureAlgorithm()
	out.Type = certificate.Type()
	out.Issuer = certificate.Issuer()
	out.Subject = certificate.SubjectString()
	out.NotBefore = &notBefore
	out.NotAfter = &notAfter
	out.Expired = &expired
	out.DNSNames = certificate.DNSNames()
	out.IPAddresses = certificate.IPAddresses()
	out.AuthorityKeyID = certificate.AuthorityKeyId()
	out.SubjectKeyID = certificate.SubjectKeyId()
	out.PublicKeyAlgorithm = certificate.PublicKeyAlgorithm()
	out.KeyUsage = certificate.KeyUsage()
	out.ExtKeyUsage = certificate.ExtKeyUsage()
	out.IsCA = &isCA

	if opts.Extensions {
		out.Extensions = buildExtensions(certificate.Extensions())
	}
	out.Warnings = buildWarnings(certificate.Warnings())
	if opts.Signature {
		out.Signature = certificate.Signature()
	}
	if opts.Pem {
		out.PEM = string(certificate.ToPEM())
	}
	return out
}

func buildCSR(csr cert.CSR, opts Options) jsonCSR {

	var out jsonCSR
	if csr.Error() != nil {
		out.Error = csr.Error().Error()
		return out
	}

	version := csr.VersionNumber()
	out.Version = &version
	out.Subject = csr.SubjectString()
	out.SignatureAlgorithm = csr.SignatureAlgorithm()
	out.PublicKeyAlgorithm = csr.PublicKeyAlgorithm()
	out.DNSNames = csr.DNSNames()
	out.IPAddresses = csr.IPAddresses()
	out.EmailAddresses = csr.EmailAddresses()
	out.URIs = csr.URIs()

	valid := csr.SelfSignatureValid()
	out.SelfSignatureValid = &valid
	out.Warnings = buildWarnings(csr.Warnings())

	if opts.Extensions {
		out.Extensions = buildExtensions(csr.Extensions())
	}
	if opts.Signature {
		out.Signature = csr.Signature()
	}
	if opts.Pem {
		out.PEM = string(csr.ToPEM())
	}
	return out
}

func buildWarnings(warnings []cert.Warning) []jsonWarning {
	var out []jsonWarning
	for _, warning := range warnings {
		out = append(out, jsonWarning{Code: warning.Code, Message: warning.Message})
	}
	return out
}

func buildExtensions(extensions []cert.Extension) []jsonExtension {
	out := make([]jsonExtension, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, jsonExtension{
			Name:     extension.Name,
			OID:      extension.Oid,
			Critical: extension.Critical,
			Values:   extension.Values,
		})
	}
	return out
}

func buildVerification(in *cert.VerificationResult) *jsonVerification {

	out := &jsonVerification{OK: in.OK, Hostname: in.Hostname, Chains: in.Chains}
	for _, warning := range in.ChainWarnings {
		out.ChainWarnings = append(out.ChainWarnings, jsonWarning{Code: warning.Code, Message: warning.Message})
	}
	for _, problem := range in.Problems {
		out.Problems = append(out.Problems, jsonVerifyProblem{
			Code: problem.Code, Message: problem.Message, Subject: problem.Subject,
		})
	}
	return out
}

func buildStaple(location cert.Location) *jsonOCSP {

	staple, err := location.StapledOCSP()
	if err != nil {
		return &jsonOCSP{Status: "unknown", Error: err.Error()}
	}
	return &jsonOCSP{
		Status:            staple.Status,
		SerialNumber:      staple.SerialNumber,
		RevokedAt:         timeOrNil(staple.RevokedAt),
		RevocationReason:  staple.RevocationReason,
		ProducedAt:        timeOrNil(staple.ProducedAt),
		ThisUpdate:        timeOrNil(staple.ThisUpdate),
		NextUpdate:        timeOrNil(staple.NextUpdate),
		SignatureVerified: staple.SignatureVerified,
		Stale:             staple.IsStale(),
	}
}

func buildRevocation(status *cert.RevocationStatus) *jsonRevocation {

	out := &jsonRevocation{
		Status:            status.Status,
		Source:            string(status.Source),
		URL:               status.URL,
		SerialNumber:      status.SerialNumber,
		RevokedAt:         timeOrNil(status.RevokedAt),
		RevocationReason:  status.RevocationReason,
		ProducedAt:        timeOrNil(status.ProducedAt),
		ThisUpdate:        timeOrNil(status.ThisUpdate),
		NextUpdate:        timeOrNil(status.NextUpdate),
		SignatureVerified: status.SignatureVerified,
		Stale:             status.IsStale(),
		IssuerFetchedFrom: status.IssuerFetchedFrom,
	}
	for _, attempt := range status.Attempts {
		try := jsonRevocationTry{Source: string(attempt.Source), URL: attempt.URL}
		if attempt.Err != nil {
			try.Error = attempt.Err.Error()
		}
		out.Attempts = append(out.Attempts, try)
	}
	return out
}

func contentTypeName(location cert.Location) string {
	switch {
	case location.IsCSR():
		return "csr"
	case location.IsMixed():
		return "mixed"
	default:
		return "certificate"
	}
}

func timeOrNil(in time.Time) *time.Time {
	if in.IsZero() {
		return nil
	}
	return &in
}
