package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	// defaultRevocationRequestTimeout bounds a single OCSP or CRL request.
	defaultRevocationRequestTimeout = 10 * time.Second
	// defaultMaxRevocationResponseSize caps how much of a response body is
	// read. CRLs from public CAs can be tens of megabytes.
	defaultMaxRevocationResponseSize = 32 << 20

	ocspRequestContentType  = "application/ocsp-request"
	ocspResponseContentType = "application/ocsp-response"
)

// RevocationSource identifies where a revocation verdict came from.
type RevocationSource string

const (
	// RevocationSourceStaple is the response the TLS server stapled to the
	// handshake, which costs no additional request.
	RevocationSourceStaple RevocationSource = "stapled OCSP"
	// RevocationSourceOCSP is a live query to the responder named in the
	// certificate's authority information access extension.
	RevocationSourceOCSP RevocationSource = "OCSP responder"
	// RevocationSourceCRL is a certificate revocation list downloaded from a
	// distribution point.
	RevocationSourceCRL RevocationSource = "CRL"
)

// RevocationAttempt records a source that was consulted and why it did not
// produce a verdict.
type RevocationAttempt struct {
	Source RevocationSource
	URL    string
	Err    error
}

func (a RevocationAttempt) String() string {
	err := "no reason given"
	if a.Err != nil {
		err = a.Err.Error()
	}
	switch {
	case a.Source == "":
		return err
	case a.URL == "":
		return fmt.Sprintf("%s: %s", a.Source, err)
	default:
		return fmt.Sprintf("%s %s: %s", a.Source, a.URL, err)
	}
}

// RevocationStatus is the outcome of a revocation check. A status of "unknown"
// means no source could be reached or trusted, which is not the same as the
// certificate being valid.
type RevocationStatus struct {
	// Source and URL describe where the verdict came from. Both are empty when
	// no source produced one.
	Source RevocationSource
	URL    string
	// Status is "good", "revoked" or "unknown".
	Status       string
	SerialNumber string
	// RevokedAt and RevocationReason are only set when Status is "revoked".
	RevokedAt        time.Time
	RevocationReason string
	// ProducedAt is only set for OCSP responses.
	ProducedAt time.Time
	// ThisUpdate and NextUpdate bound the validity of the verdict.
	ThisUpdate time.Time
	NextUpdate time.Time
	// SignatureVerified reports whether the response or list was verified
	// against the issuing CA. When false the verdict is unauthenticated.
	SignatureVerified bool
	// IssuerFetchedFrom is the url a missing issuer was downloaded from, empty
	// when the issuer was presented alongside the certificate.
	IssuerFetchedFrom string
	// Attempts records sources that were consulted without producing a verdict.
	Attempts []RevocationAttempt
}

// IsRevoked reports whether a source declared the certificate revoked.
func (r *RevocationStatus) IsRevoked() bool {
	return r != nil && r.Status == ocspStatusRevoked
}

// IsUnknown reports whether no source produced a usable verdict.
func (r *RevocationStatus) IsUnknown() bool {
	return r == nil || r.Status == ocspStatusUnknown
}

// IsStale reports whether the verdict is past its NextUpdate and should no
// longer be relied upon. Verdicts without a NextUpdate are never stale.
func (r *RevocationStatus) IsStale() bool {
	if r == nil || r.NextUpdate.IsZero() {
		return false
	}
	return time.Now().After(r.NextUpdate)
}

// RevocationChecker queries revocation status over the network. The zero value
// is usable and applies the package defaults.
type RevocationChecker struct {
	// HTTPClient issues OCSP and CRL requests. When nil a client honouring the
	// environment proxy settings is used.
	HTTPClient *http.Client
	// MaxResponseSize caps how much of a response body is read. Zero selects
	// the default.
	MaxResponseSize int64
	// SkipStaple forces a live query even when a stapled response is available.
	SkipStaple bool
	// RequestTimeout bounds a single OCSP, CRL or issuer request. Zero selects
	// the default.
	RequestTimeout time.Duration
	// SkipIssuerFetch stops a missing issuer being downloaded from the
	// certificate's authority information access extension.
	SkipIssuerFetch bool

	// A CRL from a public CA can be tens of megabytes, and a scan of many
	// hosts behind one authority would otherwise download it once per host.
	crlCache    singleFlightCache[*x509.RevocationList]
	issuerCache singleFlightCache[*x509.Certificate]

	defaultClientOnce sync.Once
	defaultClient     *http.Client
}

// NewRevocationChecker returns a checker with the default timeout, response
// size limit and proxy handling.
func NewRevocationChecker() *RevocationChecker {
	return &RevocationChecker{}
}

// client returns the client to issue requests with, building the default one
// once so that connections are reused across locations.
func (c *RevocationChecker) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	c.defaultClientOnce.Do(func() {
		timeout := c.RequestTimeout
		if timeout <= 0 {
			timeout = defaultRevocationRequestTimeout
		}
		c.defaultClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
		}
	})
	return c.defaultClient
}

func (c *RevocationChecker) maxResponseSize() int64 {
	if c.MaxResponseSize > 0 {
		return c.MaxResponseSize
	}
	return defaultMaxRevocationResponseSize
}

// Check determines the revocation status of leaf. It prefers a usable stapled
// response, then the OCSP responders named in the certificate, then its CRL
// distribution points. The first source to produce a verdict wins; sources that
// fail are recorded on the result rather than aborting the check.
//
// A nil issuer means responses cannot be authenticated: OCSP is skipped
// entirely, because a request cannot be built without it, and any CRL verdict
// is reported with SignatureVerified false.
func (c *RevocationChecker) Check(ctx context.Context, leaf, issuer *x509.Certificate, staple []byte) *RevocationStatus {

	status := &RevocationStatus{Status: ocspStatusUnknown}
	if leaf == nil {
		status.Attempts = append(status.Attempts, RevocationAttempt{
			Err: errors.New("no end-entity certificate to check"),
		})
		return status
	}
	status.SerialNumber = formatHexArray(leaf.SerialNumber.Bytes())

	// without an issuer nothing can be authenticated and OCSP cannot even be
	// asked, so it is worth a request to go and get one
	if issuer == nil {
		fetched, from, err := c.fetchIssuer(ctx, leaf)
		if err != nil {
			status.Attempts = append(status.Attempts, RevocationAttempt{
				Source: RevocationSourceIssuer, Err: err,
			})
		} else {
			issuer = fetched
			status.IssuerFetchedFrom = from
		}
	}

	if out, ok := c.checkStaple(leaf, issuer, staple, status); ok {
		return out
	}
	if out, ok := c.checkOCSP(ctx, leaf, issuer, status); ok {
		return out
	}
	if out, ok := c.checkCRL(ctx, leaf, issuer, status); ok {
		return out
	}
	return status
}

// checkStaple considers the response the server volunteered, which needs no
// request of our own.
func (c *RevocationChecker) checkStaple(leaf, issuer *x509.Certificate, staple []byte, status *RevocationStatus) (*RevocationStatus, bool) {

	if c.SkipStaple || len(staple) == 0 {
		return nil, false
	}

	parsed, err := ParseStapledOCSP(staple, leaf, issuer)
	if err != nil {
		status.Attempts = append(status.Attempts, RevocationAttempt{Source: RevocationSourceStaple, Err: err})
		return nil, false
	}
	if parsed.IsStale() {
		status.Attempts = append(status.Attempts, RevocationAttempt{
			Source: RevocationSourceStaple,
			Err:    fmt.Errorf("response expired at %s", parsed.NextUpdate.Format(time.RFC3339)),
		})
		return nil, false
	}

	out := revocationFromOCSP(parsed, RevocationSourceStaple, "")
	carryOver(out, status)
	return out, true
}

// checkOCSP queries each responder named in the certificate until one answers.
func (c *RevocationChecker) checkOCSP(ctx context.Context, leaf, issuer *x509.Certificate, status *RevocationStatus) (*RevocationStatus, bool) {

	if issuer == nil {
		status.Attempts = append(status.Attempts, RevocationAttempt{
			Source: RevocationSourceOCSP,
			Err:    errors.New("issuer certificate unavailable, cannot build request"),
		})
		return nil, false
	}
	if len(leaf.OCSPServer) == 0 {
		status.Attempts = append(status.Attempts, RevocationAttempt{
			Source: RevocationSourceOCSP,
			Err:    errors.New("certificate names no OCSP responder"),
		})
		return nil, false
	}

	for _, responder := range leaf.OCSPServer {
		out, err := c.queryOCSP(ctx, leaf, issuer, responder)
		if err != nil {
			status.Attempts = append(status.Attempts, RevocationAttempt{
				Source: RevocationSourceOCSP, URL: responder, Err: err,
			})
			continue
		}
		carryOver(out, status)
		return out, true
	}
	return nil, false
}

// checkCRL downloads each distribution point until one yields a usable list.
func (c *RevocationChecker) checkCRL(ctx context.Context, leaf, issuer *x509.Certificate, status *RevocationStatus) (*RevocationStatus, bool) {

	if len(leaf.CRLDistributionPoints) == 0 {
		status.Attempts = append(status.Attempts, RevocationAttempt{
			Source: RevocationSourceCRL,
			Err:    errors.New("certificate names no CRL distribution point"),
		})
		return nil, false
	}

	for _, point := range leaf.CRLDistributionPoints {
		out, err := c.queryCRL(ctx, leaf, issuer, point)
		if err != nil {
			status.Attempts = append(status.Attempts, RevocationAttempt{
				Source: RevocationSourceCRL, URL: point, Err: err,
			})
			continue
		}
		carryOver(out, status)
		return out, true
	}
	return nil, false
}

// queryOCSP posts an OCSP request to a single responder.
func (c *RevocationChecker) queryOCSP(ctx context.Context, leaf, issuer *x509.Certificate, responder string) (*RevocationStatus, error) {

	if err := validateHTTPURL(responder); err != nil {
		return nil, err
	}

	body, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("build OCSP request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, responder, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", ocspRequestContentType)
	request.Header.Set("Accept", ocspResponseContentType)

	raw, err := c.do(request)
	if err != nil {
		return nil, err
	}

	parsed, err := parseOCSPResponse(raw, leaf, issuer)
	if err != nil {
		return nil, err
	}
	return revocationFromOCSP(parsed, RevocationSourceOCSP, responder), nil
}

// queryCRL downloads a single distribution point and looks for the serial.
func (c *RevocationChecker) queryCRL(ctx context.Context, leaf, issuer *x509.Certificate, point string) (*RevocationStatus, error) {

	if err := validateHTTPURL(point); err != nil {
		return nil, err
	}

	list, err := c.fetchCRL(ctx, point)
	if err != nil {
		return nil, err
	}

	var verified bool
	if issuer != nil {
		if err := list.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("bad CRL signature: %w", err)
		}
		verified = true
	}

	// absence from a list that covers this certificate means not revoked
	status := &RevocationStatus{
		Source:            RevocationSourceCRL,
		URL:               point,
		Status:            ocspStatusGood,
		SerialNumber:      formatHexArray(leaf.SerialNumber.Bytes()),
		ThisUpdate:        list.ThisUpdate,
		NextUpdate:        list.NextUpdate,
		SignatureVerified: verified,
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			continue
		}
		status.Status = ocspStatusRevoked
		status.RevokedAt = entry.RevocationTime
		status.RevocationReason = revocationReasonName(entry.ReasonCode)
		break
	}
	return status, nil
}

// fetchCRL downloads and parses a revocation list, once per url however many
// certificates are being checked against it. The signature is deliberately not
// checked here: that is per certificate, since two hosts sharing a distribution
// point need not share an issuer.
func (c *RevocationChecker) fetchCRL(ctx context.Context, point string) (*x509.RevocationList, error) {

	return c.crlCache.get(point, func() (*x509.RevocationList, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, point, nil)
		if err != nil {
			return nil, err
		}
		raw, err := c.do(request)
		if err != nil {
			return nil, err
		}
		return parseCRL(raw)
	})
}

// do issues a request and reads a bounded response body.
func (c *RevocationChecker) do(request *http.Request) ([]byte, error) {

	response, err := c.client().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status %s", response.Status)
	}

	limit := c.maxResponseSize()
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes", limit)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty response")
	}
	return raw, nil
}

// carryOver moves the context gathered before a source answered onto the
// verdict it produced, which is otherwise built fresh and would lose it.
func carryOver(out, status *RevocationStatus) {
	out.Attempts = status.Attempts
	out.IssuerFetchedFrom = status.IssuerFetchedFrom
}

// revocationFromOCSP converts a parsed OCSP response into a verdict.
func revocationFromOCSP(in *StapledOCSP, source RevocationSource, url string) *RevocationStatus {
	return &RevocationStatus{
		Source:            source,
		URL:               url,
		Status:            in.Status,
		SerialNumber:      in.SerialNumber,
		RevokedAt:         in.RevokedAt,
		RevocationReason:  in.RevocationReason,
		ProducedAt:        in.ProducedAt,
		ThisUpdate:        in.ThisUpdate,
		NextUpdate:        in.NextUpdate,
		SignatureVerified: in.SignatureVerified,
	}
}

// parseCRL accepts a revocation list in either DER or PEM encoding.
func parseCRL(data []byte) (*x509.RevocationList, error) {

	list, derErr := x509.ParseRevocationList(data)
	if derErr == nil {
		return list, nil
	}

	if block, _ := pem.Decode(data); block != nil {
		list, pemErr := x509.ParseRevocationList(block.Bytes)
		if pemErr == nil {
			return list, nil
		}
		return nil, fmt.Errorf("parse CRL: %w", pemErr)
	}
	return nil, fmt.Errorf("parse CRL: %w", derErr)
}

// validateHTTPURL rejects the non-HTTP distribution points, typically ldap://,
// that some certificates carry alongside usable ones.
func validateHTTPURL(in string) error {

	parsed, err := url.Parse(in)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("url has no host")
	}
	return nil
}

// CheckRevocation determines the revocation status of every certificate
// location, querying the network concurrently. Locations that failed to load,
// and those holding CSRs, are left untouched.
func (l Locations) CheckRevocation(ctx context.Context, checker *RevocationChecker) Locations {

	if checker == nil {
		checker = NewRevocationChecker()
	}

	out := make(Locations, len(l))
	copy(out, l)

	var wg sync.WaitGroup
	for i := range out {
		if out[i].Error != nil || !out[i].IsCertificate() || len(out[i].Certificates) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaf, issuer := out[i].leafAndIssuer()
			out[i].Revocation = checker.Check(ctx, leaf, issuer, out[i].OCSPStaple)
		}()
	}
	wg.Wait()
	return out
}
