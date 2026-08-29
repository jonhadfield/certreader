package cert

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

// RevocationSourceIssuer labels the attempt to obtain a missing issuer, which
// is a prerequisite for the other sources rather than a source itself.
const RevocationSourceIssuer RevocationSource = "issuer fetch"

// pkcs7SignedDataOID is the DER encoding of 1.2.840.113549.1.7.2, which is what
// a certificate served as a pkcs#7 bundle begins with. The standard library
// cannot parse those, so they are worth naming rather than reporting as a
// confusing asn.1 error.
var pkcs7SignedDataOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}

// fetchIssuer downloads the issuing certificate from the authority information
// access extension, so that a lone end-entity certificate can still be checked.
// The returned certificate is only accepted if it actually signed the leaf.
func (c *RevocationChecker) fetchIssuer(ctx context.Context, leaf *x509.Certificate) (*x509.Certificate, string, error) {

	if c.SkipIssuerFetch {
		return nil, "", errors.New("issuer fetch is disabled")
	}
	if len(leaf.IssuingCertificateURL) == 0 {
		return nil, "", errors.New("certificate names no issuer url")
	}

	var lastErr error
	for _, url := range leaf.IssuingCertificateURL {
		issuer, err := c.downloadIssuer(ctx, leaf, url)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", url, err)
			continue
		}
		return issuer, url, nil
	}
	return nil, "", lastErr
}

func (c *RevocationChecker) downloadIssuer(ctx context.Context, leaf *x509.Certificate, url string) (*x509.Certificate, error) {

	if err := validateHTTPURL(url); err != nil {
		return nil, err
	}

	candidate, cached := c.cachedIssuer(url)
	if !cached {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		raw, err := c.do(request)
		if err != nil {
			return nil, err
		}
		candidate, err = parseIssuerCertificate(raw)
		if err != nil {
			return nil, err
		}
		c.storeIssuer(url, candidate)
	}

	// a certificate fetched over plain http is worth nothing until it is shown
	// to have signed the one being checked
	if err := leaf.CheckSignatureFrom(candidate); err != nil {
		return nil, fmt.Errorf("fetched certificate did not sign this one: %w", err)
	}
	return candidate, nil
}

func (c *RevocationChecker) cachedIssuer(url string) (*x509.Certificate, bool) {
	c.issuerCacheMu.Lock()
	defer c.issuerCacheMu.Unlock()

	issuer, ok := c.issuerCache[url]
	return issuer, ok
}

func (c *RevocationChecker) storeIssuer(url string, issuer *x509.Certificate) {
	c.issuerCacheMu.Lock()
	defer c.issuerCacheMu.Unlock()

	if c.issuerCache == nil {
		c.issuerCache = map[string]*x509.Certificate{}
	}
	c.issuerCache[url] = issuer
}

// parseIssuerCertificate accepts the encodings CAs actually serve.
func parseIssuerCertificate(data []byte) (*x509.Certificate, error) {

	if certificate, err := x509.ParseCertificate(data); err == nil {
		return certificate, nil
	}
	if block, _ := pem.Decode(data); block != nil {
		if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
			return certificate, nil
		}
	}
	if bytes.Contains(data, pkcs7SignedDataOID) {
		return nil, errors.New("served as a pkcs#7 bundle, which cannot be parsed")
	}
	return nil, errors.New("response is not a certificate in der or pem form")
}
