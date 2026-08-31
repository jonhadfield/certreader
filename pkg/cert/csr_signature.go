package cert

import "fmt"

// WarningBadSelfSignature is reported when a request's self-signature does not
// hold. It is a warning rather than a parse error: everything else in the
// request is still readable, and worth showing while saying not to trust it.
const WarningBadSelfSignature = "invalid-self-signature"

// CheckSelfSignature reports whether the request was signed by the key inside
// it.
//
// A request is signed by the key it asks to have certified, and that signature
// is the only evidence the requester holds the matching private key. It is
// also the only thing binding the subject and the alternative names to that
// key: without it a request is a list of claims anyone could have written.
// Nothing else in a request means much until this holds.
func (c CSR) CheckSelfSignature() error {
	if err := c.Error(); err != nil {
		return err
	}
	if err := c.x509CSR.CheckSignature(); err != nil {
		return fmt.Errorf("self-signature does not verify: %w", err)
	}
	return nil
}

// SelfSignatureValid says the same thing for callers that only need to know
// whether to trust what they are reading.
func (c CSR) SelfSignatureValid() bool {
	return c.CheckSelfSignature() == nil
}

// Warnings is what to draw attention to about the request. A request that does
// not verify is the only one so far, and it is the one that matters: it is the
// difference between a request and an assertion.
func (c CSR) Warnings() []Warning {
	if c.Error() != nil {
		return nil
	}

	if err := c.CheckSelfSignature(); err != nil {
		return []Warning{{
			Code:    WarningBadSelfSignature,
			Message: err.Error(),
		}}
	}
	return nil
}
