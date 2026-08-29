package cert

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// SignedCertificateTimestamp is one entry from a certificate transparency SCT
// list, as defined by RFC 6962 section 3.2. A CA embeds these to prove the
// certificate was submitted to public logs.
type SignedCertificateTimestamp struct {
	// Version is 0 for v1, the only version defined.
	Version uint8
	// LogID is the SHA-256 hash of the log's public key, which is how a log is
	// identified. There is no name here: mapping ids to names needs a list that
	// goes stale.
	LogID []byte
	// Timestamp is when the log promised to include the certificate.
	Timestamp time.Time
	// Extensions is defined by RFC 6962 but unused in practice, so normally empty.
	Extensions []byte
	// HashAlgorithm and SignatureAlgorithm are the RFC 5246 codes for the
	// signature that follows.
	HashAlgorithm      uint8
	SignatureAlgorithm uint8
	Signature          []byte
}

// SignatureAlgorithmName renders the hash and signature codes the way the rest
// of the tool names a signature algorithm, or describes them when unrecognised.
func (s SignedCertificateTimestamp) SignatureAlgorithmName() string {

	const (
		hashSHA1   = 2
		hashSHA256 = 4
		hashSHA384 = 5
		hashSHA512 = 6

		signatureRSA   = 1
		signatureECDSA = 3
	)

	switch s.SignatureAlgorithm {
	case signatureECDSA:
		switch s.HashAlgorithm {
		case hashSHA256:
			return x509.ECDSAWithSHA256.String()
		case hashSHA384:
			return x509.ECDSAWithSHA384.String()
		case hashSHA512:
			return x509.ECDSAWithSHA512.String()
		case hashSHA1:
			return x509.ECDSAWithSHA1.String()
		}
	case signatureRSA:
		switch s.HashAlgorithm {
		case hashSHA256:
			return x509.SHA256WithRSA.String()
		case hashSHA384:
			return x509.SHA384WithRSA.String()
		case hashSHA512:
			return x509.SHA512WithRSA.String()
		case hashSHA1:
			return x509.SHA1WithRSA.String()
		}
	}
	return fmt.Sprintf("unknown (hash %d, signature %d)", s.HashAlgorithm, s.SignatureAlgorithm)
}

// VersionName renders the version the way openssl does.
func (s SignedCertificateTimestamp) VersionName() string {
	if s.Version == 0 {
		return "v1 (0x0)"
	}
	return fmt.Sprintf("unknown (0x%x)", s.Version)
}

// ToSignedCertificateTimestamps parses the contents of the SCT list extension.
// The extension wraps a TLS encoded list inside an ASN.1 octet string.
func ToSignedCertificateTimestamps(in []byte) ([]SignedCertificateTimestamp, error) {

	raw, err := ToSignedCertificateTimestampList(in)
	if err != nil {
		return nil, err
	}
	return parseSCTList(raw)
}

func parseSCTList(in []byte) ([]SignedCertificateTimestamp, error) {

	list := &tlsReader{data: in}
	length, err := list.uint16()
	if err != nil {
		return nil, fmt.Errorf("sct list length: %w", err)
	}
	body, err := list.take(int(length))
	if err != nil {
		return nil, fmt.Errorf("sct list: %w", err)
	}
	if list.remaining() != 0 {
		return nil, errors.New("trailing data after sct list")
	}

	var out []SignedCertificateTimestamp
	entries := &tlsReader{data: body}
	for entries.remaining() > 0 {
		entryLength, err := entries.uint16()
		if err != nil {
			return nil, fmt.Errorf("sct length: %w", err)
		}
		entry, err := entries.take(int(entryLength))
		if err != nil {
			return nil, fmt.Errorf("sct: %w", err)
		}
		sct, err := parseSCT(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, sct)
	}
	if len(out) == 0 {
		return nil, errors.New("sct list is empty")
	}
	return out, nil
}

// logIDLength is the size of a SHA-256 hash, which is what identifies a log.
const logIDLength = 32

func parseSCT(in []byte) (SignedCertificateTimestamp, error) {

	var out SignedCertificateTimestamp
	r := &tlsReader{data: in}

	version, err := r.uint8()
	if err != nil {
		return out, fmt.Errorf("sct version: %w", err)
	}
	logID, err := r.take(logIDLength)
	if err != nil {
		return out, fmt.Errorf("sct log id: %w", err)
	}
	milliseconds, err := r.uint64()
	if err != nil {
		return out, fmt.Errorf("sct timestamp: %w", err)
	}
	extensions, err := r.vector16()
	if err != nil {
		return out, fmt.Errorf("sct extensions: %w", err)
	}
	hashAlgorithm, err := r.uint8()
	if err != nil {
		return out, fmt.Errorf("sct hash algorithm: %w", err)
	}
	signatureAlgorithm, err := r.uint8()
	if err != nil {
		return out, fmt.Errorf("sct signature algorithm: %w", err)
	}
	signature, err := r.vector16()
	if err != nil {
		return out, fmt.Errorf("sct signature: %w", err)
	}
	if r.remaining() != 0 {
		return out, errors.New("trailing data after sct")
	}

	return SignedCertificateTimestamp{
		Version:            version,
		LogID:              logID,
		Timestamp:          time.UnixMilli(int64(milliseconds)).UTC(),
		Extensions:         extensions,
		HashAlgorithm:      hashAlgorithm,
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          signature,
	}, nil
}

// tlsReader reads the big endian fixed width fields and length prefixed vectors
// that the TLS presentation language uses, refusing to run off the end.
type tlsReader struct {
	data []byte
}

func (r *tlsReader) remaining() int { return len(r.data) }

func (r *tlsReader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data) {
		return nil, fmt.Errorf("want %d bytes, have %d", n, len(r.data))
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out, nil
}

func (r *tlsReader) uint8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *tlsReader) uint16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *tlsReader) uint64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// vector16 reads a uint16 length followed by that many bytes.
func (r *tlsReader) vector16() ([]byte, error) {
	length, err := r.uint16()
	if err != nil {
		return nil, err
	}
	return r.take(int(length))
}
