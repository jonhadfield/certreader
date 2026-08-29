package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

type Extension struct {
	Name     string
	Oid      string
	Critical bool
	Values   []string
}

func parseExtension(in pkix.Extension) (string, []string, error) {
	if fn, ok := extensionsByOid[in.Id.String()]; ok {
		return fn(in.Value)
	}
	return "-N/A-", []string{in.Id.String()}, nil
}

var extensionsByOid = map[string]func(in []byte) (string, []string, error){
	"2.5.29.35": parseAuthorityKeyIdentifier,
	"2.5.29.14": parseSubjectKeyIdentifier,
	"2.5.29.15": parseKeyUsage,
	"2.5.29.32": parseCertificatePolicies,
	//"2.5.29.33": parsePolicyMappings,
	"2.5.29.17": parseSubjectAltName,
	//"2.5.29.18": parseIssuerAlternativeName,
	//"2.5.29.9": parseSubjectDirectoryAttributes,
	"2.5.29.19": parseBasicConstraints,
	//"2.5.29.30": parseNameConstraints,
	//"2.5.29.36": parsePolicyConstraints,
	"2.5.29.37": parseExtendedKeyUsage,
	"2.5.29.31": parseCRLDistributionPoints,
	//"2.5.29.54": parseInhibitAnyPolicy,
	//"2.5.29.46": parseFreshestCRL,
	// private internet extensions
	"1.3.6.1.5.5.7.1.1": parseAuthorityInformationAccess,
	//"1.3.6.1.5.5.7.11": parseSubjectInformationAccess,
	"1.3.6.1.4.1.11129.2.4.2": parseSignedCertificateTimestampList,
}

// AuthorityKeyIdentifier ::= SEQUENCE {
// keyIdentifier             [0] KeyIdentifier            OPTIONAL,
// authorityCertIssuer       [1] GeneralNames             OPTIONAL,
// authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
// -- authorityCertIssuer and authorityCertSerialNumber MUST both
// -- be present or both be absent
func parseAuthorityKeyIdentifier(in []byte) (string, []string, error) {
	name := "Authority Key Identifier"
	out, err := ToAuthorityKeyIdentifier(in)
	if err != nil {
		return name, nil, err
	}

	fields := []string{formatHexArray(out.KeyIdentifier)}
	if out.AuthorityCertIssuer != nil {
		v := strings.Join(out.AuthorityCertIssuer, ", ")
		fields = append(fields, fmt.Sprintf("Authority Cert. Issuer: %s", v))
	}
	if out.AuthorityCertSerialNumber != 0 {
		fields = append(fields, fmt.Sprintf("Authority Cert SN: %d", out.AuthorityCertSerialNumber))
	}
	return name, fields, nil
}

// SubjectKeyIdentifier ::= KeyIdentifier
func parseSubjectKeyIdentifier(in []byte) (string, []string, error) {
	name := "Subject Key Identifier"
	out := asn1.RawValue{Tag: asn1.TagOctetString}
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, nil, err
	}
	return name, []string{formatHexArray(out.Bytes)}, nil
}

//	KeyUsage ::= BIT STRING {
//	   digitalSignature        (0),
//	   nonRepudiation          (1),  -- recent editions of X.509 have
//	                              -- renamed this bit to contentCommitment
//	   keyEncipherment         (2),
//	   dataEncipherment        (3),
//	   keyAgreement            (4),
//	   keyCertSign             (5),
//	   cRLSign                 (6),
//	   encipherOnly            (7),
//	   decipherOnly            (8) }
func parseKeyUsage(in []byte) (string, []string, error) {
	name := "Key Usage"
	out, err := ToKeyUsage(in)
	if err != nil {
		return name, nil, err
	}
	return name, out, nil
}

func parseCertificatePolicies(in []byte) (string, []string, error) {
	name := "Certificate Policies"
	out, err := ToCertificatePolicies(in)
	if err != nil {
		return name, nil, err
	}
	return name, out, nil
}

func parseSubjectAltName(in []byte) (string, []string, error) {
	name := "Subject Alt. Name"
	out, err := ToGeneralNames(in)
	if err != nil {
		return name, nil, err
	}
	return name, out, nil
}

func parseExtendedKeyUsage(in []byte) (string, []string, error) {
	name := "Extended Key Usage"
	out, err := ToExtendedKeyUsage(in)
	if err != nil {
		return name, nil, err
	}
	return name, out, nil
}

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//	DistributionPoint ::= SEQUENCE {
//	    distributionPoint       [0]     DistributionPointName OPTIONAL,
//	    reasons                 [1]     ReasonFlags OPTIONAL,
//	    cRLIssuer               [2]     GeneralNames OPTIONAL }
//
//	DistributionPointName ::= CHOICE {
//	    fullName                [0]     GeneralNames,
//	    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
func parseCRLDistributionPoints(in []byte) (string, []string, error) {
	name := "CRL Distribution Points"
	out, err := ToCRLDistributionPoints(in)
	if err != nil {
		return name, nil, err
	}
	var points []string
	for _, v := range out {
		var point []string
		if len(v.DistributionPoint) != 0 {
			point = append(point, fmt.Sprintf("Distribution Point: %s", strings.Join(v.DistributionPoint, ", ")))
		}
		if len(v.Reasons) != 0 {
			point = append(point, fmt.Sprintf("Reasons: %s", strings.Join(v.Reasons, ", ")))
		}
		if len(v.CRLIssuer) != 0 {
			point = append(point, fmt.Sprintf("CRL Issuer: %s", strings.Join(v.CRLIssuer, ", ")))
		}
		if len(point) != 0 {
			points = append(points, strings.Join(point, " "))
		}
	}
	return name, points, nil
}

// AuthorityInfoAccessSyntax  ::=
// SEQUENCE SIZE (1..MAX) OF AccessDescription
//
// AccessDescription  ::=  SEQUENCE {
// accessMethod          OBJECT IDENTIFIER,
// accessLocation        GeneralName  }

func parseAuthorityInformationAccess(in []byte) (string, []string, error) {
	name := "Authority Information Access"
	out, err := ToAuthorityInformationAccess(in)
	if err != nil {
		return name, nil, err
	}
	var fields []string
	for _, v := range out {
		fields = append(fields, fmt.Sprintf("%s - %s", v.AccessMethod, v.AccessLocation))
	}
	return name, fields, nil
}

// SignedCertificateTimestampList ::= OCTET STRING wrapping the TLS encoded
// list defined by RFC 6962 section 3.3.
func parseSignedCertificateTimestampList(in []byte) (string, []string, error) {

	name := "CT Precertificate SCTs"
	out, err := ToSignedCertificateTimestamps(in)
	if err != nil {
		return name, nil, err
	}

	// laid out as openssl x509 -text does, so the two can be compared
	var fields []string
	for _, sct := range out {
		fields = append(fields,
			"Signed Certificate Timestamp:",
			"    Version   : "+sct.VersionName(),
			"    Log ID    : "+formatHexArray(sct.LogID),
			"    Timestamp : "+sct.Timestamp.Format("Jan _2 15:04:05.000 2006 MST"),
			"    Extensions: "+sctExtensions(sct.Extensions),
			"    Signature : "+sct.SignatureAlgorithmName(),
		)
		for _, line := range hexLines(sct.Signature, 16) {
			fields = append(fields, "                "+line)
		}
	}
	return name, fields, nil
}

func sctExtensions(in []byte) string {
	if len(in) == 0 {
		return "none"
	}
	return formatHexArray(in)
}

// hexLines splits a long value across lines, since a signature on one line is
// unreadable. A continued line keeps its trailing separator, as openssl does,
// so it is clear the value has not ended.
func hexLines(in []byte, perLine int) []string {

	var out []string
	for start := 0; start < len(in); start += perLine {
		end := start + perLine
		if end > len(in) {
			end = len(in)
		}
		line := formatHexArray(in[start:end])
		if end < len(in) {
			line += ":"
		}
		out = append(out, line)
	}
	return out
}

// BasicConstraints ::= SEQUENCE {
// cA                      BOOLEAN DEFAULT FALSE,
// pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
func parseBasicConstraints(in []byte) (string, []string, error) {
	name := "Basic Constraints"
	out, err := ToBasicConstraints(in)
	if err != nil {
		return name, nil, err
	}

	fields := []string{fmt.Sprintf("CA: %t", out.CA)}
	if out.PathLenConstraint != 0 {
		fields = append(fields, fmt.Sprintf("PathLenConstraint: %d", out.PathLenConstraint))
	}
	return name, fields, nil
}
