// Package print renders what pkg/cert reads: as text for a person, as json for
// something acting on it, and as pem for something else to read in turn.
package print

import (
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"strings"
	"time"
)

// Options says what to print beyond the certificate itself. It replaced a row
// of booleans at the call site: by the fifth, nobody could tell which was
// which without counting.
type Options struct {
	Chains      bool
	Pem         bool
	Extensions  bool
	Signature   bool
	Fingerprint bool
}

func printCertificates(certs cert.Certificates, opts Options) {

	for _, certificate := range certs {
		printCertificate(certificate, opts)
		fmt.Println()
		if opts.Pem {
			fmt.Println(string(certificate.ToPEM()))
		}
	}
}

func printCertificate(certificate cert.Certificate, opts Options) {

	if certificate.Error() != nil {
		fmt.Println(certificate.Error())
		return
	}

	fmt.Printf("%s: %d\n", AttributeName("Version"), certificate.Version())
	fmt.Printf("%s: %s\n", AttributeName("Serial Number"), certificate.SerialNumber())
	if opts.Fingerprint {
		fmt.Printf("%s: %s\n", AttributeName("Fingerprint SHA-256"), certificate.Fingerprint())
		fmt.Printf("%s: %s\n", AttributeName("Public Key SHA-256"), certificate.PublicKeyFingerprint())
	}
	fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), certificate.SignatureAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Type"), certificate.Type())
	fmt.Printf("%s: %s\n", AttributeName("Issuer"), certificate.Issuer())
	fmt.Printf("%s\n", AttributeName("Validity"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Not Before"), validityFormat(certificate.NotBefore()))
	fmt.Printf("    %s: %s\n", SubAttributeName("Not After"), NotAfterDate(certificate.NotAfter()))
	fmt.Printf("%s: %s\n", AttributeName("Subject"), certificate.SubjectString())
	fmt.Printf("%s: %s\n", AttributeName("DNS Names"), strings.Join(certificate.DNSNames(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("IP Addresses"), strings.Join(certificate.IPAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Authority Key Id"), certificate.AuthorityKeyId())
	fmt.Printf("%s\n", AttributeName("Subject Key"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Id"), certificate.SubjectKeyId())
	fmt.Printf("    %s: %s\n", SubAttributeName("Algorithm"), certificate.PublicKeyAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Key Usage"), strings.Join(certificate.KeyUsage(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Ext Key Usage"), strings.Join(certificate.ExtKeyUsage(), ", "))
	fmt.Printf("%s: %t\n", AttributeName("CA"), certificate.IsCA())

	if warnings := certificate.Warnings(); len(warnings) > 0 {
		fmt.Printf("%s\n", AttributeName("Warnings"))
		for _, warning := range warnings {
			fmt.Printf("    %s\n", WarningText(warning.Message))
		}
	}

	if opts.Extensions {
		fmt.Printf("%s:\n", AttributeName("Extensions"))
		for _, extension := range certificate.Extensions() {
			name := fmt.Sprintf("%s (%s)", extension.Name, extension.Oid)
			if extension.Critical {
				name = fmt.Sprintf("%s [critical]", name)
			}
			fmt.Printf("    %s\n", SubAttributeName(name))
			for _, line := range extension.Values {
				fmt.Printf("        %s\n", line)
			}
		}
	}

	if opts.Signature {
		fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), certificate.SignatureAlgorithm())
		fmt.Printf("%s\n", AttributeName("Signature Value"))
		for _, line := range splitString(certificate.Signature(), "    ", 54) {
			fmt.Println(line)
		}
	}
}

func validityFormat(t time.Time) string {
	// format for NotBefore and NotAfter fields to make output similar to openssl
	return t.Format("Jan _2 15:04:05 2006 MST")
}

func splitString(in, prefix string, size int) []string {
	if len(in) <= size {
		return []string{prefix + in}
	}

	var chunk string
	var out []string
	for {
		in, chunk = in[size:], in[:size]
		out = append(out, prefix+chunk)
		if len(in) <= size {
			out = append(out, prefix+in)
			break
		}
	}
	return out
}

// Locations prints locations with auto-detected content (certificates or CSRs)
func Locations(locations []cert.Location, opts Options) {
	for _, location := range locations {
		if location.Error != nil {
			fmt.Printf("--- [%s: %v] ---\n", location.Name(), location.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", location.Name())

		// Print based on content type
		if location.IsCSR() {
			printCSRs(location.CSRs, opts.Pem, opts.Extensions, opts.Signature)
		} else if location.IsCertificate() {
			printCertificates(location.Certificates, opts)
			printVerification(location)
			printRevocation(location)

			if opts.Chains {
				chains, err := location.Chains()
				if err != nil {
					fmt.Printf("--- [chains for %s: %v] ---\n", location.Name(), err)
					continue
				}

				if len(chains) == 1 {
					fmt.Printf("--- [%d chain for %s] ---\n", len(chains), location.Name())
				} else {
					fmt.Printf("--- [%d chains for %s] ---\n", len(chains), location.Name())
				}
				for i, chain := range chains {
					fmt.Printf(" -- [chain %d] -- \n", i+1)
					printCertificates(chain, opts)
				}
			}
		}
	}
}

// Pem prints PEM blocks for locations with auto-detected content
func Pem(locations []cert.Location, printChains bool) {
	for _, location := range locations {
		if location.Error != nil {
			fmt.Printf("--- [%s: %v] ---\n", location.Name(), location.Error)
			fmt.Println()
			continue
		}

		if location.IsCSR() {
			for _, csr := range location.CSRs {
				if csr.Error() != nil {
					fmt.Println(csr.Error())
					continue
				}
				fmt.Print(string(csr.ToPEM()))
			}
		} else if location.IsCertificate() {
			for _, certificate := range location.Certificates {
				if certificate.Error() != nil {
					fmt.Println(certificate.Error())
					continue
				}
				fmt.Print(string(certificate.ToPEM()))
			}

			if printChains {
				chains, err := location.Chains()
				if err != nil {
					fmt.Printf("--- [chains for %s: %v] ---\n", location.Name(), err)
					continue
				}

				for _, chain := range chains {
					for _, certificate := range chain {
						if certificate.Error() != nil {
							continue
						}
						fmt.Print(string(certificate.ToPEM()))
					}
				}
			}
		}
	}
}

// Expiry prints expiry information for certificate locations (CSRs don't have expiry)
func Expiry(locations []cert.Location) {
	for _, location := range locations {
		if location.Error != nil {
			fmt.Printf("%s: ERROR: %v\n", location.Name(), location.Error)
			continue
		}

		// Only certificates have expiry dates, skip CSRs
		if location.IsCertificate() {
			for _, certificate := range location.Certificates {
				if certificate.Error() != nil {
					fmt.Printf("%s: %s\n", location.Name(), certificate.Error())
					continue
				}

				// the subject distinguishes the certificates in a chain, which
				// otherwise share a line prefix and cannot be told apart
				fmt.Printf("%s: %s  %s\n", location.Name(), NotAfterDate(certificate.NotAfter()), expirySubject(certificate))
			}
		} else if location.IsCSR() {
			fmt.Printf("%s: CSR (no expiry)\n", location.Name())
		}
	}
}

// expirySubject names a certificate briefly enough to keep the line scannable.
// The common name is enough to tell one from another; the full distinguished
// name, which an EV certificate can drag out to several hundred characters, is
// in the default output and the json.
func expirySubject(certificate cert.Certificate) string {
	if name := certificate.CommonName(); name != "" {
		return name
	}
	return certificate.SubjectString()
}
