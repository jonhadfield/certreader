package print

import (
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"log/slog"
)

// LocationsUnified prints locations with auto-detected content (certificates or CSRs)
func LocationsUnified(locations []cert.Location, printChains, printPem, printExtensions, printSignature bool) {
	for _, location := range locations {
		if location.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", location.Name(), location.Error))
			fmt.Printf("--- [%s: %v] ---\n", location.Name(), location.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", location.Name())

		// Print based on content type
		if location.IsCSR() {
			printCSRs(location.CSRs, printPem, printExtensions, printSignature)
		} else if location.IsCertificate() {
			printCertificates(location.Certificates, printPem, printExtensions, printSignature)

			if printChains {
				chains, err := location.Chains()
				if err != nil {
					slog.Error(fmt.Sprintf("chains for %s: %v", location.Name(), err))
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
					printCertificates(chain, printPem, printExtensions, printSignature)
				}
			}
		}
	}
}

// PemUnified prints PEM blocks for locations with auto-detected content
func PemUnified(locations []cert.Location, printChains bool) {
	for _, location := range locations {
		if location.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", location.Name(), location.Error))
			fmt.Printf("--- [%s: %v] ---\n", location.Name(), location.Error)
			fmt.Println()
			continue
		}

		if location.IsCSR() {
			for _, csr := range location.CSRs {
				if csr.Error() != nil {
					slog.Error(csr.Error().Error())
					fmt.Println(csr.Error())
					continue
				}
				fmt.Print(string(csr.ToPEM()))
			}
		} else if location.IsCertificate() {
			for _, certificate := range location.Certificates {
				if certificate.Error() != nil {
					slog.Error(certificate.Error().Error())
					fmt.Println(certificate.Error())
					continue
				}
				fmt.Print(string(certificate.ToPEM()))
			}

			if printChains {
				chains, err := location.Chains()
				if err != nil {
					slog.Error(fmt.Sprintf("chains for %s: %v", location.Name(), err))
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

// ExpiryUnified prints expiry information for certificate locations (CSRs don't have expiry)
func ExpiryUnified(locations []cert.Location) {
	for _, location := range locations {
		if location.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", location.Name(), location.Error))
			fmt.Printf("%s: ERROR: %v\n", location.Name(), location.Error)
			continue
		}

		// Only certificates have expiry dates, skip CSRs
		if location.IsCertificate() {
			for _, certificate := range location.Certificates {
				if certificate.Error() != nil {
					slog.Error(certificate.Error().Error())
					fmt.Printf("%s: %s\n", location.Name(), certificate.Error())
					continue
				}

				fmt.Printf("%s: %s\n", location.Name(), NotAfterDate(certificate.NotAfter()))
			}
		} else if location.IsCSR() {
			fmt.Printf("%s: CSR (no expiry)\n", location.Name())
		}
	}
}
