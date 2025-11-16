package print

import (
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"log/slog"
	"strings"
)

func CSRLocations(csrLocations []cert.CSRLocation, printPem, printExtensions, printSignature bool) {
	for _, csrLocation := range csrLocations {
		if csrLocation.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", csrLocation.Name(), csrLocation.Error))
			fmt.Printf("--- [%s: %v] ---\n", csrLocation.Name(), csrLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", csrLocation.Name())
		printCSRs(csrLocation.CSRs, printPem, printExtensions, printSignature)
	}
}

func printCSRs(csrs cert.CSRs, printPem, printExtensions, printSignature bool) {
	for _, csr := range csrs {
		printCSR(csr, printExtensions, printSignature)
		fmt.Println()
		if printPem {
			fmt.Println(string(csr.ToPEM()))
		}
	}
}

func printCSR(csr cert.CSR, printExtensions, printSignature bool) {
	if csr.Error() != nil {
		slog.Error(csr.Error().Error())
		fmt.Println(csr.Error())
		return
	}

	fmt.Printf("%s: %d\n", AttributeName("Version"), csr.Version())
	fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), csr.SignatureAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Subject"), csr.SubjectString())
	fmt.Printf("%s: %s\n", AttributeName("DNS Names"), strings.Join(csr.DNSNames(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("IP Addresses"), strings.Join(csr.IPAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Email Addresses"), strings.Join(csr.EmailAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("URIs"), strings.Join(csr.URIs(), ", "))
	fmt.Printf("%s\n", AttributeName("Public Key"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Algorithm"), csr.PublicKeyAlgorithm())

	if printExtensions {
		fmt.Printf("%s:\n", AttributeName("Extensions"))
		for _, extension := range csr.Extensions() {
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

	if printSignature {
		fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), csr.SignatureAlgorithm())
		fmt.Printf("%s\n", AttributeName("Signature Value"))
		for _, line := range splitString(csr.Signature(), "    ", 54) {
			fmt.Println(line)
		}
	}
}
