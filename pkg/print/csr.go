package print

import (
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"log/slog"
	"strings"
)

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

	// the number and the encoding, as openssl shows it: the label has to mean
	// the same thing it does for a certificate, and the encoded value is still
	// what anyone comparing against the bytes will see
	fmt.Printf("%s: %d (0x%x)\n", AttributeName("Version"), csr.VersionNumber(), csr.Version())
	fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), csr.SignatureAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Subject"), csr.SubjectString())
	fmt.Printf("%s: %s\n", AttributeName("DNS Names"), strings.Join(csr.DNSNames(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("IP Addresses"), strings.Join(csr.IPAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Email Addresses"), strings.Join(csr.EmailAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("URIs"), strings.Join(csr.URIs(), ", "))
	fmt.Printf("%s\n", AttributeName("Public Key"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Algorithm"), csr.PublicKeyAlgorithm())

	// A request is signed by the key it asks to have certified, and that
	// signature is what binds everything above to that key. It is printed
	// whether or not it holds, since a reader has no way to tell otherwise.
	if err := csr.CheckSelfSignature(); err != nil {
		fmt.Printf("%s: %s\n", AttributeName("Self-Signature"), WarningText(err.Error()))
	} else {
		fmt.Printf("%s: %s\n", AttributeName("Self-Signature"), "verified against the key in the request")
	}

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
