package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
)

var indentation = `  `

func loadX509CertFile(certFile string) (*x509.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEMBlock)
	return x509.ParseCertificate(block.Bytes)
}

func indentor(s string) string {
	indentedLines := []string{}
	for _, line := range strings.Split(s, "\n") {
		// line = strings.TrimSpace(line)
		line = indentation + line
		indentedLines = append(indentedLines, line)
	}
	return strings.Join(indentedLines, "\n")
}
