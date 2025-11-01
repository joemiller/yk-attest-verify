package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
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

type result struct {
	Cmd  *cobra.Command
	JSON bool
	Data struct {
		Attestation interface{}
		Error       *resultError
	}
}

type resultError struct {
	Messages []string
}

func (e *resultError) Add(msg string) {
	e.Messages = append(e.Messages, msg)
}

func (e *resultError) MarshalJSON() ([]byte, error) {
	if e.Messages == nil {
		// Make sure JSON ends up as an empty array, not null.
		return json.Marshal(make([]string, 0))
	}
	return json.Marshal(e.Messages)
}

// Wrap cobra.Command.Printf(), only running it if not in JSON mode.
func (o *result) Printf(s string, a ...interface{}) {
	if !o.JSON {
		o.Cmd.Printf(s, a...)
	}
}

func (o *result) PrintE(s string) {
	if o.JSON {
		o.Data.Error.Add(s)
	} else {
		o.Cmd.Printf("✖ %s\n", s)
	}
}

func (o *result) PrintResultJSON(attestation interface{}) error {
	o.Data.Attestation = attestation
	data, err := json.MarshalIndent(o.Data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintf(o.Cmd.OutOrStdout(), "%s\n", data) //nolint:errcheck
	return nil
}
