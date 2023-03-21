package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var app = "yk-attest-verify"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   app,
	Short: "Validate and enforce policy on YubiKey PIV and OpenPGP attestation certificates.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
