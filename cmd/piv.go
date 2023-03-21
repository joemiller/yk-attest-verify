package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/joemiller/yk-attest-verify/pkg/piv"
	"github.com/joemiller/yk-attest-verify/pkg/pubkeys"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// pivCmd represents the PIV attestion verification sub command
var pivCmd = &cobra.Command{
	Use:   "piv ATTESTATION SIGNER",
	Short: "Verify the signature and contents of a YuibKey PIV Attestation certificate.",
	Long:  "Verify the signature and contents of a YuibKey PIV Attestation certificate.",
	Example: indentor(`
# verify the signature chain of an attestation certificate:
yk-attest-verify piv attestation.pem signer.pem

# also verify the public key in an ssh public key file matches the public key in the attestation:
yk-attest-verify piv attestation.pem signer.pem --ssh-pub-key="id_rsa.pub"

# policy: verify the attested key has an allowed Touch Policy set:
yk-attest-verify piv attestation.pem signer.pem --allowed-touch-policies="always,cached"

# policy: verify the attested key has an allowed PIN Policy set:
yk-attest-verify piv attestation.pem signer.pem --allowed-touch-policies="once,always"
	`),
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE:         pivVerify,
}

func init() {
	// policy flags (--allowed-*)
	pivCmd.Flags().StringSlice(
		"allowed-slots",
		[]string{},
		"Comma-separated list of allowed key Slots. If not set all slots are accepted. (9a,9c,9d,9e)",
	)

	pivCmd.Flags().StringSlice(
		"allowed-pin-policies",
		[]string{},
		"Comma-separated list of allowed PIN policies. If not set any source is accepted. (never,once,always)",
	)

	pivCmd.Flags().StringSlice(
		"allowed-touch-policies",
		[]string{},
		"Comma-separated list of allowed touch policies. If not set all policies are accepted. (never,always,cached)",
	)

	pivCmd.Flags().String(
		"ssh-pub-key",
		"",
		"Verify an ssh public key file contains the same public key as the attestation certificate",
	)

	rootCmd.AddCommand(pivCmd)
}

func pivVerify(cmd *cobra.Command, args []string) error {
	// these are guaranteed to exist by the ExactArgs(2) in the pivCmd struct
	attestCertFile := args[0]
	attestSignerFile := args[1]

	attestCert, err := loadX509CertFile(attestCertFile)
	if err != nil {
		return err
	}

	attestSigner, err := loadX509CertFile(attestSignerFile)
	if err != nil {
		return err
	}

	sshPubKeyFile, err := cmd.Flags().GetString("ssh-pub-key")
	if err != nil {
		return err
	}

	var sshPubKey ssh.PublicKey
	if sshPubKeyFile != "" {
		pubkeyraw, err := os.ReadFile(sshPubKeyFile)
		if err != nil {
			return fmt.Errorf("Error reading SSH pub key %s: %w", sshPubKeyFile, err)
		}
		sshPubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubkeyraw)
		if err != nil {
			return fmt.Errorf("Error parsing SSH pub key %s: %w", sshPubKeyFile, err)
		}
	}

	verifyReq := piv.VerificationRequest{
		AttestCert:       attestCert,
		AttestSignerCert: attestSigner,
	}
	if val, err := cmd.Flags().GetStringSlice("allowed-slots"); err == nil {
		for _, i := range val {
			i = strings.ToLower(i)
			switch i {
			case "9a", "9c", "9d", "9e":
				verifyReq.Policy.AllowedSlots = append(verifyReq.Policy.AllowedSlots, piv.Slot(i))
			default:
				return fmt.Errorf("--allowed-slots unknown slot name '%v'", i)
			}
		}
	}

	if val, err := cmd.Flags().GetStringSlice("allowed-pin-policies"); err == nil {
		for _, i := range val {
			i = strings.ToLower(i)
			switch i {
			case "never":
				verifyReq.Policy.AllowedPINPolicies = append(verifyReq.Policy.AllowedPINPolicies, piv.PINPolicyNever)
			case "once":
				verifyReq.Policy.AllowedPINPolicies = append(verifyReq.Policy.AllowedPINPolicies, piv.PINPolicyOnce)
			case "always":
				verifyReq.Policy.AllowedPINPolicies = append(verifyReq.Policy.AllowedPINPolicies, piv.PINPolicyAlways)
			default:
				return fmt.Errorf("--allowed-pin-policies unknown policy '%v'", i)
			}
		}
	}

	if val, err := cmd.Flags().GetStringSlice("allowed-touch-policies"); err == nil {
		for _, i := range val {
			i = strings.ToLower(i)
			switch i {
			case "never":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, piv.TouchPolicyNever)
			case "always":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, piv.TouchPolicyAlways)
			case "cached":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, piv.TouchPolicyCached)
			default:
				return fmt.Errorf("--allowed-touch-policies unknown policy '%v'", i)
			}
		}
	}

	errors := false

	attestation, err := piv.VerifyAttestation(verifyReq)
	if attestation != nil {
		printPIVAttestation(cmd.OutOrStdout(), attestation)
	}

	cmd.Println("\nAttestation Policy Checks:")
	if err == nil {
		cmd.Println("✔ All policy checks OK")
	} else {
		errors = true
		verifyErrs, ok := err.(piv.VerificationErrors)
		if !ok {
			return err
		}
		for _, e := range verifyErrs {
			cmd.Println("✖", e)
		}
	}

	// if --ssh-pub-key=file was specified, compare it to the public key in the attestation
	if sshPubKey != nil {
		cmd.Printf("\nSSH public key file '%s':\n", sshPubKeyFile)

		if pubkeys.Compare(sshPubKey, attestCert.PublicKey) {
			cmd.Println("✔ SSH public key file matches attestation public key")
		} else {
			errors = true
			sshFP := ssh.FingerprintSHA256(sshPubKey)
			certSSHpub, err := ssh.NewPublicKey(attestCert.PublicKey)
			certFP := ssh.FingerprintSHA256(certSSHpub)

			if err != nil {
				cmd.Printf("✖ Unable to parse attestation cert public key: %v\n", err)
			} else {
				cmd.Printf("✖ SSH public key (%s) does not match attestation public key (%s)\n", sshFP, certFP)
			}
		}
	}

	if errors {
		os.Exit(1)
	}

	return nil
}

func printPIVAttestation(w io.Writer, attestation *piv.Attestation) {
	fmt.Fprintln(w, "YubiKey PIV Attestation:")
	fmt.Fprintf(w, " - Key slot       : %s\n", attestation.Slot)
	fmt.Fprintf(w, " - YubiKey Version: v%d.%d.%d\n", attestation.Version.Major, attestation.Version.Minor, attestation.Version.Patch)
	fmt.Fprintf(w, " - Serial #       : %d\n", attestation.Serial)
	fmt.Fprintf(w, " - Formfactor     : %s\n", attestation.Formfactor)
	fmt.Fprintf(w, " - PIN Policy     : %s\n", attestation.PINPolicy)
	fmt.Fprintf(w, " - Touch Policy   : %s\n", attestation.TouchPolicy)
}
