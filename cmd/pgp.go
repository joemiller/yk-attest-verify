package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/joemiller/yk-attest-verify/pkg/pgp"
	"github.com/joemiller/yk-attest-verify/pkg/pubkeys"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// pgpCmd represents the PGP attestion verification sub command
var pgpCmd = &cobra.Command{
	Use:   "pgp ATTESTATION SIGNER",
	Short: "Verify the signature and contents of a YuibKey OpenPGP Attestation certificate.",
	Long:  "Verify the signature and contents of a YuibKey OpenPGP Attestation certificate.",
	Example: indentor(`
# verify the signature chain of an attestation certificate:
yk-attest-verify pgp attestation.pem signer.pem

# also verify the public key in an ssh public key file matches the public key in the attestation:
yk-attest-verify pgp attestation.pem signer.pem --ssh-pub-key="id_rsa.pub"

# policy: verify the attested key was generated on the YubiKey:
yk-attest-verify pgp attestation.pem signer.pem --allowed-keysources="generated"

# policy: verify the attested key has an allowed Touch Policy set:
yk-attest-verify pgp attestation.pem signer.pem --allowed-touch-policies="enabled,cached"
	`),
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE:         pgpVerify,
}

func init() {
	// policy flags (--allowed-*)
	pgpCmd.Flags().StringSlice(
		"allowed-slots",
		[]string{},
		"Comma-separated list of allowed key Slots. If not set all slots are accepted. (SIG,ENC,AUT)",
	)

	pgpCmd.Flags().StringSlice(
		"allowed-keysources",
		[]string{},
		"Comma-separated list of allowed key sources. If not set any source is accepted. (generated,imported)",
	)

	pgpCmd.Flags().StringSlice(
		"allowed-touch-policies",
		[]string{},
		"Comma-separated list of allowed touch policies. If not set all policies are accepted. (disabled,enabled,enabled-permanent,enabled-cached,enabled-permanent-cached)",
	)

	pgpCmd.Flags().StringSlice(
		"allowed-cardholders",
		[]string{},
		"Comma-separated list of accepted card holder names. If not set all policies are accepted.",
	)

	pgpCmd.Flags().String(
		"ssh-pub-key",
		"",
		"Verify an ssh public key file contains the same public key as the attestation certificate",
	)

	rootCmd.AddCommand(pgpCmd)
}

func pgpVerify(cmd *cobra.Command, args []string) error {
	// these are guaranteed to exist by the ExactArgs(2) in the pgpCmd struct
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
		pubkeyraw, err := ioutil.ReadFile(sshPubKeyFile)
		if err != nil {
			return fmt.Errorf("Error reading SSH pub key %s: %w", sshPubKeyFile, err)
		}
		sshPubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubkeyraw)
		if err != nil {
			return fmt.Errorf("Error parsing SSH pub key %s: %w", sshPubKeyFile, err)
		}
	}

	verifyReq := pgp.VerificationRequest{
		AttestCert:       attestCert,
		AttestSignerCert: attestSigner,
	}
	if val, err := cmd.Flags().GetStringSlice("allowed-slots"); err == nil {
		for _, i := range val {
			i = strings.ToUpper(i)
			switch i {
			case "AUT", "SIG", "ENC":
				verifyReq.Policy.AllowedSlots = append(verifyReq.Policy.AllowedSlots, pgp.Slot(i))
			default:
				return fmt.Errorf("--allowed-slots unknown slot name '%v'", i)
			}
		}
	}

	if val, err := cmd.Flags().GetStringSlice("allowed-keysources"); err == nil {
		for _, i := range val {
			i = strings.ToLower(i)
			switch i {
			case "imported":
				verifyReq.Policy.AllowedKeySources = append(verifyReq.Policy.AllowedKeySources, pgp.KeysourceImported)
			case "generated":
				verifyReq.Policy.AllowedKeySources = append(verifyReq.Policy.AllowedKeySources, pgp.KeysourceGenerated)
			default:
				return fmt.Errorf("--allowed-keysource unknown keysource '%v'", i)
			}
		}
	}

	if val, err := cmd.Flags().GetStringSlice("allowed-touch-policies"); err == nil {
		for _, i := range val {
			i = strings.ToLower(i)
			switch i {
			case "disabled":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, pgp.TouchPolicyDisabled)
			case "enabled":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, pgp.TouchPolicyEnabled)
			case "enabled-permanent":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, pgp.TouchPolicyPermanent)
			case "enabled-cached":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, pgp.TouchPolicyCached)
			case "enabled-permanent-cached":
				verifyReq.Policy.AllowedTouchPolicies = append(verifyReq.Policy.AllowedTouchPolicies, pgp.TouchPolicyPermanentCached)
			default:
				return fmt.Errorf("--allowed-touch-policies unknown policy '%v'", i)
			}
		}
	}

	if val, err := cmd.Flags().GetStringSlice("allowed-cardholders"); err == nil {
		for _, i := range val {
			verifyReq.Policy.AllowedCardholders = append(verifyReq.Policy.AllowedCardholders, i)
		}
	}

	errors := false

	attestation, err := pgp.VerifyAttestation(verifyReq)
	if attestation != nil {
		printPGPAttestation(cmd.OutOrStdout(), attestation)
	}

	cmd.Println("\nAttestation Policy Checks:")
	if err == nil {
		cmd.Println("✔ All policy checks OK")
	} else {
		errors = true
		verifyErrs, ok := err.(pgp.VerificationErrors)
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

func printPGPAttestation(w io.Writer, attestation *pgp.Attestation) {
	fmt.Fprintln(w, "YubiKey OPGP Attestation:")
	fmt.Fprintf(w, " - Generation Date: %s\n", attestation.GenerationDate)
	fmt.Fprintf(w, " - Cardholder     : %s\n", attestation.Cardholder)
	fmt.Fprintf(w, " - Key slot       : %s\n", attestation.Slot)
	fmt.Fprintf(w, " - Key source     : %s\n", attestation.Keysource)
	fmt.Fprintf(w, " - Key fingerprint: %s\n", attestation.Fingerprint)
	fmt.Fprintf(w, " - YubiKey Version: v%d.%d.%d\n", attestation.Version.Major, attestation.Version.Minor, attestation.Version.Patch)
	fmt.Fprintf(w, " - Serial #       : %d\n", attestation.Serial)
	fmt.Fprintf(w, " - Formfactor     : %s\n", attestation.Formfactor)
	fmt.Fprintf(w, " - Touch Policy   : %s\n", attestation.TouchPolicy)
}
