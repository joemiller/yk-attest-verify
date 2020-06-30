package pgp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// Policy represents a set of allowed contents of a YubiKey OPGP attestation certificate.
type Policy struct {
	AllowedTouchPolicies []TouchPolicy
	AllowedKeySources    []Keysource
	AllowedSlots         []Slot
	AllowedCardholders   []string
}

// VerificationRequest contains a Yubikey Attestation certificate signed by a
// attestation signer key.
//
// Attestation (AttestCert) certs can be generated with the `ykman` utility and the
// `ykman openpgp attest` command. The AttestSignerCert used to sign the attestation cert (signer)
// can be exported from the Yubikey using the `ykman openpgp export-certificate ATT`:
//
//    # create an attestation cert covering the key in the authentication (AUT) key slot
//     ykman openpgp attest AUT attest.pem
//
//    # export the attestation (ATT) singer cert used to sign the cert above.
//    ykman openpgp attest AUT signer.pem
//
type VerificationRequest struct {
	AttestCert       *x509.Certificate
	AttestSignerCert *x509.Certificate
	Policy           Policy
}

// VerificationErrors holds errors representing policy violations from a verification request.
type VerificationErrors []error

// Error implements the error interface for VerificationErrors and returns a
// summary of the error messages. To inspect the list of errors individually you
// would cast the err to VerificationError and inspect the list.
//    errs := err.(VerificationErrors)
func (ve VerificationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}

	s := []string{}
	for _, e := range ve {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}

// VerifyAttestation verifies the signature chain of an attestation cert and evaluates
// the attributes in the attestation against a list of policies. If the cert chain
// is valid and all policy rules apply nil is returned. Otherwise an error that
// may be cast to .(VerificationErrors) will be returned. This accumulator contains
// a slice of one or more errors representing policy violations.
func VerifyAttestation(req VerificationRequest) (*Attestation, error) {
	var v verifier
	return v.verify(req)
}

type verifier struct {
	Root *x509.Certificate
}

func (v *verifier) verify(req VerificationRequest) (*Attestation, error) {
	var errs VerificationErrors

	root := v.Root
	if root == nil {
		ca, err := yubicoCA()
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing YubiCo Root CA: %v", err))
			return nil, errs
		}
		root = ca
	}

	// Verify signatures:
	// The Attestation Signer Cert from the yubikey must be signed by YubiCo's attestation root
	if err := verifySignature(root, req.AttestSignerCert); err != nil {
		errs = append(errs, fmt.Errorf("attestation signer certifcate is not signed by the YubiCo OpenPGP Root CA: %v", err))
	}
	// The Attestation Cert must be signed by the Attestation Signer Cert
	if err := verifySignature(req.AttestSignerCert, req.AttestCert); err != nil {
		errs = append(errs, fmt.Errorf("attestation certificate not signed by device's attestation signer key: %v", err))
	}

	attestation, err := ParseAttestation(req.AttestCert)
	if err != nil {
		errs = append(errs, fmt.Errorf("Unable to parse attestation cert: %v", err))
		return nil, errs
	}

	// Verify the attestation specifies an allowed TouchPolicy.
	if len(req.Policy.AllowedTouchPolicies) > 0 {
		found := false
		for _, pol := range req.Policy.AllowedTouchPolicies {
			if attestation.TouchPolicy == pol {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Touch Policy '%v' is not allowed", attestation.TouchPolicy))
		}
	}

	if len(req.Policy.AllowedKeySources) > 0 {
		found := false
		for _, src := range req.Policy.AllowedKeySources {
			if attestation.Keysource == src {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Key Source '%v' is not allowed", attestation.Keysource))
		}
	}

	if len(req.Policy.AllowedSlots) > 0 {
		found := false
		for _, slot := range req.Policy.AllowedSlots {
			if attestation.Slot == slot {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Slot '%v' not allowed by policy", attestation.Slot))
		}
	}

	if len(req.Policy.AllowedCardholders) > 0 {
		found := false
		for _, cardholder := range req.Policy.AllowedCardholders {
			if attestation.Cardholder == cardholder {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Unexpected cardholder '%v'", attestation.Cardholder))
		}
	}

	// check if errs is empty and if so return nil explicitly, otherwise
	// errs will always be != nil
	if len(errs) == 0 {
		return attestation, nil
	}
	return attestation, errs
}

func verifySignature(parent, c *x509.Certificate) error {
	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// yubicoPGPCAPEM is the PEM encoded attestation certificate used by Yubico for OpenPGP keys.
//
// https://developers.yubico.com/PGP/Attestation.html
// https://github.com/Yubico/developers.yubico.com/blob/master/content/PGP/Attestation.adoc
// https://developers.yubico.com/PGP/opgp-attestation-ca.pem
const yubicoPGPCAPEM = `-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIJAN0XtOvBoi4ZMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNV
BAMMHVl1YmljbyBPcGVuUEdQIEF0dGVzdGF0aW9uIENBMB4XDTE5MDgwMTAwMDAw
MFoXDTQ2MTIxNzAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIE9wZW5QR1AgQXR0
ZXN0YXRpb24gQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClkKck
+NEH+iSVLjbOvvreMlvkK4DZ7aETLusDfkEDy5+cv8SHtKSVcYfKhkST1l/5kbyx
WAnxLRr+aYP52830qkDfYY1OE/IQG76BdWaGZJuMU4cdUPQR21Y7JB+ELHNMQHav
3CmregKVqIRB6vgwWq/6AM37VKqKNTsBUmrAyihX/vY/kS3L1cP/NCPhUC9Gqab2
zohxXansjz92+4/dbN1cKDSGI8kVmoLpLbCf/CqGE4lWen0HxMCo/zIZo0nlGS7G
rEAqN+PRRwiemBZhwBzeYiCLkh7qaqO4O1eWCNLjkJeLwIZ/uyRTESbaFoXOxqFp
FjIyEjMYIdRXfaHVAgMBAAGjZjBkMB0GA1UdDgQWBBT7/MlvyfSnaal2RJH3cc8m
ZS4SSjAfBgNVHSMEGDAWgBT7/MlvyfSnaal2RJH3cc8mZS4SSjASBgNVHRMBAf8E
CDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAK+TP
HgYNIFTy+2PXpxmPVnNOcJRcVykAxaLJAAxey2BXy9xmU7lzHbl2x23Lw3kH7Crr
RqG67WGcwSZzvWWEcbq4zmX3vnu3FOFlqKFhU164tod4cXz1JGsTgfXaPRvoKJAo
XMotYH/u2UY/K8jmqycgEyHAFc9wx1v/q0H6p4WgbXLu2oBzRodHokgK/6EbIbR+
Jok3xJ+5haGcMCCz2A8RBah4dxPDNeaz3tSkAjrtwLANV79hAZv2g9CZX6z0H2Zy
HhK6CLTg2MfwT0NxS3Am76k2opXSqbk8k5nnNFSYFuvgxunQxUOB+3M+gWHmVTh8
7yaamyNndwmhhIAgeA==
-----END CERTIFICATE-----`

func yubicoCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPGPCAPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}
