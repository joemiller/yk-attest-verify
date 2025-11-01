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
//	# create an attestation cert covering the key in the authentication (AUT) key slot
//	 ykman openpgp attest AUT attest.pem
//
//	# export the attestation (ATT) singer cert used to sign the cert above.
//	ykman openpgp attest AUT signer.pem
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
//
//	errs := err.(VerificationErrors)
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
		// Try verifying with the old root CA first
		ca, err := yubicoCA()
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing YubiCo Root CA: %v", err))
			return nil, errs
		}
		root = ca
	}

	// Verify signatures:
	// The Attestation Signer Cert from the yubikey must be signed by YubiCo's attestation root
	// Try old root first, then new root with intermediates
	err := verifySignature(root, req.AttestSignerCert)
	if err == nil {
		// Old chain verification succeeded
		goto verifyCert
	}

	// If old root fails, try the new certificate chain:
	// Root -> Attestation Intermediate B 1 -> OPGP Attestation B 1 -> Device Signer
	if err := v.tryNewCertChain(req.AttestSignerCert); err == nil {
		// New chain verification succeeded
		goto verifyCert
	}

	// Both chains failed
	errs = append(errs, fmt.Errorf("attestation signer certificate is not signed by the YubiCo OpenPGP Root CA: %v", err))

verifyCert:
	// The Attestation Cert must be signed by the Attestation Signer Cert
	if err := verifySignature(req.AttestSignerCert, req.AttestCert); err != nil {
		errs = append(errs, fmt.Errorf("attestation certificate not signed by device's attestation signer key: %v", err))
	}

	attestation, err := ParseAttestation(req.AttestCert)
	if err != nil {
		errs = append(errs, fmt.Errorf("unable to parse attestation cert: %v", err))
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

// tryNewCertChain attempts to verify the attestation signer cert using the new (2024+) certificate chain.
// Returns nil if verification succeeds, error otherwise.
func (v *verifier) tryNewCertChain(signerCert *x509.Certificate) error {
	// Load all certificates in the new chain
	newRoot, err := yubicoNewRootCA()
	if err != nil {
		return err
	}

	attestInt, err := yubicoAttestationIntermediateB()
	if err != nil {
		return err
	}

	opgpInt, err := yubicoOPGPIntermediate()
	if err != nil {
		return err
	}

	// Verify: new root -> attestation intermediate B
	if err := verifySignature(newRoot, attestInt); err != nil {
		return err
	}

	// Verify: attestation intermediate B -> OPGP intermediate
	if err := verifySignature(attestInt, opgpInt); err != nil {
		return err
	}

	// Verify: OPGP intermediate -> attestation signer cert
	return verifySignature(opgpInt, signerCert)
}

// yubicoPGPCAPEM is the legacy PEM encoded attestation certificate used by Yubico for OpenPGP keys.
// This is the original root CA used by older YubiKeys (pre-2024).
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

// yubicoNewRootCAPEM is the new Yubico Attestation Root 1 issued on 2024-12-01.
// Newer YubiKeys (2024+) use a new certificate chain with this root.
//
// https://developers.yubico.com/PKI/yubico-ca-1.pem
const yubicoNewRootCAPEM = `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQEN
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0
dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXvl12LUhBZ5LmiBScI
Zd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G74b/
U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAu
csrbE485HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyC
imJukhYy6KoqNMKQEdpNiSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdw
MRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNmMGQwHQYDVR0OBBYEFNLu71oijTptXCOX
PfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOXPfKF1SbxJXuSMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4IB
AQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1
XnquB5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIF
TWeIhMNcZKsDZrFAyPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7V
olBNlld6pRFKlX8ust6OTMOeADl2xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3i
roRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/HqaUYCA/L8ldRk6H7Xk35D+W
Vpmq2Sh/xT5HiFuhf4wJb0bK
-----END CERTIFICATE-----`

// yubicoAttestationIntermediateBPEM is the middle intermediate in the new cert chain.
// Chain: Root -> Attestation Intermediate B 1 -> OPGP Attestation B 1 -> Device Signer
//
// https://developers.yubico.com/PKI/yubico-intermediate.pem
const yubicoAttestationIntermediateBPEM = `-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIUDqERw+4RnGSggxgUewJFEPDRZ3YwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowLjEsMCoGA1UEAwwjWXViaWNvIEF0
dGVzdGF0aW9uIEludGVybWVkaWF0ZSBCIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDI7XnH+ZvDwMCQU8M8ZeV5qscublvVYaaRt3Ybaxn9godLx5sw
H0lXrdgjh5h7FpVgCgYYX7E4bl1vbzULemrMWT8N3WMGUe8QAJbBeioV7W/E+hTZ
P/0SKJVa3ewKBo6ULeMnfQZDrVORAk8wTLq2v5Llj5vMj7JtOotKa9J7nHS8kLmz
XXSaj0SwEPh5OAZUTNV4zs1bvoTAQQWrL4/J9QuKt6WCFE5nUNiRQcEbVF8mlqK2
bx2z6okVltyDVLCxYbpUTELvY1usR3DTGPUoIClOm4crpwnDRLVHvjYePGBB//pE
yzxA/gcScxjwaH1ZUw9bnSbHyurKqbTa1KvjAgMBAAGjZjBkMB0GA1UdDgQWBBTq
t0KQngx7ZHrbVHwDunxOn9ihYTAfBgNVHSMEGDAWgBTS7u9aIo06bVwjlz3yhdUm
8SV7kjASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG
9w0BAQsFAAOCAQEAqQaCWMxTGqVVX7Sk7kkJmUueTSYKuU6+KBBSgwIRnlw9K7He
1IpxZ0hdwpPNikKjmcyFgFPzhImwHJgxxuT90Pw3vYOdcJJNktDg35PXOfzSn15c
FAx1RO0mPTmIb8dXiEWOpzoXvdwXDM41ZaCDYMT7w4IQtMyvE7xUBZq2bjtAnq/N
DUA7be4H8H3ipC+/+NKlUrcUh+j48K67WI0u1m6FeQueBA7n06j825rqDqsaLs9T
b7KAHAw8PmrWaNPG2kjKerxPEfecivlFawp2RWZvxrVtn3TV2SBxyCJCkXsND05d
CErVHSJIs+BdtTVNY9AwtyPmnyb0v4mSTzvWdw==
-----END CERTIFICATE-----`

// yubicoOPGPIntermediatePEM contains the intermediate certificate used in the new cert chain.
// This intermediate is signed by Yubico Attestation Intermediate B 1 which is signed by
// Yubico Attestation Root 1, and signs the device attestation signers.
//
// https://developers.yubico.com/PKI/yubico-intermediate.pem
const yubicoOPGPIntermediatePEM = `-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIUbeEhxjsv7XjQwdAQIi5G5i+4qhIwDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBC
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCYxJDAiBgNVBAMM
G1l1YmljbyBPUEdQIEF0dGVzdGF0aW9uIEIgMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMe9oJ6kuLQOlnUoyWzDaum4m23s3cR5jn0gVQSV6VPsQP8Q
d7wYiW/GiDUPAT4N/NqKdhcqX/5hazrbsKA+gCDU1E+zWunl0J0Fo5B0OCXQfxtA
0LhFHORvpJ1yz7HsRgEYScO7/rO2ip0bPbaKy4MG4UhyzKgzwmujOO7nmf6BcMil
8ZZRJbQOuEWsignM5EKuCrymyK3+R9Y+8NGjh/zb14Not9+JvwDgUYnHW+hip9si
UOzC2X8QYA/yBUCqTYGUePfC4ZOB0ZSi/HYtxhSnOTcDY6C+AcFnOCvCKD8t4Rdd
z6dFJINQgsATnfHycB22cUamIB9hBb9xXZYg36sCAwEAAaNmMGQwHQYDVR0OBBYE
FI1QCVLy1KcdxIkdZMMkn+wzyN0XMB8GA1UdIwQYMBaAFOq3QpCeDHtkettUfAO6
fE6f2KFhMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgGGMA0GCSqG
SIb3DQEBCwUAA4IBAQCRtalpNipOThRLO8o0/4WVLIjlC8yiPBLsVMuXHuXhTdhW
ubRUSazhHr7tTRShPJ/OeWiiap9aZtZe7FUgTIOdaR0oI4Tp5Cu4TUJTLQEUqtA9
HSU6bP485aRJi26hDD+h2AYplmEeVNEWj8PUIAp3N8mKMMqIkjB7d0QN14fze/Nb
REzHU6SVvuJo11jfHpJTfpbpCqvcVl8bMPUbdtOvqc1ibkj7O7OmTDACqTT1f3yQ
Zj0PbreP1qN9jv7kDAxT9O2yVSgXNXbz/Ygl121TkGWjXRQ8B3PW2Z3+n7B8ETAd
8fJ0/5guPgvO2VQHQv8H9U3tsqSq/siosMJ8KtS5
-----END CERTIFICATE-----`

func yubicoCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPGPCAPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}

func yubicoNewRootCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoNewRootCAPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode new yubico root CA pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}

func yubicoAttestationIntermediateB() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoAttestationIntermediateBPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico attestation intermediate B pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}

func yubicoOPGPIntermediate() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoOPGPIntermediatePEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico OPGP intermediate pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}
