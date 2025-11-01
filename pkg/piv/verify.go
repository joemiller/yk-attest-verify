// Portions of code from https://github.com/go-piv/piv-go/blob/e6548dd11f020eb8a3922086893dee86537b47ce/piv/key.go are
// reproduced here and modified. Motivations for this are:
//   - avoid having to link against platform native smartcard libraries such as pcsc
//     which is not needed for attestation certificate parsing.
//   - Conform to the interface desired by the yk-attest-verify application.
// The copyright notice is included below:

// Copyright 2020 Google LLC
// Modifications 2020 Joe Miller
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// Policy represents a set of allowed contents of a YubiKey PIV attestation certificate.
type Policy struct {
	AllowedSlots         []Slot
	AllowedPINPolicies   []PINPolicy
	AllowedTouchPolicies []TouchPolicy
}

// VerificationRequest contains a Yubikey Attestation certificate signed by a
// attestation signer key.
//
// Attestation (AttestCert) certs can be generated with the `yubico-piv-tool` utility
//
//    # generate an attestation cert against the 9a slot:
//     yubico-piv-tool --action=attest --slot=9a >piv-attest.pem
//
//    # export the signer cert:
//     yubico-piv-tool --action=read-certificate --slot=f9 >piv-attestation-signer.pem
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
	// Try old root first, then new root with intermediates
	err := verifySignature(root, req.AttestSignerCert)
	if err == nil {
		// Old chain verification succeeded
		goto verifyCert
	}

	// If old root fails, try the new certificate chain:
	// Root -> Attestation Intermediate B 1 -> PIV Attestation B 1 -> Device Signer
	if err := v.tryNewCertChain(req.AttestSignerCert); err == nil {
		// New chain verification succeeded
		goto verifyCert
	}

	// Both chains failed
	errs = append(errs, fmt.Errorf("attestation signer certificate is not signed by YubiCo PIV Root CA: %v", err))

verifyCert:
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

	if len(req.Policy.AllowedPINPolicies) > 0 {
		found := false
		for _, pol := range req.Policy.AllowedPINPolicies {
			if attestation.PINPolicy == pol {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("PIN Policy '%v' is not allowed", attestation.PINPolicy))
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

	pivInt, err := yubicoPIVIntermediate()
	if err != nil {
		return err
	}

	// Verify: new root -> attestation intermediate B
	if err := verifySignature(newRoot, attestInt); err != nil {
		return err
	}

	// Verify: attestation intermediate B -> PIV intermediate
	if err := verifySignature(attestInt, pivInt); err != nil {
		return err
	}

	// Verify: PIV intermediate -> attestation signer cert
	return verifySignature(pivInt, signerCert)
}

// yubicoPIVCAPEM is the legacy PEM encoded attestation certificate used by Yubico for PIV keys.
// This is the original root CA used by older YubiKeys (pre-2024).
//
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
// https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
const yubicoPIVCAPEM = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
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
// Chain: Root -> Attestation Intermediate B 1 -> PIV Attestation B 1 -> Device Signer
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

// yubicoPIVIntermediatePEM contains the PIV intermediate certificate used in the new cert chain.
// This intermediate is signed by Yubico Attestation Intermediate B 1 which is signed by
// Yubico Attestation Root 1, and signs the device attestation signers.
//
// https://developers.yubico.com/PKI/yubico-intermediate.pem
const yubicoPIVIntermediatePEM = `-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUWVf2oJG+t1qP8t8TicWgJ2KYan4wDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBC
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCUxIzAhBgNVBAMM
Gll1YmljbyBQSVYgQXR0ZXN0YXRpb24gQiAxMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAv7WBL9/5AKxSpCMoL63183WqRtFrOHY7tdyuGtoidoYWQrxV
aV9S+ZwH0aynh0IzD5A/PvCtuxdtL5w2cAI3tgsborOlEert4IZ904CZQfq3ooar
1an/wssbtMpPOQkC3MQiqrUyHlFS2BTbuwbBXY66lSVX/tGRuUgnBdfBJtcQKS6M
O4bU5ndPQqhGPyzcyY1LvlfzK7KJ1r/bixCRFqjhJRnPs0Czpg6rkRrFgC6cd5bK
1UgTsJy+3wrIqkv4CeV3EhSVnhnQjZgIrdIcI5WZ8T1Oq3OhMlWmY0K0dy/oZdP/
bpbG2qbyHLa6gprLT/qChQWLmffxn6D2DAB1zQIDAQABo2YwZDAdBgNVHQ4EFgQU
M0Nt3QHo7eGzaKMZn2SmXT74vpcwHwYDVR0jBBgwFoAU6rdCkJ4Me2R621R8A7p8
Tp/YoWEwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
hvcNAQELBQADggEBAI0HwoS84fKMUyIof1LdUXvyeAMmEwW7+nVETvxNNlTMuwv7
zPJ4XZAm9Fv95tz9CqZBj6l1PAPQn6Zht9LQA92OF7W7buuXuxuusBTgLM0C1iX2
CGXqY/k/uSNvi3ZYfrpd44TIrfrr8bCG9ux7B5ZCRqb8adDUm92Yz3lK1aX2M6Cw
jC9IZVTXQWhLyP8Ys3p7rb20CO2jJzV94deJ/+AsEb+bnCQImPat1GDKwrBosar+
BxtU7k6kgkxZ0G384O59GFXqnwkbw2b5HhORvOsX7nhOUhePFufzi1vT1g8Tzbwr
+TUfTwo2biKHHcI762KGtp8o6Bcv5y8WgExFuWY=
-----END CERTIFICATE-----`

func yubicoCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPIVCAPEM))
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

func yubicoPIVIntermediate() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPIVIntermediatePEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico PIV intermediate pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}
