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
	if err := verifySignature(root, req.AttestSignerCert); err != nil {
		errs = append(errs, fmt.Errorf("attestation signer certifcate is not signed by YubiCo PIV Root CA: %v", err))
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

// yubicoPIVCAPEM is the PEM encoded attestation certificate used by Yubico for PIV keys.
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

func yubicoCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPIVCAPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}
