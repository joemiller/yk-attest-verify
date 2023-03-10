package piv

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

/* test cases:

# test the certificate chains:
x 1. test attestation cert not signed by the correct attestation signer
x 2. test the attestation signer is not signed by the yubico root

# test policy assertions:
1. touch policy (none, one, multiple)
2. keysources policy (generated, imported)
3. allowed slots (aut, sign, enc)
4. allowed card holder (none, one, multiple)
*/

// TestVerify_NotSignedByYubiCoRoot:
// TestVerify_NotSignedByOnDeviceAttestationKey:
//
// test the certificate chains. The signature chain of a yubikey attestation cert
// looks like:
//   yubico root ->
//     YubiKey PIV Attestation -> (this key+crt is stored on the yubikey)
//       Attestation Cert          (an attestation covering the key in one of the
//                                  slots on the yubikey)
//
func TestVerify_NotSignedByYubiCoRoot(t *testing.T) {
	rootA := fakeYubiRoot(t)
	rootB := fakeYubiRoot(t)
	signer := fakeAttestSigner(t, rootB)
	v := verifier{Root: rootA.Certificate}

	attestationCert := makePIVAttestationCert(t, signer, pivAttestation{})
	req := VerificationRequest{
		AttestCert:       attestationCert,
		AttestSignerCert: signer.Certificate,
	}

	_, err := v.verify(req)
	assert.NotNil(t, err)

	verifyErrs := err.(VerificationErrors)
	assert.Contains(t, verifyErrs, errors.New("attestation signer certificate is not signed by YubiCo PIV Root CA: crypto/rsa: verification error"))
}

func TestVerify_NotSignedByOnDeviceAttestationKey(t *testing.T) {
	root := fakeYubiRoot(t)
	signerA := fakeAttestSigner(t, root)
	signerB := fakeAttestSigner(t, root)
	v := verifier{Root: root.Certificate}

	attestationCert := makePIVAttestationCert(t, signerB, pivAttestation{})
	req := VerificationRequest{
		AttestCert:       attestationCert,
		AttestSignerCert: signerA.Certificate,
	}

	_, err := v.verify(req)
	assert.NotNil(t, err)

	verifyErrs := err.(VerificationErrors)
	assert.Contains(t, verifyErrs, errors.New("attestation certificate not signed by device's attestation signer key: crypto/rsa: verification error"))
}

func TestVerify_Policies(t *testing.T) {
	root := fakeYubiRoot(t)
	signer := fakeAttestSigner(t, root)
	v := verifier{Root: root.Certificate}

	// NOTE: all of these tests assume the signature chain is valid
	tests := []struct {
		name           string
		attestContents pivAttestation
		policy         Policy
		expectedErrs   *VerificationErrors
	}{
		{
			name:           "empty policies passes policy test",
			attestContents: pivAttestation{},
			policy:         Policy{},
			expectedErrs:   nil,
		},
		{
			name: "allowed touch policy passes policy test",
			attestContents: pivAttestation{
				touchpolicy: TouchPolicyAlways,
			},
			policy: Policy{
				AllowedTouchPolicies: []TouchPolicy{TouchPolicyAlways},
			},
			expectedErrs: nil,
		},
		{
			name: "dis-allowed touch policy fails policy test",
			attestContents: pivAttestation{
				touchpolicy: TouchPolicyNever,
			},
			policy: Policy{
				AllowedTouchPolicies: []TouchPolicy{TouchPolicyAlways},
			},
			expectedErrs: &VerificationErrors{errors.New("Touch Policy 'Never' is not allowed")},
		},
		{
			name: "allowed key slots passes policy test",
			attestContents: pivAttestation{
				slot: SlotSignature,
			},
			policy: Policy{
				AllowedSlots: []Slot{SlotSignature},
			},
			expectedErrs: nil,
		},
		{
			name: "disallowed key slots fails policy test",
			attestContents: pivAttestation{
				slot: SlotSignature,
			},
			policy: Policy{
				AllowedSlots: []Slot{SlotAuthenticate},
			},
			expectedErrs: &VerificationErrors{errors.New("Slot '9c' not allowed by policy")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attestationCert := makePIVAttestationCert(t, signer, tc.attestContents)

			req := VerificationRequest{
				AttestCert:       attestationCert,
				AttestSignerCert: signer.Certificate,
				Policy:           tc.policy,
			}
			_, err := v.verify(req)
			// spew.Dump(err)

			if tc.expectedErrs == nil {
				assert.Nil(t, err)
			} else {
				verifyErrs := err.(VerificationErrors)
				assert.Equal(t, *tc.expectedErrs, verifyErrs)
			}
		})
	}
}
