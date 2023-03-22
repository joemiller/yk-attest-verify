package pgp

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
//     YubiKey OPGP Attestation -> (this key+crt is stored on the yubikey)
//       Attestation Cert          (an attestation covering the key in one of the
//                                  slots on the yubikey, eg: an Auth, Sign, or Encrypt key)
//
func TestVerify_NotSignedByYubiCoRoot(t *testing.T) {
	rootA := fakeYubiRoot(t)
	rootB := fakeYubiRoot(t)
	signer := fakeAttestSigner(t, rootB)
	v := verifier{Root: rootA.Certificate}

	attestationCert := makeOPGPAttestationCert(t, signer, opgpAttestation{})
	req := VerificationRequest{
		AttestCert:       attestationCert,
		AttestSignerCert: signer.Certificate,
	}

	_, err := v.verify(req)
	assert.NotNil(t, err)

	verifyErrs := err.(VerificationErrors)
	assert.Contains(t, verifyErrs, errors.New("attestation signer certificate is not signed by the YubiCo OpenPGP Root CA: crypto/rsa: verification error"))
}

func TestVerify_NotSignedByOnDeviceAttestationKey(t *testing.T) {
	root := fakeYubiRoot(t)
	signerA := fakeAttestSigner(t, root)
	signerB := fakeAttestSigner(t, root)
	v := verifier{Root: root.Certificate}

	attestationCert := makeOPGPAttestationCert(t, signerB, opgpAttestation{})
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
		attestContents opgpAttestation
		policy         Policy
		expectedErrs   *VerificationErrors
	}{
		{
			name:           "empty policies passes policy test",
			attestContents: opgpAttestation{},
			policy:         Policy{},
			expectedErrs:   nil,
		},
		{
			name: "allowed touch policy passes policy test",
			attestContents: opgpAttestation{
				touchpolicy: TouchPolicyPermanent,
			},
			policy: Policy{
				AllowedTouchPolicies: []TouchPolicy{TouchPolicyPermanent},
			},
			expectedErrs: nil,
		},
		{
			name: "dis-allowed touch policy fails policy test",
			attestContents: opgpAttestation{
				touchpolicy: TouchPolicyDisabled,
			},
			policy: Policy{
				AllowedTouchPolicies: []TouchPolicy{TouchPolicyEnabled},
			},
			expectedErrs: &VerificationErrors{errors.New("Touch Policy 'Disabled' is not allowed")},
		},
		{
			name: "allowed key source passes policy test",
			attestContents: opgpAttestation{
				keysource: KeysourceGenerated,
			},
			policy: Policy{
				AllowedKeySources: []Keysource{KeysourceGenerated},
			},
			expectedErrs: nil,
		},
		{
			name: "dis-allowed key source fails policy test",
			attestContents: opgpAttestation{
				keysource: KeysourceImported,
			},
			policy: Policy{
				AllowedKeySources: []Keysource{KeysourceGenerated},
			},
			expectedErrs: &VerificationErrors{errors.New("Key Source 'Imported' is not allowed")},
		},
		{
			name: "allowed key slots passes policy test",
			attestContents: opgpAttestation{
				slot: SlotEncrypt,
			},
			policy: Policy{
				AllowedSlots: []Slot{SlotEncrypt},
			},
			expectedErrs: nil,
		},
		{
			name: "disallowed key slots fails policy test",
			attestContents: opgpAttestation{
				slot: SlotEncrypt,
			},
			policy: Policy{
				AllowedSlots: []Slot{SlotAuthenticate},
			},
			expectedErrs: &VerificationErrors{errors.New("Slot 'ENC' not allowed by policy")},
		},
		{
			name: "allowed cardholder name passes policy test",
			attestContents: opgpAttestation{
				cardholder: "Alice Crypto",
			},
			policy: Policy{
				AllowedCardholders: []string{"Alice Crypto"},
			},
			expectedErrs: nil,
		},
		{
			name: "disallowed cardholder name fails policy test",
			attestContents: opgpAttestation{
				cardholder: "Bob Hacker",
			},
			policy: Policy{
				AllowedCardholders: []string{"Alice Crypto"},
			},
			expectedErrs: &VerificationErrors{errors.New("Unexpected cardholder 'Bob Hacker'")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attestationCert := makeOPGPAttestationCert(t, signer, tc.attestContents)

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
