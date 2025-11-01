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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
)

var (
	extIDFirmwareVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 3})
	extIDSerialNumber    = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 7})
	extIDKeyPolicy       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 8})
	extIDFormFactor      = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 9})
)

type Slot string

// Slot represents the YubiKey card slot that is covered by the attestation.
//
//	$ yubico-piv-tool -h
//	  9a is for PIV Authentication
//	  9c is for Digital Signature (PIN always checked)
//	  9d is for Key Management
//	  9e is for Card Authentication (PIN never checked)
//	  82-95 is for Retired Key Management
//	  f9 is for Attestation
const (
	SlotAuthenticate  = Slot("9a")
	SlotSignature     = Slot("9c")
	SlotKeyManagement = Slot("9d")
	SlotKeyCardAuth   = Slot("9e")
)

// Version encodes a major, minor, and patch version.
type Version struct {
	Major int
	Minor int
	Patch int
}

// Formfactor enumerates the physical set of forms a key can take. USB-A vs.
// USB-C and Keychain vs. Nano.
type Formfactor int

// Formfactors recognized by this package.
const (
	FormfactorUnspecified Formfactor = iota
	FormfactorUSBAKeychain
	FormfactorUSBANano
	FormfactorUSBCKeychain
	FormfactorUSBCNano
	FormfactorUSBCLightningKeychain
)

var formfactorNames = []string{
	FormfactorUnspecified:           "Unspecified",
	FormfactorUSBAKeychain:          "USB-A Keychain",
	FormfactorUSBANano:              "USB-A Nano",
	FormfactorUSBCKeychain:          "USB-C Keychain",
	FormfactorUSBCNano:              "USB-C Nano",
	FormfactorUSBCLightningKeychain: "USB-C + Lightning Keychain",
}

func (f Formfactor) String() string {
	return formfactorNames[f]
}

// MarshalJSON encodes value into String().
func (f Formfactor) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.String())
}

// PINPolicy represents PIN requirements when signing or decrypting with an
// asymmetric key in a given slot.
type PINPolicy int

// PIN policies supported by this package.
//
// BUG(ericchiang): Caching for PINPolicyOnce isn't supported on YubiKey
// versions older than 4.3.0 due to issues with verifying if a PIN is needed.
// If specified, a PIN will be required for every operation.
const (
	PINPolicyNever PINPolicy = iota + 1
	PINPolicyOnce
	PINPolicyAlways
)

var pinpolicyNames = []string{
	PINPolicyNever:  "Never",
	PINPolicyOnce:   "Once",
	PINPolicyAlways: "Always",
}

func (p PINPolicy) String() string {
	return pinpolicyNames[p]
}

// MarshalJSON encodes value into String().
func (p PINPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// TouchPolicy represents proof-of-presence requirements when signing or
// decrypting with asymmetric key in a given slot.
type TouchPolicy int

// Touch policies supported by this package.
const (
	TouchPolicyNever TouchPolicy = iota + 1
	TouchPolicyAlways
	TouchPolicyCached
)

var touchPolicyNames = []string{
	TouchPolicyNever:  "Never",
	TouchPolicyAlways: "Always",
	TouchPolicyCached: "Cached",
}

func (t TouchPolicy) String() string {
	return touchPolicyNames[t]
}

// MarshalJSON encodes value into String().
func (t TouchPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Attestation returns additional information about a key attested to be on a
// card.
type Attestation struct {
	// Slot is the key slot
	Slot Slot

	// Version of the YubiKey's firmware.
	Version Version

	// Serial is the YubiKey's serial number.
	Serial uint32

	// Formfactor indicates the physical type of the YubiKey.
	//
	// Formfactor may be empty Formfactor(0) for some YubiKeys.
	Formfactor Formfactor

	// PINPolicy set on the slot.
	PINPolicy PINPolicy

	// TouchPolicy set on the slot.
	TouchPolicy TouchPolicy
}

// ParseAttestation parses a YubiKey PIV attestation certificate and returns
// an Attestation.
func ParseAttestation(attestCert *x509.Certificate) (*Attestation, error) {
	var a Attestation
	for _, ext := range attestCert.Extensions {
		if err := a.addExt(ext); err != nil {
			return nil, fmt.Errorf("parsing extension: %v", err)
		}
	}
	slot, err := parseSlot(attestCert.Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf("parsing slot: %v", err)
	}
	a.Slot = slot
	return &a, nil
}

func (a *Attestation) addExt(e pkix.Extension) error {
	switch {
	case e.Id.Equal(extIDFirmwareVersion):
		// XXX(joe): unlike OPGP attestation certs that encode the version as 3 byte ASN.1 Octet-String
		//           the version in PIV attestations appears to lack any ASN.1 tag information, so we
		//           take the 3 bytes directly without any asn1.Unmarshal():
		// var version []byte
		// if _, err := asn1.Unmarshal(e.Value, &version); err != nil {
		// 	return fmt.Errorf("parsing version: %v", err)
		// }
		version := e.Value
		if len(version) != 3 {
			return fmt.Errorf("expected 3 bytes for firmware version, got: %d", len(version))
		}
		a.Version = Version{
			Major: int(version[0]),
			Minor: int(version[1]),
			Patch: int(version[2]),
		}

	case e.Id.Equal(extIDSerialNumber):
		var serial int64
		if _, err := asn1.Unmarshal(e.Value, &serial); err != nil {
			return fmt.Errorf("parsing serial number: %v", err)
		}
		if serial < 0 {
			return fmt.Errorf("serial number was negative: %d", serial)
		}
		a.Serial = uint32(serial)

	case e.Id.Equal(extIDKeyPolicy):
		// XXX(joe): keypolicy is encoded directly as 2 bytes. It is not marshaled into a specific ASN.1
		//           type, so we take the 2 bytes directly.
		// var keypolicy []byte
		// if _, err := asn1.Unmarshal(e.Value, &keypolicy); err != nil {
		// 	return fmt.Errorf("parsing keypolicy: %v", err)
		// }
		keypolicy := e.Value
		if len(keypolicy) != 2 {
			return fmt.Errorf("expected 2 bytes from key policy, got: %d", len(keypolicy))
		}
		switch keypolicy[0] {
		case 0x01:
			a.PINPolicy = PINPolicyNever
		case 0x02:
			a.PINPolicy = PINPolicyOnce
		case 0x03:
			a.PINPolicy = PINPolicyAlways
		default:
			return fmt.Errorf("unrecognized pin policy: 0x%x", keypolicy[0])
		}
		switch keypolicy[1] {
		case 0x01:
			a.TouchPolicy = TouchPolicyNever
		case 0x02:
			a.TouchPolicy = TouchPolicyAlways
		case 0x03:
			a.TouchPolicy = TouchPolicyCached
		default:
			return fmt.Errorf("unrecognized touch policy: 0x%x", keypolicy[1])
		}

	case e.Id.Equal(extIDFormFactor):
		// XXX(joe): formfactor is encoded directly as 1 byte. It is not marshaled into an ASN.1 type
		var formfactor []byte
		// if _, err := asn1.Unmarshal(e.Value, &formfactor); err != nil {
		// 	return fmt.Errorf("parsing formfactor: %v", err)
		// }
		formfactor = e.Value
		if len(formfactor) != 1 {
			return fmt.Errorf("expected 1 byte from formfactor, got: %d", len(formfactor))
		}
		switch formfactor[0] {
		case 0x01:
			a.Formfactor = FormfactorUSBAKeychain
		case 0x02:
			a.Formfactor = FormfactorUSBANano
		case 0x03:
			a.Formfactor = FormfactorUSBCKeychain
		case 0x04:
			a.Formfactor = FormfactorUSBCNano
		case 0x05:
			a.Formfactor = FormfactorUSBCLightningKeychain
		default:
			return fmt.Errorf("unrecognized formfactor: 0x%x", formfactor[0])
		}
	}
	return nil
}

// parseSlot parses the common-name from the attestation cert's subject. The format
// is described in: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
//
//	Subject will be the string "YubiKey PIV Attestation " with the
//	attested slot appended.
func parseSlot(subject string) (Slot, error) {
	if len(subject) < 2 {
		return Slot(""), fmt.Errorf("subject less than 2 chars, unable to determine slot")
	}
	slot := subject[len(subject)-2:]

	switch slot {
	case "9a":
		return SlotAuthenticate, nil
	case "9c":
		return SlotSignature, nil
	case "9d":
		return SlotKeyManagement, nil
	case "9e":
		return SlotKeyCardAuth, nil
	}
	return Slot(""), fmt.Errorf("unknown slot '%v'", slot)
}
