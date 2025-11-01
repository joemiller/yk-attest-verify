package pgp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// This package provides the ability to parse and verify Yubikey OpenPGP attestation certificates.
//
// It is based off of https://github.com/go-piv/piv-go piv.Verify() which is
// only capable of verifying Yubikey PIV attestation certificates.

var (
	yubicoBaseOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482}

	// OIDs present in OpenPGP attestation certs - https://developers.yubico.com/PGP/Attestation.html
	yubikeyPGPCardHolderName      = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 1}...)
	yubikeyPGPKeySource           = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 2}...)
	yubikeyPGPVersionNumber       = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 3}...)
	yubikeyPGPKeyFingerprint      = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 4}...)
	yubikeyPGPKeyGenerationDate   = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 5}...)
	yubikeyPGPSignatureCounter    = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 6}...)
	yubikeyPGPSerialNumber        = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 7}...)
	yubikeyPGPUserInteractionFlag = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 8}...)
	yubikeyPGPFormFactor          = append(yubicoBaseOID, asn1.ObjectIdentifier{5, 9}...)
)

// Keysourxe represents the source of the key (imported or generated)
type Keysource int

const (
	KeysourceImported Keysource = iota
	KeysourceGenerated
)

var keysourceNames = []string{
	KeysourceImported:  "Imported",
	KeysourceGenerated: "Generated",
}

func (k Keysource) String() string {
	return keysourceNames[k]
}

// MarshalJSON encodes value into String().
func (k Keysource) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// Slot represents the YubiKey card slot that is covered by the attestation.
type Slot string

const (
	SlotSignature    = Slot("SIG")
	SlotEncrypt      = Slot("ENC")
	SlotAuthenticate = Slot("AUT")
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

// TouchPolicy represents proof-of-presence requirements when signing or
// decrypting with asymmetric key in a given slot.
type TouchPolicy int

// Touch policies supported by this package.
//
//	$ ykman openpgp set-touch
const (
	TouchPolicyDisabled        TouchPolicy = iota // No touch required
	TouchPolicyEnabled                            // Touch required
	TouchPolicyPermanent                          // Touch required, can't be disabled without a full reset
	TouchPolicyCached                             // Touch required, cached for 15s after use
	TouchPolicyPermanentCached                    // Touch required, cached for 15s after use, can't be disabled without a full reset
)

var touchPolicyNames = []string{
	TouchPolicyDisabled:        "Disabled",
	TouchPolicyEnabled:         "Enabled",
	TouchPolicyPermanent:       "Enabled-Permanent",
	TouchPolicyCached:          "Enabled-Cached",
	TouchPolicyPermanentCached: "Enabled-Permanent-Cached",
}

func (t TouchPolicy) String() string {
	return touchPolicyNames[t]
}

// MarshalJSON encodes value into String().
func (t TouchPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Attestation contains additional information about a key attested to be on a
// card.
type Attestation struct {
	// Cardholder is the name of the cardholder
	Cardholder string

	// Keysource
	Keysource Keysource

	// Slot is the key slot
	Slot Slot

	// Version of the YubiKey's firmware.
	Version Version

	// Fingerprint
	Fingerprint string

	// GenerationDate
	GenerationDate time.Time

	// SignatureCounter (if applicable)
	SignatureCounter uint32

	// Serial is the YubiKey's serial number.
	Serial uint32

	// Formfactor indicates the physical type of the YubiKey.
	//
	// Formfactor may be empty Formfactor(0) for some YubiKeys.
	Formfactor Formfactor

	// TouchPolicy set on the slot.
	TouchPolicy TouchPolicy
}

// ParseAttestation parses a YubiKey OPGP attestation certificate and returns
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
	case e.Id.Equal(yubikeyPGPCardHolderName):
		var name string
		if _, err := asn1.Unmarshal(e.Value, &name); err != nil {
			return fmt.Errorf("parsing cardholder name: %v", err)
		}
		a.Cardholder = string(name)

	case e.Id.Equal(yubikeyPGPKeySource):
		var source int
		if _, err := asn1.Unmarshal(e.Value, &source); err != nil {
			return fmt.Errorf("parsing key source: %v", err)
		}
		switch source {
		case 0x00:
			a.Keysource = KeysourceImported // not permitted, but yubikey may some day generate attestations for imported keys
		case 0x01:
			a.Keysource = KeysourceGenerated
		default:
			return fmt.Errorf("unknown keysource 0x%x", source)
		}

	case e.Id.Equal(yubikeyPGPVersionNumber):
		var version []byte
		if _, err := asn1.Unmarshal(e.Value, &version); err != nil {
			return fmt.Errorf("parsing version: %v", err)
		}
		if len(version) != 3 {
			return fmt.Errorf("expected at least 3 bytes for firmware version, got: %d", len(version))
		}
		a.Version = Version{
			Major: int(version[0]),
			Minor: int(version[1]),
			Patch: int(version[2]),
		}

	case e.Id.Equal(yubikeyPGPKeyFingerprint):
		var fp []byte
		if _, err := asn1.Unmarshal(e.Value, &fp); err != nil {
			return fmt.Errorf("parsing fingerprint: %v", err)
		}
		a.Fingerprint = hex.EncodeToString(fp)

	case e.Id.Equal(yubikeyPGPKeyGenerationDate):
		var ts []byte
		if _, err := asn1.Unmarshal(e.Value, &ts); err != nil {
			return fmt.Errorf("parsing generation date: %v", err)
		}
		a.GenerationDate = time.Unix(int64(binary.BigEndian.Uint32(ts)), 0)

	case e.Id.Equal(yubikeyPGPSignatureCounter):
		var counter int64
		if _, err := asn1.Unmarshal(e.Value, &counter); err != nil {
			return fmt.Errorf("parsing signature counter: %v", err)
		}
		a.SignatureCounter = uint32(counter)

	case e.Id.Equal(yubikeyPGPSerialNumber):
		var serial int64
		if _, err := asn1.Unmarshal(e.Value, &serial); err != nil {
			return fmt.Errorf("parsing serial number: %v", err)
		}
		if serial < 0 {
			return fmt.Errorf("serial number was negative: %d", serial)
		}
		a.Serial = uint32(serial)

	case e.Id.Equal(yubikeyPGPUserInteractionFlag):
		var flag []byte
		if _, err := asn1.Unmarshal(e.Value, &flag); err != nil {
			return fmt.Errorf("parsing touch policy: %v", err)
		}
		switch flag[0] {
		case 0x00:
			a.TouchPolicy = TouchPolicyDisabled
		case 0x01:
			a.TouchPolicy = TouchPolicyEnabled
		case 0x02:
			a.TouchPolicy = TouchPolicyPermanent
		case 0x03:
			a.TouchPolicy = TouchPolicyCached
		case 0x04:
			a.TouchPolicy = TouchPolicyPermanentCached
		default:
			return fmt.Errorf("unknown touch policy 0x%x", flag)
		}

	case e.Id.Equal(yubikeyPGPFormFactor):
		var formfactor []byte
		if _, err := asn1.Unmarshal(e.Value, &formfactor); err != nil {
			return fmt.Errorf("parsing form factor: %v", err)
		}
		switch formfactor[0] {
		case 0x00:
			a.Formfactor = FormfactorUnspecified
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
			return fmt.Errorf("unrecognized formfactor: 0x%x", formfactor)
		}
	}

	return nil
}

// parseSlot parses the common-name from the attestation cert's subject. The format
// is described in: https://developers.yubico.com/PGP/Attestation.html -
//
//	Subject will be the string "YubiKey OPGP Attestation " with the
//	attested slot appended ("SIG", "DEC", or "AUT")
func parseSlot(subject string) (Slot, error) {
	if len(subject) < 3 {
		return Slot(""), fmt.Errorf("subject less than 3 chars, unable to determine slot")
	}
	slot := subject[len(subject)-3:]

	switch slot {
	case "SIG":
		return SlotSignature, nil
	case "ENC", "DEC":
		return SlotEncrypt, nil
	case "AUT":
		return SlotAuthenticate, nil
	}
	return Slot(""), fmt.Errorf("unknown slot '%v'", slot)
}
