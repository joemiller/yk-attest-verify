package piv

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"

	"github.com/joemiller/certin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAttestation(t *testing.T) {
	root := fakeYubiRoot(t)
	signer := fakeAttestSigner(t, root)

	cfg := pivAttestation{
		version:     []byte{4, 3, 1},
		slot:        SlotAuthenticate,
		serial:      1234,
		formfactor:  FormfactorUSBCKeychain,
		pinpolicy:   PINPolicyAlways,
		touchpolicy: TouchPolicyAlways,
	}
	attestationCert := makePIVAttestationCert(t, signer, cfg)
	parsedAttestation, err := ParseAttestation(attestationCert)
	assert.NoError(t, err)
	assert.Equal(t, SlotAuthenticate, parsedAttestation.Slot)
	assert.Equal(t, uint32(1234), parsedAttestation.Serial)
	assert.Equal(t, FormfactorUSBCKeychain, parsedAttestation.Formfactor)
	assert.Equal(t, TouchPolicyAlways, parsedAttestation.TouchPolicy)

	expectedVersion := Version{4, 3, 1}
	assert.Equal(t, expectedVersion, parsedAttestation.Version)
}

type pivAttestation struct {
	version     []byte
	slot        Slot
	serial      uint32
	formfactor  Formfactor
	pinpolicy   PINPolicy
	touchpolicy TouchPolicy
}

// Create an attestation cert and sign it with the attestation signer key.
// Sane defaults will be used for nil or zero values where possible so that callers
// can supply values for only things they're interested in testing.
func makePIVAttestationCert(t *testing.T, signer *certin.KeyAndCert, cfg pivAttestation) *x509.Certificate {
	if cfg.slot == "" {
		cfg.slot = SlotSignature // default slot is "SIG" if not specified
	}

	if cfg.version == nil {
		cfg.version = []byte{4, 3, 0} // default version if not specified
	}
	// version, err := asn1.Marshal(cfg.version)
	// require.Nil(t, err)

	serial, err := asn1.Marshal(int64(cfg.serial))
	require.Nil(t, err)

	if cfg.formfactor == 0 {
		cfg.formfactor = FormfactorUSBAKeychain // default if not specified
	}
	// formfactor, err := asn1.Marshal([]byte{byte(cfg.formfactor)})
	// require.Nil(t, err)
	formfactor := []byte{byte(cfg.formfactor)}

	if cfg.pinpolicy == 0 {
		cfg.pinpolicy = PINPolicyNever
	}
	if cfg.touchpolicy == 0 {
		cfg.touchpolicy = TouchPolicyNever
	}
	// keypolicy, err := asn1.Marshal([]byte{
	// 	byte(cfg.pinpolicy),
	// 	byte(cfg.touchpolicy),
	// })
	// require.Nil(t, err)
	keypolicy := []byte{byte(cfg.pinpolicy), byte(cfg.touchpolicy)}

	attestationCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("YubiKey PIV Attestation %s", cfg.slot),
		},
		NotBefore: time.Now().Add(-30 * time.Second),
		NotAfter:  time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extIDFirmwareVersion, Critical: false, Value: cfg.version}, //version},
			{Id: extIDSerialNumber, Critical: false, Value: serial},
			{Id: extIDKeyPolicy, Critical: false, Value: keypolicy},
			{Id: extIDFormFactor, Critical: false, Value: formfactor},
		},
	}
	attestation, err := certin.NewCertFromX509Template(signer, "rsa-2048", attestationCertTemplate)
	if err != nil {
		t.Fatal(err)
	}
	return attestation.Certificate
}

func fakeYubiRoot(t *testing.T) *certin.KeyAndCert {
	root, err := certin.NewCert(nil, certin.Request{CN: "Yubico PIV Root CA Serial 263751"})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func fakeAttestSigner(t *testing.T, root *certin.KeyAndCert) *certin.KeyAndCert {
	signer, err := certin.NewCert(root, certin.Request{CN: "Yubikey PIV Attestation"})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
