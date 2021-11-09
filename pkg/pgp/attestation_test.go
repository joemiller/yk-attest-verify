package pgp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
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

	cfg := opgpAttestation{
		cardholder:  "Alice Crypto",
		slot:        SlotAuthenticate,
		keysource:   KeysourceGenerated,
		version:     []byte{5, 2, 4},
		fingerprint: []byte{1, 2, 3},
		timestamp:   time.Now(),
		sigcounter:  2,
		serial:      1234,
		formfactor:  FormfactorUSBCNano,
		touchpolicy: TouchPolicyPermanent,
	}
	attestationCert := makeOPGPAttestationCert(t, signer, cfg)

	parsedAttestation, err := ParseAttestation(attestationCert)
	assert.NoError(t, err)
	assert.Equal(t, "Alice Crypto", parsedAttestation.Cardholder)
	assert.Equal(t, SlotAuthenticate, parsedAttestation.Slot)
	assert.Equal(t, KeysourceGenerated, parsedAttestation.Keysource)
	assert.Equal(t, "010203", parsedAttestation.Fingerprint)
	assert.Equal(t, uint32(2), parsedAttestation.SignatureCounter)
	assert.Equal(t, uint32(1234), parsedAttestation.Serial)
	assert.Equal(t, TouchPolicyPermanent, parsedAttestation.TouchPolicy)
	assert.Equal(t, FormfactorUSBCNano, parsedAttestation.Formfactor)

	expectedVersion := Version{5, 2, 4}
	assert.Equal(t, expectedVersion, parsedAttestation.Version)
}

func fakeYubiRoot(t *testing.T) *certin.KeyAndCert {
	root, err := certin.NewCert(nil, certin.Request{CN: "Yubico OpenPGP Attestation CA"})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func fakeAttestSigner(t *testing.T, root *certin.KeyAndCert) *certin.KeyAndCert {
	signer, err := certin.NewCert(root, certin.Request{CN: "Yubikey OPGP Attestation"})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type opgpAttestation struct {
	cardholder  string
	slot        Slot
	keysource   Keysource
	version     []byte
	fingerprint []byte
	timestamp   time.Time
	sigcounter  uint32
	serial      uint32
	formfactor  Formfactor
	touchpolicy TouchPolicy
}

// Create an attestation cert and sign it with the attestation signer key.
// Sane defaults will be used for nil or zero values where possible so that callers
// can supply values for only things they're interested in testing.
func makeOPGPAttestationCert(t *testing.T, signer *certin.KeyAndCert, cfg opgpAttestation) *x509.Certificate {
	cardholder, err := asn1.Marshal(cfg.cardholder)
	require.Nil(t, err)

	if cfg.slot == "" {
		cfg.slot = SlotSignature // default slot is "SIG" if not specified
	}

	keysource, err := asn1.Marshal(cfg.keysource)
	require.Nil(t, err)

	if cfg.version == nil {
		cfg.version = []byte{5, 2, 1} // default version if not specified
	}
	version, err := asn1.Marshal(cfg.version)
	require.Nil(t, err)

	fingerprint, err := asn1.Marshal(cfg.fingerprint)
	require.Nil(t, err)

	if !cfg.timestamp.IsZero() {
		cfg.timestamp = time.Now() // default timestmap if not specified
	}
	timestampBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timestampBytes, uint32(cfg.timestamp.Unix()))
	timestamp, err := asn1.Marshal(timestampBytes)
	require.Nil(t, err)

	sigcounter, err := asn1.Marshal(int64(cfg.sigcounter))
	require.Nil(t, err)

	serial, err := asn1.Marshal(int64(cfg.serial))
	require.Nil(t, err)

	pinpolicy, err := asn1.Marshal([]byte{byte(cfg.touchpolicy)})
	require.Nil(t, err)

	formfactor, err := asn1.Marshal([]byte{byte(cfg.formfactor)})
	require.Nil(t, err)

	attestationCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("YubiKey OPGP Attestation %s", cfg.slot),
		},
		NotBefore: time.Now().Add(-30 * time.Second),
		NotAfter:  time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: yubikeyPGPCardHolderName, Critical: false, Value: cardholder},
			{Id: yubikeyPGPKeySource, Critical: false, Value: keysource},
			{Id: yubikeyPGPVersionNumber, Critical: false, Value: version},
			{Id: yubikeyPGPKeyFingerprint, Critical: false, Value: fingerprint},
			{Id: yubikeyPGPKeyGenerationDate, Critical: false, Value: timestamp},
			{Id: yubikeyPGPSignatureCounter, Critical: false, Value: sigcounter},
			{Id: yubikeyPGPSerialNumber, Critical: false, Value: serial},
			{Id: yubikeyPGPUserInteractionFlag, Critical: false, Value: pinpolicy},
			{Id: yubikeyPGPFormFactor, Critical: false, Value: formfactor},
		},
	}
	attestation, err := certin.NewCertFromX509Template(signer, "rsa-2048", attestationCertTemplate)
	if err != nil {
		t.Fatal(err)
	}
	return attestation.Certificate
}
