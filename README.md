yk-attest-verify
================

![main](https://github.com/joemiller/yk-attest-verify/workflows/main/badge.svg)
TODO: godoc

Validate and enforce policy on YubiKey PIV and OpenPGP attestation certificates.

One use case of this utility is to enforce SSH keys are generated and stored solely on a YubiKey.

Install
-------

* macOS homebrew (Linuxbrew might work too): `brew install joemiller/taps/yk-attest-verify`
* Binaries for all platforms (macOS, Linux, *BSD) on [GitHub Releases](https://github.com/joemiller/yk-attest-verify/releases)
* [Docker images](https://hub.docker.com/r/joemiller/yk-attest-verify) are also available.

Generating attestation certs
----------------------------

The process for generating and verifying attestation certs is similar for both PIV and
OpenPGP. You need to generate an **attestation** certificate and export the **signing** certificate
from the YubiKey. Both files are required inputs to `yk-attest-verify`.

The signing certificate is similar to an intermediate CA cert. It is unique to each YubiKey
and is signed by YubiKey's root certificate.

The attestation certificate and the signing certificate are input into `yk-attest-verify`
and the signing chain back to the YubiKey root certificate is checked.

Attestation certificates cover a single key slot on the card. If you want to attest multiple
key slots you will generate an attestation for each of them.

For SSH keys the 'authentication' key slot is typically used. This is slot `AUT` for OpenPGP
and slot `9a` for PIV.

### PGP

PGP attestation is available on YubiKey 5.2+

https://developers.yubico.com/PGP/Attestation.html

After you've generated your PGP keys using a tool such as GPG or `ykman`:

* generate an attestation certificate covering the key in the `AUT` (authenticate) slot:

      ykman openpgp attest AUT attestation.pem

* export the signer certificate:

      ykman openpgp export-certificate ATT signer.pem

### PIV

PIV attestation is available on YubiKey 4.3+

https://developers.yubico.com/PIV/Introduction/PIV_attestation.html

After you've generated your PIV keys using a tool such as `yubico-piv-tool` or
[yubikey-agent](https://github.com/FiloSottile/yubikey-agent):

* generate an attestation cert covering the key in the 9a slot:

      yubico-piv-tool --action=attest --slot=9a >attestation.pem

* export the signer certificate:

      yubico-piv-tool --action=read-certificate --slot=f9 >signer.pem

Verification
------------

### PGP

* Help:

      yk-attest-verify pgp -h

* Verify the signature chain of `attestation.pem`:

      yk-attest-verify pgp attestation.pem signer.pem

* Verify the signature chain and compare the public keys from an SSH pub key file
  to the public key on the YubiKey:

      yk-attest-verify pgp attestation.pem signer.pem --ssh-pub-key="id_rsa.pub"

* policy check: verify the attested key was generated on the YubiKey:

      yk-attest-verify pgp attestation.pem signer.pem --allowed-keysources="generated"

* policy check: verify the attested key has an allowed Touch Policy set:

      yk-attest-verify pgp attestation.pem signer.pem --allowed-touch-policies="enabled,cached"

Multiple `--allowed-*` flags can be used together to express a complete policy.

### PIV

* Help:

      yk-attest-verify piv -h

* Verify the signature chain of `attestation.pem`:

      yk-attest-verify piv attestation.pem signer.pem

* Verify the signature chain and compare the public keys from an SSH pub key file
  to the public key on the YubiKey:

      yk-attest-verify piv attestation.pem signer.pem --ssh-pub-key="id_rsa.pub"

* policy check: verify the attested key has an allowed Touch Policy set:

      yk-attest-verify piv attestation.pem signer.pem --allowed-touch-policies="always,cached"

* policy check: verify the attested key has an allowed PIN Policy set:

      yk-attest-verify piv attestation.pem signer.pem --allowed-touch-policies="once,always"

Multiple `--allowed-*` flags can be used together to express a complete policy.
