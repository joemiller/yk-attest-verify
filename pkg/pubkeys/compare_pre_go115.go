// +build !go1.15

// backport from publickey Equal() funcs introduced in go1.15:
// https://go-review.googlesource.com/c/go/+/225460/

package pubkeys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

func Compare(sshkey ssh.PublicKey, certkey crypto.PublicKey) bool {
	// upgrade sshpub to ssh.CryptoPublicKey so we can access the underlying crypto.PublicKey
	sshpub := sshkey.(ssh.CryptoPublicKey)

	switch sshk := sshpub.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		certk, ok := certkey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return sshk.N.Cmp(certk.N) == 0 && sshk.E == certk.E

	case *ecdsa.PublicKey:
		certk, ok := certkey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return sshk.X.Cmp(certk.X) == 0 && sshk.Y.Cmp(certk.Y) == 0 && sshk.Curve == certk.Curve

	case ed25519.PublicKey:
		certk, ok := certkey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return bytes.Equal(sshk, certk)

	}
	return false
}
