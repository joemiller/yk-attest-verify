// +build go1.15

package pubkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

// Compare compares the contents of an ssh.PublicKey and a crypto.PublicKey
// and returns true if they are identical.
func Compare(sshkey ssh.PublicKey, certkey crypto.PublicKey) bool {
	// upgrade sshpub to ssh.CryptoPublicKey so we can access the underlying crypto.PublicKey
	sshpub := sshkey.(ssh.CryptoPublicKey)

	// fmt.Printf("key type %T %T", sshkey, certkey)
	switch k := sshpub.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return k.Equal(certkey)
	case *ecdsa.PublicKey:
		return k.Equal(certkey)
	case ed25519.PublicKey:
		return k.Equal(certkey)
	}
	// unknown key type
	// fmt.Printf("unknown key type %T %T", sshkey, certkey)
	return false
}
