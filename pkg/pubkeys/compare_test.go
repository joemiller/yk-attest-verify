package pubkeys_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/joemiller/certin"
	"github.com/joemiller/yk-attest-verify/pkg/pubkeys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCompare(t *testing.T) {

	tests := []string{
		"rsa-2048", "rsa-3072", "rsa-4096",
		"ecdsa-256", "ecdsa-384", "ecdsa-521",
		"ed25519",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			keyA, err := certin.GenerateKey(tc)
			require.NoError(t, err)
			keyB, err := certin.GenerateKey(tc)
			require.NoError(t, err)

			var certpubkeyA crypto.PublicKey
			var certpubkeyB crypto.PublicKey
			var sshpubkeyA ssh.PublicKey
			var sshpubkeyB ssh.PublicKey

			switch {
			case strings.Contains(tc, "rsa"):
				certpubkeyA = keyA.(*rsa.PrivateKey).Public()
				certpubkeyB = keyB.(*rsa.PrivateKey).Public()
				sshpubkeyA, err = ssh.NewPublicKey(certpubkeyA)
				require.NoError(t, err)
				sshpubkeyB, err = ssh.NewPublicKey(certpubkeyB)
				require.NoError(t, err)

			case strings.Contains(tc, "ec"):
				certpubkeyA = keyA.(*ecdsa.PrivateKey).Public()
				certpubkeyB = keyB.(*ecdsa.PrivateKey).Public()
				sshpubkeyA, err = ssh.NewPublicKey(certpubkeyA)
				require.NoError(t, err)
				sshpubkeyB, err = ssh.NewPublicKey(certpubkeyB)
				require.NoError(t, err)

			case strings.Contains(tc, "ed25519"):
				certpubkeyA = keyA.(ed25519.PrivateKey).Public()
				certpubkeyB = keyB.(ed25519.PrivateKey).Public()
				sshpubkeyA, err = ssh.NewPublicKey(certpubkeyA)
				require.NoError(t, err)
				sshpubkeyB, err = ssh.NewPublicKey(certpubkeyB)
				require.NoError(t, err)

			default:
				t.Fatalf("unknown keytype %v", tc)
			}

			assert.True(t, pubkeys.Compare(sshpubkeyA, certpubkeyA))
			assert.False(t, pubkeys.Compare(sshpubkeyA, certpubkeyB))

			assert.True(t, pubkeys.Compare(sshpubkeyB, certpubkeyB))
			assert.False(t, pubkeys.Compare(sshpubkeyB, certpubkeyA))
		})
	}
}
