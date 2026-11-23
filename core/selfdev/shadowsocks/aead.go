package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// newAEAD builds the AEAD cipher for a method from a session
// subkey, using only vetted implementations: Go's standard
// AES-GCM and x/crypto's ChaCha20-Poly1305 family.
func (m Method) newAEAD(subkey []byte) (cipher.AEAD, error) {
	switch {
	case m.XChaCha:
		return chacha20poly1305.NewX(subkey)
	case m.ChaCha:
		return chacha20poly1305.New(subkey)
	default:
		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}

// nonceCounter is the little-endian nonce counter both editions
// increment once per AEAD operation (SIP004 TCP section, SIP022
// 3.1.1).
type nonceCounter struct {
	b []byte
}

func newNonceCounter(size int) *nonceCounter { return &nonceCounter{b: make([]byte, size)} }

func (n *nonceCounter) next() []byte {
	out := make([]byte, len(n.b))
	copy(out, n.b)
	for i := range n.b {
		n.b[i]++
		if n.b[i] != 0 {
			break
		}
	}
	return out
}

// tagSize is the AEAD overhead of every method in scope.
const tagSize = 16
