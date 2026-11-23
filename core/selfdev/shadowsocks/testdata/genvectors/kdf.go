package main

// Key-derivation primitives transcribed from SIP004 (AEAD ciphers,
// Key Derivation) and SIP022 section 2.2. Cryptographic primitives
// themselves are always the standard library / vetted x/crypto /
// zeebo-blake3 implementations - this file only assembles them the
// way the specifications prescribe. Nothing here is production
// code: it exists to produce test vectors whose expected values
// are cross-checked against independent sources (see README.md).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// evpBytesToKey is OpenSSL's EVP_BytesToKey with MD5, no salt,
// one iteration, as mandated by SIP004 for password-based master
// keys: D_i = MD5(D_{i-1} || password), concatenated and cut.
func evpBytesToKey(password []byte, keyLen int) []byte {
	var out, prev []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// hkdfSHA1Subkey derives the Shadowsocks 2017 session subkey:
// HKDF-SHA1(salt = session salt, IKM = master key,
// info = "ss-subkey").
func hkdfSHA1Subkey(masterKey, salt []byte, keyLen int) []byte {
	r := hkdf.New(func() hash.Hash { return sha1.New() }, masterKey, salt, []byte("ss-subkey"))
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

// blake3SessionKey derives the Shadowsocks 2022 session subkey:
// BLAKE3 derive-key mode, context "shadowsocks 2022 session
// subkey", key material = PSK || salt (SIP022 section 2.2).
func blake3SessionKey(psk, salt []byte, keyLen int) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey("shadowsocks 2022 session subkey", material, out)
	return out
}

// methodInfo describes one of the seven in-scope methods.
type methodInfo struct {
	name       string
	keyLen     int // master key (2017) or PSK (2022) length; salt length equals it
	nonceLen   int
	is2022     bool
	chacha     bool // IETF ChaCha20-Poly1305 (12-byte nonce)
	xchacha    bool // XChaCha20-Poly1305 (24-byte nonce, 2017 only)
	chacha2022 bool // 2022-blake3-chacha20-poly1305
}

var methods = map[string]methodInfo{
	"aes-128-gcm":                   {name: "aes-128-gcm", keyLen: 16, nonceLen: 12},
	"aes-256-gcm":                   {name: "aes-256-gcm", keyLen: 32, nonceLen: 12},
	"chacha20-ietf-poly1305":        {name: "chacha20-ietf-poly1305", keyLen: 32, nonceLen: 12, chacha: true},
	"xchacha20-ietf-poly1305":       {name: "xchacha20-ietf-poly1305", keyLen: 32, nonceLen: 24, xchacha: true},
	"2022-blake3-aes-128-gcm":       {name: "2022-blake3-aes-128-gcm", keyLen: 16, nonceLen: 12, is2022: true},
	"2022-blake3-aes-256-gcm":       {name: "2022-blake3-aes-256-gcm", keyLen: 32, nonceLen: 12, is2022: true},
	"2022-blake3-chacha20-poly1305": {name: "2022-blake3-chacha20-poly1305", keyLen: 32, nonceLen: 12, is2022: true, chacha2022: true},
}

// newAEAD builds the AEAD for a method from a session subkey.
func newAEAD(m methodInfo, subkey []byte) cipher.AEAD {
	var a cipher.AEAD
	var err error
	switch {
	case m.xchacha:
		a, err = chacha20poly1305.NewX(subkey)
	case m.chacha || m.chacha2022:
		a, err = chacha20poly1305.New(subkey)
	default:
		var block cipher.Block
		block, err = aes.NewCipher(subkey)
		if err != nil {
			panic(err)
		}
		a, err = cipher.NewGCM(block)
	}
	if err != nil {
		panic(fmt.Sprintf("%s: %v", m.name, err))
	}
	return a
}

// aesBlockEncrypt is a single raw AES block encryption (the
// SIP022 UDP separate-header protection: AES block cipher keyed
// directly by the PSK).
func aesBlockEncrypt(psk, in []byte) []byte {
	block, err := aes.NewCipher(psk)
	if err != nil {
		panic(err)
	}
	if len(in) != aes.BlockSize {
		panic("separate header must be one block")
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, in)
	return out
}

// nonceCounter is the little-endian per-operation nonce counter
// used by both editions' stream ciphers.
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
