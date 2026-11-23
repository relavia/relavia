package shadowsocks

// Key derivation, assembled from vetted primitives exactly as
// SIP004 / SIP022 prescribe (spec section 2.4). No cryptographic
// primitive is implemented here: MD5 and SHA-1 appear only as
// the specifications' mandated legacy KDF components.

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"hash"
	"io"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/hkdf"
)

// EVPBytesToKey is OpenSSL's EVP_BytesToKey with MD5, no salt,
// one iteration - the SIP004 master-key derivation from a
// password: D_i = MD5(D_{i-1} || password), concatenated and
// truncated to keyLen.
func EVPBytesToKey(password []byte, keyLen int) []byte {
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

// subkey2017 derives the SIP004 session subkey:
// HKDF-SHA1(salt = session salt, IKM = master key,
// info = "ss-subkey").
func subkey2017(masterKey, salt []byte, keyLen int) []byte {
	r := hkdf.New(func() hash.Hash { return sha1.New() }, masterKey, salt, []byte("ss-subkey"))
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF over SHA-1 cannot fail for these sizes.
		panic(err)
	}
	return out
}

// sessionKey2022 derives the SIP022 session subkey: BLAKE3 in
// derive-key mode, context "shadowsocks 2022 session subkey",
// key material = PSK || salt.
func sessionKey2022(psk, salt []byte, keyLen int) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey("shadowsocks 2022 session subkey", material, out)
	return out
}

func base64StdDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func base64RawDecode(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
