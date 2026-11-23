// Command genvectors generates the Shadowsocks self-development
// test vector set (docs/自研协议路线-01-shadowsocks-测试向量清单.md)
// into ../vectors.json.
//
// Every key in this file is a TEST-ONLY value generated for this
// vector set; none of them protects any real traffic.
//
// Regeneration must be byte-identical: if a regenerated file
// differs from the committed one, either the generator or an
// expectation changed - both are reviewable events, never silent
// ones (vector files are append-only; changed expectations get
// new IDs, see the checklist's maintenance rules).
//
// Run from this directory:
//
//	go run . [-out ../vectors.json]
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type vector struct {
	ID       string         `json:"id"`
	Priority string         `json:"priority"`
	Category string         `json:"category"`
	Method   string         `json:"method,omitempty"`
	Inputs   map[string]any `json:"inputs"`
	Expected map[string]any `json:"expected"`
	Sources  []string       `json:"sources"`
	Notes    string         `json:"notes,omitempty"`
}

type vectorFile struct {
	Version int      `json:"version"`
	Note    string   `json:"note"`
	Vectors []vector `json:"vectors"`
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// psk32 / psk16 are the fixed TEST-ONLY 2022 pre-shared keys.
var (
	psk16 = saltPattern(0x00, 16) // 00 01 02 ... 0f
	psk32 = saltPattern(0x00, 32) // 00 01 02 ... 1f
)

const (
	srcSIP004   = "SIP004 text (shadowsocks-org docs/doc/aead.md)"
	srcSIP022   = "SIP022 text (shadowsocks-org docs/doc/sip022.md)"
	srcOpenSSL  = "OpenSSL 3.0 EVP_BytesToKey (openssl enc -P -md md5 -nosalt)"
	srcPython   = "Python hashlib/hmac HKDF-SHA1 (crosscheck.py)"
	srcLukeB3   = "lukechampine.com/blake3 v1.3.0 (xcheck, independent BLAKE3 implementation)"
	srcRustLive = "shadowsocks-rust v1.25.0 live interop (diffrig cross-decryption)"
	srcSingLive = "sing-box v1.14.4 (sing-shadowsocks2) live interop (diffrig)"
)

func main() {
	out := flag.String("out", "../vectors.json", "output path")
	flag.Parse()

	vf := vectorFile{
		Version: 1,
		Note:    "TEST-ONLY vector set for the self-developed Shadowsocks engine. All passwords, PSKs and salts in this file are dedicated test values, never used by any real node.",
	}
	vf.Vectors = append(vf.Vectors, kdfVectors()...)
	vf.Vectors = append(vf.Vectors, aeadVectors()...)
	vf.Vectors = append(vf.Vectors, wire2017Vectors()...)
	vf.Vectors = append(vf.Vectors, wire2022Vectors()...)
	vf.Vectors = append(vf.Vectors, negativeVectors()...)

	data, err := json.MarshalIndent(vf, "", " ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(vf.Vectors), *out)
}

// --- A. KDF vectors ------------------------------------------------

func kdfVectors() []vector {
	var vs []vector
	add := func(id, prio, method string, inputs, expected map[string]any, sources []string, notes string) {
		vs = append(vs, vector{ID: id, Priority: prio, Category: "kdf", Method: method,
			Inputs: inputs, Expected: expected, Sources: sources, Notes: notes})
	}

	// KDF-01 / KDF-02: EVP_BytesToKey at 16 and 32 bytes.
	pw := "test-password" // TEST-ONLY
	add("KDF-01", "P0", "aes-128-gcm",
		map[string]any{"password": pw, "keyLen": 16},
		map[string]any{"masterKey": hx(evpBytesToKey([]byte(pw), 16))},
		[]string{srcSIP004, srcOpenSSL}, "")
	add("KDF-02", "P0", "aes-256-gcm",
		map[string]any{"password": pw, "keyLen": 32},
		map[string]any{"masterKey": hx(evpBytesToKey([]byte(pw), 32))},
		[]string{srcSIP004, srcOpenSSL},
		"32-byte output exercises the MD5 chain's second block (D2 = MD5(D1 || password)).")

	// KDF-03: long (100-byte) and non-ASCII passwords.
	longPW := (strings.Repeat("0123456789", 10))[:100]
	nonASCII := "pässwörd-测试" // TEST-ONLY, UTF-8 bytes are the KDF input
	add("KDF-03", "P0", "aes-256-gcm",
		map[string]any{"password": longPW, "passwordHex": hx([]byte(longPW)), "keyLen": 32},
		map[string]any{"masterKey": hx(evpBytesToKey([]byte(longPW), 32))},
		[]string{srcSIP004, srcOpenSSL}, "Long password (100 bytes).")
	add("KDF-03b", "P0", "aes-256-gcm",
		map[string]any{"password": nonASCII, "passwordHex": hx([]byte(nonASCII)), "keyLen": 32},
		map[string]any{"masterKey": hx(evpBytesToKey([]byte(nonASCII), 32))},
		[]string{srcSIP004, srcOpenSSL}, "Non-ASCII password; input is its UTF-8 encoding.")

	// KDF-04: HKDF-SHA1 session subkeys from the KDF-02 master key.
	master := evpBytesToKey([]byte(pw), 32)
	salt16 := saltPattern(0xA0, 16)
	salt32 := saltPattern(0xA0, 32)
	add("KDF-04", "P0", "aes-256-gcm",
		map[string]any{"masterKey": hx(master), "salt": hx(salt32), "info": "ss-subkey", "keyLen": 32},
		map[string]any{"subkey": hx(hkdfSHA1Subkey(master, salt32, 32))},
		[]string{srcSIP004, srcPython}, "")
	add("KDF-04b", "P0", "aes-128-gcm",
		map[string]any{"masterKey": hx(evpBytesToKey([]byte(pw), 16)), "salt": hx(salt16), "info": "ss-subkey", "keyLen": 16},
		map[string]any{"subkey": hx(hkdfSHA1Subkey(evpBytesToKey([]byte(pw), 16), salt16, 16))},
		[]string{srcSIP004, srcPython}, "16-byte salt / 16-byte subkey form.")

	// KDF-05: BLAKE3 session subkeys.
	add("KDF-05", "P0", "2022-blake3-aes-128-gcm",
		map[string]any{"psk": hx(psk16), "salt": hx(saltPattern(0x30, 16)), "context": "shadowsocks 2022 session subkey", "keyLen": 16},
		map[string]any{"subkey": hx(blake3SessionKey(psk16, saltPattern(0x30, 16), 16))},
		[]string{srcSIP022, srcLukeB3}, "")
	add("KDF-05b", "P0", "2022-blake3-aes-256-gcm",
		map[string]any{"psk": hx(psk32), "salt": hx(saltPattern(0x30, 32)), "context": "shadowsocks 2022 session subkey", "keyLen": 32},
		map[string]any{"subkey": hx(blake3SessionKey(psk32, saltPattern(0x30, 32), 32))},
		[]string{srcSIP022, srcLukeB3}, "")

	// KDF-06 (revised per spec section 6): UDP separate header =
	// raw AES block encryption under the PSK. TCP has no separate
	// header key; its header chunks ride on the KDF-05 subkey and
	// are covered byte-wise by the W22 vectors.
	sep := append(u64be(0x0102030405060708), u64be(0)...)
	add("KDF-06", "P0", "2022-blake3-aes-128-gcm",
		map[string]any{"psk": hx(psk16), "separateHeader": hx(sep)},
		map[string]any{"encryptedSeparateHeader": hx(aesBlockEncrypt(psk16, sep))},
		[]string{srcSIP022, srcRustLive}, "AES-128 single-block encryption of the UDP separate header.")
	add("KDF-06b", "P0", "2022-blake3-aes-256-gcm",
		map[string]any{"psk": hx(psk32), "separateHeader": hx(sep)},
		map[string]any{"encryptedSeparateHeader": hx(aesBlockEncrypt(psk32, sep))},
		[]string{srcSIP022, srcRustLive}, "AES-256 form.")

	// KDF-07 (P1): EVP_BytesToKey at MD5 block boundaries.
	for _, n := range []int{1, 55, 56, 64} {
		p := strings.Repeat("k", n)
		add(fmt.Sprintf("KDF-07-%d", n), "P1", "aes-256-gcm",
			map[string]any{"password": p, "keyLen": 32},
			map[string]any{"masterKey": hx(evpBytesToKey([]byte(p), 32))},
			[]string{srcSIP004, srcOpenSSL},
			fmt.Sprintf("Password length %d (MD5 padding boundary).", n))
	}
	return vs
}

// --- B. AEAD primitive vectors --------------------------------------

func aeadVectors() []vector {
	var vs []vector
	add := func(id, method string, inputs, expected map[string]any, sources []string, notes string) {
		vs = append(vs, vector{ID: id, Priority: "P0", Category: "aead", Method: method,
			Inputs: inputs, Expected: expected, Sources: sources, Notes: notes})
	}

	// AES-128-GCM, GCM spec (McGrew-Viega) test case 2: zero
	// key, zero nonce, 16 zero plaintext bytes. The expected
	// values are asserted before writing; the ciphertext block
	// was independently arbitrated with OpenSSL's raw AES
	// (AES-128(0, J0+1) = 0388dace..., and the case-1 tag below
	// equals AES-128(0, J0) = 58e2fcce..., both OpenSSL-computed).
	{
		m := methods["aes-128-gcm"]
		a := newAEAD(m, make([]byte, 16))
		ct := a.Seal(nil, make([]byte, 12), make([]byte, 16), nil)
		want := "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf"
		if hx(ct) != want {
			panic("AES-128-GCM published vector mismatch: " + hx(ct))
		}
		add("AEAD-01", "aes-128-gcm",
			map[string]any{"key": hx(make([]byte, 16)), "nonce": hx(make([]byte, 12)), "plaintext": hx(make([]byte, 16))},
			map[string]any{"ciphertextAndTag": want},
			[]string{"GCM spec (McGrew-Viega) test case 2", "OpenSSL AES-128 block arbitration", "Go crypto/cipher GCM"},
			"Ciphertext 0388dace..., tag ab6e47d4....")
	}
	// AES-128-GCM empty plaintext: GCM test case 1 tag.
	{
		m := methods["aes-128-gcm"]
		a := newAEAD(m, make([]byte, 16))
		ct := a.Seal(nil, make([]byte, 12), nil, nil)
		want := "58e2fccefa7e3061367f1d57a4e7455a"
		if hx(ct) != want {
			panic("AES-128-GCM empty-plaintext tag mismatch: " + hx(ct))
		}
		add("AEAD-01b", "aes-128-gcm",
			map[string]any{"key": hx(make([]byte, 16)), "nonce": hx(make([]byte, 12)), "plaintext": ""},
			map[string]any{"ciphertextAndTag": want},
			[]string{"GCM spec (McGrew-Viega) test case 1", "Go crypto/cipher GCM"}, "")
	}
	// AES-256-GCM zero vector (library output; construction is
	// additionally covered end-to-end by the W17/W22 interop).
	{
		m := methods["aes-256-gcm"]
		a := newAEAD(m, make([]byte, 32))
		ct := a.Seal(nil, make([]byte, 12), make([]byte, 16), nil)
		add("AEAD-01c", "aes-256-gcm",
			map[string]any{"key": hx(make([]byte, 32)), "nonce": hx(make([]byte, 12)), "plaintext": hx(make([]byte, 16))},
			map[string]any{"ciphertextAndTag": hx(ct)},
			[]string{"Go crypto/cipher GCM", srcRustLive}, "")
	}
	// ChaCha20-Poly1305, RFC 8439 appendix A.5: the generator
	// asserts the published tag before writing.
	{
		key, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
		nonce, _ := hex.DecodeString("070000004041424344454647")
		aad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
		pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
		m := methods["chacha20-ietf-poly1305"]
		a := newAEAD(m, key)
		ct := a.Seal(nil, nonce, pt, aad)
		tag := ct[len(ct)-16:]
		if hx(tag) != "1ae10b594f09e26a7e902ecbd0600691" {
			panic("RFC 8439 A.5 tag mismatch: " + hx(tag))
		}
		add("AEAD-02", "chacha20-ietf-poly1305",
			map[string]any{"key": hx(key), "nonce": hx(nonce), "aad": hx(aad), "plaintext": hx(pt)},
			map[string]any{"ciphertextAndTag": hx(ct)},
			[]string{"RFC 8439 appendix A.5 published vector", "golang.org/x/crypto/chacha20poly1305"},
			"Tag 1ae10b59... is the RFC's published value (with the RFC's AAD 50515253c0c1c2c3c4c5c6c7).")
	}
	// XChaCha20-Poly1305 with a 24-byte nonce (library output;
	// construction covered by W17-04 interop).
	{
		key := saltPattern(0x00, 32)
		nonce := saltPattern(0x40, 24)
		pt := pattern(64, 0x07)
		m := methods["xchacha20-ietf-poly1305"]
		a := newAEAD(m, key)
		ct := a.Seal(nil, nonce, pt, nil)
		add("AEAD-02b", "xchacha20-ietf-poly1305",
			map[string]any{"key": hx(key), "nonce": hx(nonce), "plaintext": hx(pt)},
			map[string]any{"ciphertextAndTag": hx(ct)},
			[]string{"golang.org/x/crypto/chacha20poly1305 (NewX)", srcRustLive}, "")
	}
	// 1 MiB plaintext: expected value stored as SHA-256 of the
	// full ciphertext so the vector file stays reviewable.
	{
		m := methods["aes-256-gcm"]
		a := newAEAD(m, saltPattern(0x00, 32))
		pt := pattern(1<<20, 0x11)
		ct := a.Seal(nil, saltPattern(0x60, 12), pt, nil)
		sum := sha256.Sum256(ct)
		add("AEAD-01d", "aes-256-gcm",
			map[string]any{"key": hx(saltPattern(0x00, 32)), "nonce": hx(saltPattern(0x60, 12)), "plaintextPattern": "pattern(1048576, 0x11) per genvectors pattern()", "plaintextLen": 1 << 20},
			map[string]any{"ciphertextAndTagSHA256": hx(sum[:]), "ciphertextAndTagLen": len(ct)},
			[]string{"Go crypto/cipher GCM"}, "Large-input smoke vector; digest form keeps the file small.")
	}
	return vs
}

// --- C. AEAD-2017 wire vectors ---------------------------------------

const pw2017 = "relavia-test-2017" // TEST-ONLY

func wire2017Vectors() []vector {
	var vs []vector
	tcp := func(id, prio, method, host string, port int, payloadLen int, respPayloadLen int, notes string) {
		m := methods[method]
		salt := saltPattern(0xA0, m.keyLen)
		rsalt := saltPattern(0x50, m.keyLen)
		payload := pattern(payloadLen, 0x21)
		rpayload := pattern(respPayloadLen, 0x33)
		vs = append(vs, vector{ID: id, Priority: prio, Category: "wire2017tcp", Method: method,
			Inputs: map[string]any{
				"password": pw2017, "salt": hx(salt), "responseSalt": hx(rsalt),
				"host": host, "port": port, "payload": hx(payload), "responsePayload": hx(rpayload),
			},
			Expected: map[string]any{
				"requestStream":  hx(wire2017TCP(m, pw2017, salt, host, port, payload)),
				"responseStream": hx(wire2017TCP(m, pw2017, rsalt, host, port, rpayload)),
			},
			Sources: []string{srcSIP004, srcRustLive, srcSingLive},
			Notes:   notes})
	}
	tcp("W17-01", "P0", "aes-256-gcm", "93.184.216.34", 80, 100, 64, "IPv4 target, small payload, both directions.")
	tcp("W17-02", "P0", "aes-128-gcm", "example.com", 443, 100, 64, "Domain target.")
	tcp("W17-03", "P0", "chacha20-ietf-poly1305", "2001:db8::1", 8388, 100, 64, "IPv6 target.")
	tcp("W17-04", "P0", "xchacha20-ietf-poly1305", "example.org", 53, 100, 64, "Domain target, XChaCha (24-byte nonce).")

	// W17-05: chunk-boundary pair. The address header for
	// 93.184.216.34:80 is 7 bytes, so payload sizes are chosen
	// to make the first chunk's plaintext exactly 0x3FFF, and
	// 0x3FFF+1 overall in the second vector.
	{
		m := methods["aes-256-gcm"]
		salt := saltPattern(0xA0, m.keyLen)
		addrLen := len(socksAddr("93.184.216.34", 80))
		for _, tc := range []struct {
			id    string
			total int
		}{{"W17-05a", chunkCap2017}, {"W17-05b", chunkCap2017 + 1}} {
			payload := pattern(tc.total-addrLen, 0x21)
			vs = append(vs, vector{ID: tc.id, Priority: "P0", Category: "wire2017tcp", Method: "aes-256-gcm",
				Inputs: map[string]any{
					"password": pw2017, "salt": hx(salt), "host": "93.184.216.34", "port": 80,
					"payload": hx(payload),
				},
				Expected: map[string]any{
					"requestStream": hx(wire2017TCP(m, pw2017, salt, "93.184.216.34", 80, payload)),
				},
				Sources: []string{srcSIP004, srcSingLive},
				Notes:   fmt.Sprintf("Plaintext stream (addr+payload) is exactly %d bytes: chunk split boundary.", tc.total)})
		}
	}
	// W17-06: empty payload - the first chunk carries only the
	// address header.
	tcp("W17-06", "P0", "aes-256-gcm", "93.184.216.34", 80, 0, 0, "Empty payload: first chunk is the address header alone.")

	// W17-07: UDP single packets, four methods, rotating target
	// forms; response direction included.
	udp := func(id, method, host string, port int) {
		m := methods[method]
		salt := saltPattern(0xA0, m.keyLen)
		rsalt := saltPattern(0x50, m.keyLen)
		payload := pattern(48, 0x21)
		rpayload := pattern(40, 0x33)
		vs = append(vs, vector{ID: id, Priority: "P0", Category: "wire2017udp", Method: method,
			Inputs: map[string]any{
				"password": pw2017, "salt": hx(salt), "responseSalt": hx(rsalt),
				"host": host, "port": port, "payload": hx(payload), "responsePayload": hx(rpayload),
			},
			Expected: map[string]any{
				"requestPacket":  hx(wire2017UDP(m, pw2017, salt, host, port, payload)),
				"responsePacket": hx(wire2017UDP(m, pw2017, rsalt, host, port, rpayload)),
			},
			Sources: []string{srcSIP004, srcRustLive, srcSingLive}})
	}
	udp("W17-07a", "aes-128-gcm", "93.184.216.34", 53)
	udp("W17-07b", "aes-256-gcm", "example.com", 53)
	udp("W17-07c", "chacha20-ietf-poly1305", "2001:db8::2", 53)
	udp("W17-07d", "xchacha20-ietf-poly1305", "93.184.216.34", 123)

	// W17-08 (P1): UDP large packet; 255-byte domain TCP.
	{
		m := methods["aes-256-gcm"]
		salt := saltPattern(0xA0, m.keyLen)
		payload := pattern(4096, 0x21)
		vs = append(vs, vector{ID: "W17-08a", Priority: "P1", Category: "wire2017udp", Method: "aes-256-gcm",
			Inputs:   map[string]any{"password": pw2017, "salt": hx(salt), "host": "93.184.216.34", "port": 53, "payload": hx(payload)},
			Expected: map[string]any{"requestPacket": hx(wire2017UDP(m, pw2017, salt, "93.184.216.34", 53, payload))},
			Sources:  []string{srcSIP004, srcSingLive}, Notes: "4096-byte UDP payload."})
		host255 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)
		if len(host255) != 255 {
			panic("host255 length")
		}
		p2 := pattern(16, 0x21)
		vs = append(vs, vector{ID: "W17-08b", Priority: "P1", Category: "wire2017tcp", Method: "aes-256-gcm",
			Inputs:   map[string]any{"password": pw2017, "salt": hx(salt), "host": host255, "port": 80, "payload": hx(p2)},
			Expected: map[string]any{"requestStream": hx(wire2017TCP(m, pw2017, salt, host255, 80, p2))},
			Sources:  []string{srcSIP004}, Notes: "255-byte domain name (SOCKS address length boundary)."})
	}
	// W17-09 (P1): chunk-per-write stream - the address header
	// as its own chunk, then five payload chunks; the nonce
	// counter must advance once per AEAD operation across all
	// 6 chunks.
	{
		m := methods["aes-256-gcm"]
		salt := saltPattern(0xA0, m.keyLen)
		master := evpBytesToKey([]byte(pw2017), m.keyLen)
		subkey := hkdfSHA1Subkey(master, salt, m.keyLen)
		a := newAEAD(m, subkey)
		nonce := newNonceCounter(m.nonceLen)
		out := append([]byte{}, salt...)
		writes := [][]byte{socksAddr("93.184.216.34", 80)}
		for i := 0; i < 5; i++ {
			writes = append(writes, pattern(20+i*7, byte(0x40+i)))
		}
		var inputs []string
		for _, w := range writes {
			inputs = append(inputs, hx(w))
			out = a.Seal(out, nonce.next(), u16be(len(w)), nil)
			out = a.Seal(out, nonce.next(), w, nil)
		}
		vs = append(vs, vector{ID: "W17-09", Priority: "P1", Category: "wire2017tcp", Method: "aes-256-gcm",
			Inputs:   map[string]any{"password": pw2017, "salt": hx(salt), "chunks": inputs},
			Expected: map[string]any{"requestStream": hx(out)},
			Sources:  []string{srcSIP004},
			Notes:    "Chunk-per-write stream: nonce counter continuity across 6 chunks (12 AEAD operations)."})
	}
	return vs
}

// --- D. SS2022 wire vectors -------------------------------------------

const tsFixed = 1700000000 // fixed vector timestamp (SIP022 vectors are reproducible offline)

func wire2022Vectors() []vector {
	var vs []vector
	tcp := func(id, prio, method string, psk []byte, host string, port int) {
		m := methods[method]
		salt := saltPattern(0xA0, m.keyLen)
		rsalt := saltPattern(0x50, m.keyLen)
		padding := pattern(8, 0x77)
		payload := pattern(100, 0x21)
		rpayload := pattern(64, 0x33)
		vs = append(vs, vector{ID: id, Priority: prio, Category: "wire2022tcp", Method: method,
			Inputs: map[string]any{
				"psk": hx(psk), "pskBase64": b64(psk), "salt": hx(salt), "responseSalt": hx(rsalt),
				"timestamp": tsFixed, "host": host, "port": port,
				"padding": hx(padding), "payload": hx(payload), "responsePayload": hx(rpayload),
			},
			Expected: map[string]any{
				"requestStream":  hx(wire2022TCPRequest(m, psk, salt, tsFixed, host, port, padding, payload, nil)),
				"responseStream": hx(wire2022TCPResponse(m, psk, rsalt, salt, tsFixed, rpayload, nil)),
			},
			Sources: []string{srcSIP022, srcRustLive, srcSingLive},
			Notes:   "Payload rides as the variable header's initial payload; response payload is the first payload chunk."})
	}
	tcp("W22-01", "P0", "2022-blake3-aes-256-gcm", psk32, "93.184.216.34", 80)
	tcp("W22-02", "P0", "2022-blake3-aes-128-gcm", psk16, "example.com", 443)
	tcp("W22-03", "P0", "2022-blake3-chacha20-poly1305", psk32, "2001:db8::1", 8388)

	// W22-04: UDP single packets, three methods, both directions.
	{
		const clientSID = 0x0102030405060708
		const serverSID = 0x1112131415161718
		// AES-128
		{
			m := methods["2022-blake3-aes-128-gcm"]
			payload := pattern(32, 0x21)
			rpayload := pattern(24, 0x33)
			vs = append(vs, vector{ID: "W22-04a", Priority: "P0", Category: "wire2022udp", Method: m.name,
				Inputs: map[string]any{
					"psk": hx(psk16), "clientSessionID": clientSID, "serverSessionID": serverSID,
					"packetID": 0, "timestamp": tsFixed, "host": "93.184.216.34", "port": 53,
					"payload": hx(payload), "responsePayload": hx(rpayload),
				},
				Expected: map[string]any{
					"requestPacket":  hx(wire2022UDPAES(m, psk16, clientSID, 0, tsFixed, false, 0, "", "93.184.216.34", 53, payload)),
					"responsePacket": hx(wire2022UDPAES(m, psk16, serverSID, 0, tsFixed, true, clientSID, "", "93.184.216.34", 53, rpayload)),
				},
				Sources: []string{srcSIP022, srcRustLive, srcSingLive}})
		}
		// AES-256, domain target, packet ID 7 (non-zero counter).
		{
			m := methods["2022-blake3-aes-256-gcm"]
			payload := pattern(32, 0x21)
			vs = append(vs, vector{ID: "W22-04b", Priority: "P0", Category: "wire2022udp", Method: m.name,
				Inputs: map[string]any{
					"psk": hx(psk32), "clientSessionID": clientSID, "packetID": 7, "timestamp": tsFixed,
					"host": "example.com", "port": 53, "payload": hx(payload),
				},
				Expected: map[string]any{
					"requestPacket": hx(wire2022UDPAES(m, psk32, clientSID, 7, tsFixed, false, 0, "", "example.com", 53, payload)),
				},
				Sources: []string{srcSIP022, srcSingLive}})
		}
		// ChaCha: fixed 24-byte nonce.
		{
			m := methods["2022-blake3-chacha20-poly1305"]
			nonce := saltPattern(0x70, 24)
			rnonce := saltPattern(0x90, 24)
			payload := pattern(32, 0x21)
			rpayload := pattern(24, 0x33)
			vs = append(vs, vector{ID: "W22-04c", Priority: "P0", Category: "wire2022udp", Method: m.name,
				Inputs: map[string]any{
					"psk": hx(psk32), "clientSessionID": clientSID, "serverSessionID": serverSID,
					"packetID": 0, "timestamp": tsFixed, "nonce": hx(nonce), "responseNonce": hx(rnonce),
					"host": "93.184.216.34", "port": 53, "payload": hx(payload), "responsePayload": hx(rpayload),
				},
				Expected: map[string]any{
					"requestPacket":  hx(wire2022UDPChaCha(m, psk32, nonce, clientSID, 0, tsFixed, false, 0, "", "93.184.216.34", 53, payload)),
					"responsePacket": hx(wire2022UDPChaCha(m, psk32, rnonce, serverSID, 0, tsFixed, true, clientSID, "", "93.184.216.34", 53, rpayload)),
				},
				Sources: []string{srcSIP022, srcRustLive, srcSingLive}})
		}
	}
	// W22-05 (P1): cross-chunk TCP payload via data chunks (empty
	// initial payload + non-zero padding), and a 3-packet UDP
	// sequence with incrementing packet IDs.
	{
		m := methods["2022-blake3-aes-256-gcm"]
		salt := saltPattern(0xA0, m.keyLen)
		padding := pattern(4, 0x77)
		payload := pattern(chunkCap2017+100, 0x21)
		vs = append(vs, vector{ID: "W22-05a", Priority: "P1", Category: "wire2022tcp", Method: m.name,
			Inputs: map[string]any{
				"psk": hx(psk32), "salt": hx(salt), "timestamp": tsFixed, "host": "93.184.216.34", "port": 80,
				"padding": hx(padding), "payload": hx(payload),
			},
			Expected: map[string]any{
				"requestStream": hx(wire2022TCPRequest(m, psk32, salt, tsFixed, "93.184.216.34", 80, padding, nil, payload)),
			},
			Sources: []string{srcSIP022, srcSingLive},
			Notes:   "Payload in data chunks (0x3FFF sender split; receivers must accept up to 0xFFFF per SIP022 3.1.2)."})
		var packets []string
		for pid := uint64(0); pid < 3; pid++ {
			packets = append(packets, hx(wire2022UDPAES(methods["2022-blake3-aes-128-gcm"], psk16, 0x0102030405060708, pid, tsFixed, false, 0, "", "93.184.216.34", 53, pattern(16, byte(0x21+pid)))))
		}
		vs = append(vs, vector{ID: "W22-05b", Priority: "P1", Category: "wire2022udp", Method: "2022-blake3-aes-128-gcm",
			Inputs: map[string]any{
				"psk": hx(psk16), "clientSessionID": 0x0102030405060708, "timestamp": tsFixed,
				"host": "93.184.216.34", "port": 53, "packetIDs": []int{0, 1, 2},
			},
			Expected: map[string]any{"requestPackets": packets},
			Sources:  []string{srcSIP022},
			Notes:    "Three packets, packet IDs 0,1,2, payloads pattern(16, 0x21+packetID)."})
	}
	// W22-06 (P1): timestamp tolerance boundary values. These are
	// behavioural vectors (server acceptance), recorded here so
	// the rig's error set can reference fixed numbers: tolerance
	// is 30 s (SIP022 3.1.3/3.2.3), so -30/+30 are in-window and
	// -31/+31 are replay-class.
	vs = append(vs, vector{ID: "W22-06", Priority: "P1", Category: "behavioral", Method: "2022-blake3-aes-256-gcm",
		Inputs:   map[string]any{"toleranceSeconds": 30, "offsets": []int{-31, -30, 30, 31}},
		Expected: map[string]any{"accepted": []int{-30, 30}, "rejected": []int{-31, 31}},
		Sources:  []string{srcSIP022, srcSingLive},
		Notes:    "Exercised by the diffrig error set against both reference servers; not a byte vector."})
	return vs
}

// --- E. Negative vectors ----------------------------------------------

func negativeVectors() []vector {
	var vs []vector
	// NEG-01: W17-01's response stream with one bit flipped
	// inside the first length chunk's ciphertext. The salt is 32
	// bytes; the length chunk starts at offset 32.
	{
		m := methods["aes-256-gcm"]
		rsalt := saltPattern(0x50, m.keyLen)
		resp := wire2017TCP(m, pw2017, rsalt, "93.184.216.34", 80, pattern(64, 0x33))
		tampered := append([]byte{}, resp...)
		tampered[32+1] ^= 0x01
		vs = append(vs, vector{ID: "NEG-01", Priority: "P0", Category: "negative", Method: "aes-256-gcm",
			Inputs: map[string]any{
				"base": "W17-01 response stream", "tamperedOffset": 33, "xor": 1,
				"responseStream": hx(tampered), "salt": hx(rsalt), "password": pw2017,
				"host": "93.184.216.34", "port": 80,
			},
			Expected: map[string]any{
				"failStage": "response length chunk 0 AEAD open",
				"kind":      "handshake_failed",
				"plaintext": "none released",
			},
			Sources: []string{srcSIP004},
			Notes:   "Bit flip inside the encrypted length chunk: open must fail before any plaintext is released."})
	}
	// NEG-02: truncations of W17-01's request stream at four
	// points: mid-salt, mid length chunk, mid length tag, mid
	// payload tag.
	{
		m := methods["aes-256-gcm"]
		salt := saltPattern(0xA0, m.keyLen)
		req := wire2017TCP(m, pw2017, salt, "93.184.216.34", 80, pattern(100, 0x21))
		cuts := map[string]int{
			"midSalt":        16,     // inside the 32-byte salt
			"midLengthChunk": 32 + 1, // inside the 2-byte length ciphertext
			"midLengthTag":   32 + 10,
			"midPayloadTag":  len(req) - 8,
		}
		exp := map[string]any{}
		for name, cut := range cuts {
			exp[name] = hx(req[:cut])
		}
		vs = append(vs, vector{ID: "NEG-02", Priority: "P0", Category: "negative", Method: "aes-256-gcm",
			Inputs: map[string]any{
				"base": "W17-01 request stream", "password": pw2017, "salt": hx(salt),
				"host": "93.184.216.34", "port": 80, "fullStream": hx(req), "cutPoints": cuts,
			},
			Expected: exp,
			Sources:  []string{srcSIP004},
			Notes:    "Each truncated stream must fail cleanly (EOF-class error), never hang or panic."})
	}
	// NEG-05 (data half): an invalid-base64 PSK and a
	// wrong-length PSK; the engine-level expectations live in
	// the engine tests, the values are recorded here.
	vs = append(vs, vector{ID: "NEG-05", Priority: "P0", Category: "negative", Method: "2022-blake3-aes-128-gcm",
		Inputs: map[string]any{
			"invalidBase64": "not!base64!",
			"wrongLength":   b64(saltPattern(0x00, 24)), // 24 bytes for a 16-byte method
		},
		Expected: map[string]any{"kind": "invalid_config", "networkTraffic": "none"},
		Sources:  []string{srcSIP022, srcSingLive},
		Notes:    "Rejected before any dial. Unpadded-but-valid base64 is ACCEPTED (shadowsocks-rust behaviour, spec section 6 item 7)."})
	// NEG-08 (data half): multi-PSK and plugin-carrying node
	// shapes route to the fallback backend.
	vs = append(vs, vector{ID: "NEG-08", Priority: "P1", Category: "negative", Method: "2022-blake3-aes-256-gcm",
		Inputs: map[string]any{
			"multiPSKPassword": b64(psk32) + ":" + b64(psk32),
			"plugin":           "obfs-local",
			"pluginOpts":       "obfs=http",
		},
		Expected: map[string]any{"kind": "unsupported", "route": "singbox fallback with logged reason"},
		Sources:  []string{srcSIP022},
		Notes:    "Exercised by the composite-adapter policy tests."})
	return vs
}
