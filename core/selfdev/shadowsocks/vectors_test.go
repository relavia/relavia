package shadowsocks

// Vector tests: the engine is verified against the frozen
// vector set in testdata/vectors.json (checklist gate G3: P0
// vectors must pass 100%). The vectors were generated from the
// SIP texts and dual-source cross-checked offline; these tests
// are where the production engine proves it reproduces them
// byte for byte, in both directions.

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"openproxy/core/kernel"
)

type vecFile struct {
	Vectors []vecEntry `json:"vectors"`
}

type vecEntry struct {
	ID       string         `json:"id"`
	Priority string         `json:"priority"`
	Category string         `json:"category"`
	Method   string         `json:"method"`
	Inputs   map[string]any `json:"inputs"`
	Expected map[string]any `json:"expected"`
}

// testTB is the subset of *testing.T / *testing.F the vector
// loader needs (fuzz seed corpora load the same file).
type testTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

func loadVectors(t testTB) []vecEntry {
	t.Helper()
	f, err := os.Open("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	defer f.Close()
	// UseNumber: session IDs exceed float64's exact integer
	// range (2^53); decoding them as float64 silently rounds
	// the low bits and corrupts the vectors.
	dec := json.NewDecoder(f)
	dec.UseNumber()
	var vf vecFile
	if err := dec.Decode(&vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vf.Vectors
}

func vHex(t testTB, m map[string]any, key string) []byte {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("missing hex field %q", key)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return b
}

func vStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func vInt(m map[string]any, key string) int {
	n, _ := m[key].(json.Number)
	i, _ := n.Int64()
	return int(i)
}

func vUint64(m map[string]any, key string) uint64 {
	n, _ := m[key].(json.Number)
	i, _ := n.Int64()
	return uint64(i)
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// pattern mirrors the generator's deterministic payload filler.
func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i) ^ byte(i>>8) ^ seed
	}
	return out
}

func TestVectorsKDF(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Category != "kdf" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			switch {
			case v.Expected["masterKey"] != nil:
				pw := []byte(vStr(v.Inputs, "password"))
				if vStr(v.Inputs, "passwordHex") != "" {
					pw = vHex(t, v.Inputs, "passwordHex")
				}
				got := EVPBytesToKey(pw, vInt(v.Inputs, "keyLen"))
				if !bytes.Equal(got, vHex(t, v.Expected, "masterKey")) {
					t.Fatalf("EVPBytesToKey = %x, want %s", got, v.Expected["masterKey"])
				}
			case v.Expected["subkey"] != nil && v.Inputs["masterKey"] != nil:
				got := subkey2017(vHex(t, v.Inputs, "masterKey"), vHex(t, v.Inputs, "salt"), vInt(v.Inputs, "keyLen"))
				if !bytes.Equal(got, vHex(t, v.Expected, "subkey")) {
					t.Fatalf("HKDF subkey mismatch")
				}
			case v.Expected["subkey"] != nil && v.Inputs["psk"] != nil:
				got := sessionKey2022(vHex(t, v.Inputs, "psk"), vHex(t, v.Inputs, "salt"), vInt(v.Inputs, "keyLen"))
				if !bytes.Equal(got, vHex(t, v.Expected, "subkey")) {
					t.Fatalf("BLAKE3 subkey mismatch")
				}
			case v.Expected["encryptedSeparateHeader"] != nil:
				block, err := aes.NewCipher(vHex(t, v.Inputs, "psk"))
				if err != nil {
					t.Fatal(err)
				}
				out := make([]byte, 16)
				block.Encrypt(out, vHex(t, v.Inputs, "separateHeader"))
				if !bytes.Equal(out, vHex(t, v.Expected, "encryptedSeparateHeader")) {
					t.Fatalf("separate header mismatch")
				}
			default:
				t.Fatalf("unhandled KDF vector shape")
			}
		})
	}
}

func TestVectorsAEAD(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Category != "aead" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			m, _ := LookupMethod(v.Method)
			a, err := m.newAEAD(vHex(t, v.Inputs, "key"))
			if err != nil {
				t.Fatal(err)
			}
			var aad []byte
			if _, ok := v.Inputs["aad"]; ok {
				aad = vHex(t, v.Inputs, "aad")
			}
			var pt []byte
			if _, ok := v.Inputs["plaintext"]; ok {
				pt = vHex(t, v.Inputs, "plaintext")
			} else {
				pt = pattern(vInt(v.Inputs, "plaintextLen"), 0x11)
			}
			ct := a.Seal(nil, vHex(t, v.Inputs, "nonce"), pt, aad)
			if _, ok := v.Expected["ciphertextAndTag"]; ok {
				if !bytes.Equal(ct, vHex(t, v.Expected, "ciphertextAndTag")) {
					t.Fatalf("ciphertext mismatch")
				}
			} else {
				sum := sha256.Sum256(ct)
				if hex.EncodeToString(sum[:]) != vStr(v.Expected, "ciphertextAndTagSHA256") {
					t.Fatalf("ciphertext digest mismatch")
				}
			}
		})
	}
}

// buildStream2017 reproduces the engine's request stream for a
// fixed salt, mirroring wrapTCP exactly: salt, then a chunk
// writer whose buffer is seeded with the address header, so the
// address shares the first payload chunk.
func buildStream2017(t *testing.T, c *Client, salt []byte, target Addr, payload []byte) []byte {
	t.Helper()
	m := c.method
	sub := subkey2017(c.key, salt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		t.Fatal(err)
	}
	nonce := newNonceCounter(m.NonceLen)
	out := append([]byte{}, salt...)
	var buf bytes.Buffer
	cw := newChunkWriter(&buf, a, nonce, chunkCap2017)
	cw.buf = target.appendSocks(cw.buf)
	if _, err := cw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := cw.Flush(); err != nil {
		t.Fatal(err)
	}
	return append(out, buf.Bytes()...)
}

func buildStream2017Chunks(t *testing.T, m Method, password string, salt []byte, chunks []any) []byte {
	t.Helper()
	sub := subkey2017(EVPBytesToKey([]byte(password), m.KeyLen), salt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		t.Fatal(err)
	}
	nonce := newNonceCounter(m.NonceLen)
	out := append([]byte{}, salt...)
	for _, cv := range chunks {
		chunk, err := hex.DecodeString(cv.(string))
		if err != nil {
			t.Fatal(err)
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(chunk)))
		out = a.Seal(out, nonce.next(), lb[:], nil)
		out = a.Seal(out, nonce.next(), chunk, nil)
	}
	return out
}

func TestVectorsWire2017TCP(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Category != "wire2017tcp" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			m, _ := LookupMethod(v.Method)
			client, err := NewClient(v.Method, vStr(v.Inputs, "password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := v.Expected["requestStream"]; ok {
				salt := vHex(t, v.Inputs, "salt")
				var got []byte
				if chunks, ok := v.Inputs["chunks"]; ok {
					got = buildStream2017Chunks(t, m, vStr(v.Inputs, "password"), salt, chunks.([]any))
				} else {
					target := Addr{Host: vStr(v.Inputs, "host"), Port: vInt(v.Inputs, "port")}
					got = buildStream2017(t, client, salt, target, vHex(t, v.Inputs, "payload"))
				}
				want := vHex(t, v.Expected, "requestStream")
				if !bytes.Equal(got, want) {
					t.Fatalf("request stream mismatch (%d vs %d bytes)", len(got), len(want))
				}
			}
			if _, ok := v.Expected["responseStream"]; ok {
				r, err := client.readResponsePrologue(bytes.NewReader(vHex(t, v.Expected, "responseStream")), nil)
				if err != nil {
					t.Fatalf("response prologue: %v", err)
				}
				plain, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				if !bytes.Equal(plain, vHex(t, v.Inputs, "responsePayload")) {
					t.Fatalf("response payload = %d bytes, want %d", len(plain), len(vHex(t, v.Inputs, "responsePayload")))
				}
			}
		})
	}
}

func TestVectorsWire2022TCP(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Category != "wire2022tcp" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			m, _ := LookupMethod(v.Method)
			psk := vHex(t, v.Inputs, "psk")
			pw := vStr(v.Inputs, "pskBase64")
			if pw == "" {
				pw = b64std(psk)
			}
			client, err := NewClient(v.Method, pw)
			if err != nil {
				t.Fatal(err)
			}
			ts := int64(vUint64(v.Inputs, "timestamp"))
			client.now = func() time.Time { return time.Unix(ts, 0) }

			salt := vHex(t, v.Inputs, "salt")
			sub := sessionKey2022(psk, salt, m.KeyLen)
			a, err := m.newAEAD(sub)
			if err != nil {
				t.Fatal(err)
			}
			nonce := newNonceCounter(m.NonceLen)
			target := Addr{Host: vStr(v.Inputs, "host"), Port: vInt(v.Inputs, "port")}
			var buf bytes.Buffer
			if v.ID == "W22-05a" {
				// Payload rides in data chunks; the variable
				// header carries padding only.
				if err := client.writeRequestHeader2022With(&buf, a, nonce, salt, target,
					vHex(t, v.Inputs, "padding"), nil); err != nil {
					t.Fatal(err)
				}
				cw := newChunkWriter(&buf, a, nonce, chunkCap2017)
				if _, err := cw.Write(vHex(t, v.Inputs, "payload")); err != nil {
					t.Fatal(err)
				}
				if err := cw.Flush(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := client.writeRequestHeader2022With(&buf, a, nonce, salt, target,
					vHex(t, v.Inputs, "padding"), vHex(t, v.Inputs, "payload")); err != nil {
					t.Fatal(err)
				}
			}
			want := vHex(t, v.Expected, "requestStream")
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("request stream mismatch (%d vs %d bytes)", buf.Len(), len(want))
			}
			if _, ok := v.Expected["responseStream"]; ok {
				r, err := client.readResponsePrologue(bytes.NewReader(vHex(t, v.Expected, "responseStream")), salt)
				if err != nil {
					t.Fatalf("response prologue: %v", err)
				}
				plain, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				if !bytes.Equal(plain, vHex(t, v.Inputs, "responsePayload")) {
					t.Fatalf("response payload mismatch")
				}
			}
		})
	}
}

// newVectorPacketConn builds a PacketConn whose 2022 client
// session ID is the vector's: the engine draws the ID from its
// rand source, so the test feeds it the vector's ID bytes (plus
// the vector's ChaCha nonce when present).
func newVectorPacketConn(t *testing.T, v vecEntry) *PacketConn {
	t.Helper()
	client, err := NewClient(v.Method, b64std(vHex(t, v.Inputs, "psk")))
	if err != nil {
		t.Fatal(err)
	}
	ts := int64(vUint64(v.Inputs, "timestamp"))
	client.now = func() time.Time { return time.Unix(ts, 0) }
	randBytes := u64be(vUint64(v.Inputs, "clientSessionID"))
	if _, ok := v.Inputs["nonce"]; ok {
		randBytes = append(randBytes, vHex(t, v.Inputs, "nonce")...)
	}
	client.rand = bytes.NewReader(randBytes)
	pc := client.newPacketConn(nil)
	pc.packetID = vUint64(v.Inputs, "packetID")
	return pc
}

func TestVectorsWireUDP(t *testing.T) {
	for _, v := range loadVectors(t) {
		switch v.Category {
		case "wire2017udp":
			t.Run(v.ID, func(t *testing.T) {
				m, _ := LookupMethod(v.Method)
				master := EVPBytesToKey([]byte(vStr(v.Inputs, "password")), m.KeyLen)
				target := Addr{Host: vStr(v.Inputs, "host"), Port: vInt(v.Inputs, "port")}
				got := encodePacket2017(m, master, vHex(t, v.Inputs, "salt"), target, vHex(t, v.Inputs, "payload"))
				if !bytes.Equal(got, vHex(t, v.Expected, "requestPacket")) {
					t.Fatalf("request packet mismatch")
				}
				if _, ok := v.Expected["responsePacket"]; ok {
					addr, plain, err := decodePacket2017(m, master, vHex(t, v.Expected, "responsePacket"))
					if err != nil {
						t.Fatalf("decode response: %v", err)
					}
					if addr != target || !bytes.Equal(plain, vHex(t, v.Inputs, "responsePayload")) {
						t.Fatalf("response decode = %v / %d bytes", addr, len(plain))
					}
				}
			})
		case "wire2022udp":
			t.Run(v.ID, func(t *testing.T) {
				target := Addr{Host: vStr(v.Inputs, "host"), Port: vInt(v.Inputs, "port")}
				if packets, ok := v.Expected["requestPackets"]; ok {
					for i, pv := range packets.([]any) {
						want, _ := hex.DecodeString(pv.(string))
						pc := newVectorPacketConn(t, v)
						pc.packetID = uint64(i)
						got, err := pc.encodeLocked(target, pattern(16, byte(0x21+i)))
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got, want) {
							t.Fatalf("packet %d mismatch", i)
						}
					}
					return
				}
				pc := newVectorPacketConn(t, v)
				got, err := pc.encodeLocked(target, vHex(t, v.Inputs, "payload"))
				if err != nil {
					t.Fatal(err)
				}
				want := vHex(t, v.Expected, "requestPacket")
				if !bytes.Equal(got, want) {
					t.Fatalf("request packet mismatch (%d vs %d bytes)", len(got), len(want))
				}
				if _, ok := v.Expected["responsePacket"]; ok {
					addr, plain, err := pc.decodeLocked(vHex(t, v.Expected, "responsePacket"))
					if err != nil {
						t.Fatalf("decode response: %v", err)
					}
					if addr != target || !bytes.Equal(plain, vHex(t, v.Inputs, "responsePayload")) {
						t.Fatalf("response decode = %v / %d bytes", addr, len(plain))
					}
				}
			})
		}
	}
}

func TestVectorsNegative(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Category != "negative" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			switch v.ID {
			case "NEG-01":
				client, err := NewClient(v.Method, vStr(v.Inputs, "password"))
				if err != nil {
					t.Fatal(err)
				}
				r, err := client.readResponsePrologue(bytes.NewReader(vHex(t, v.Inputs, "responseStream")), nil)
				if err != nil {
					t.Fatalf("prologue: %v", err)
				}
				_, err = io.ReadAll(r)
				if !errors.Is(err, ErrAEADFailure) {
					t.Fatalf("tampered stream: got err %v, want AEAD failure", err)
				}
			case "NEG-02":
				client, err := NewClient(v.Method, vStr(v.Inputs, "password"))
				if err != nil {
					t.Fatal(err)
				}
				for name := range v.Expected {
					truncated := vHex(t, v.Expected, name)
					r, err := client.readResponsePrologue(bytes.NewReader(truncated), nil)
					if err != nil {
						continue // failing at the prologue is a clean failure
					}
					if _, err := io.ReadAll(r); err == nil {
						t.Fatalf("%s: truncated stream read without error", name)
					}
				}
			case "NEG-05":
				if _, err := NewClient(v.Method, vStr(v.Inputs, "invalidBase64")); !kernel.IsKind(err, kernel.KindInvalidConfig) {
					t.Fatalf("invalid base64: got %v", err)
				}
				if _, err := NewClient(v.Method, vStr(v.Inputs, "wrongLength")); !kernel.IsKind(err, kernel.KindInvalidConfig) {
					t.Fatalf("wrong length: got %v", err)
				}
			case "NEG-08":
				if _, err := NewClient(v.Method, vStr(v.Inputs, "multiPSKPassword")); !kernel.IsKind(err, kernel.KindUnsupported) {
					t.Fatalf("multi-PSK: got %v", err)
				}
			}
		})
	}
}
