package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"openproxy/core/kernel"
)

func TestNewClientClassification(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		password string
		kind     kernel.Kind // "" means success
	}{
		{"ok 2017", "aes-256-gcm", "pw", ""},
		{"ok 2022", "2022-blake3-aes-256-gcm", b64std(bytes.Repeat([]byte{7}, 32)), ""},
		{"ok 2022 unpadded base64", "2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw", ""},
		{"unknown method", "aes-256-gcm-plus", "pw", kernel.KindUnsupported},
		{"legacy stream cipher", "aes-256-cfb", "pw", kernel.KindUnsupported},
		{"legacy aead 2017 sip004 removed", "aes-256-gcm-sip004", "pw", kernel.KindUnsupported},
		{"empty 2017 password", "aes-128-gcm", "", kernel.KindInvalidConfig},
		{"2022 bad base64", "2022-blake3-aes-128-gcm", "!!!not-base64!!!", kernel.KindInvalidConfig},
		{"2022 wrong length", "2022-blake3-aes-128-gcm", b64std([]byte{1, 2, 3}), kernel.KindInvalidConfig},
		{"2022 multi psk", "2022-blake3-aes-256-gcm", b64std(bytes.Repeat([]byte{7}, 32)) + ":" + b64std(bytes.Repeat([]byte{9}, 32)), kernel.KindUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(tc.method, tc.password)
			if tc.kind == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			if !kernel.IsKind(err, tc.kind) {
				t.Fatalf("want kind %s, got %v", tc.kind, err)
			}
		})
	}
}

func TestSlidingWindow(t *testing.T) {
	w := &slidingWindow{}
	if !w.check(0) || !w.check(5000) {
		t.Fatal("fresh window must accept")
	}
	w.add(5000)
	if w.check(5000) {
		t.Fatal("replayed packet ID accepted")
	}
	if !w.check(4999) || !w.check(5001) {
		t.Fatal("neighbours of the highest ID must be accepted")
	}
	w.add(4999)
	if w.check(4999) {
		t.Fatal("replayed older ID accepted")
	}
	// Slide far forward: IDs more than windowSize behind the
	// new highest fall out and must be rejected as too old.
	w.add(5000 + windowSize + 10)
	if w.check(5000) {
		t.Fatal("packet ID older than the window accepted")
	}
}

func TestParseSocksAddr(t *testing.T) {
	for _, a := range []Addr{
		{Host: "93.184.216.34", Port: 80},
		{Host: "example.com", Port: 443},
		{Host: "2001:db8::1", Port: 853},
	} {
		enc := a.appendSocks(nil)
		got, n, err := parseSocksAddr(append(enc, 0xAA))
		if err != nil {
			t.Fatalf("%v: %v", a, err)
		}
		if got != a || n != len(enc) {
			t.Fatalf("round trip = %v consumed %d of %d bytes", got, n, len(enc))
		}
	}
	if _, _, err := parseSocksAddr([]byte{0x09, 1, 2}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown ATYP: got %v", err)
	}
	if _, _, err := parseSocksAddr([]byte{0x01, 1}); err == nil {
		t.Fatal("truncated address accepted")
	}
}

// craftResponse2022 builds a 2022 response prologue with
// caller-controlled fixed-header fields, for validation tests.
func craftResponse2022(t *testing.T, c *Client, respSalt, echoSalt []byte, typ byte, ts int64, payload []byte) []byte {
	t.Helper()
	m := c.method
	sub := sessionKey2022(c.key, respSalt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		t.Fatal(err)
	}
	nonce := newNonceCounter(m.NonceLen)
	fixed := []byte{typ}
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(ts))
	fixed = append(fixed, tb[:]...)
	fixed = append(fixed, echoSalt...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
	fixed = append(fixed, lb[:]...)
	out := append([]byte{}, respSalt...)
	out = a.Seal(out, nonce.next(), fixed, nil)
	out = a.Seal(out, nonce.next(), payload, nil)
	return out
}

func TestResponse2022Validation(t *testing.T) {
	client, err := NewClient("2022-blake3-aes-256-gcm", b64std(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	client.now = func() time.Time { return now }
	reqSalt := bytes.Repeat([]byte{0x11}, 32)
	respSalt := bytes.Repeat([]byte{0x22}, 32)
	payload := []byte("hello")

	good := craftResponse2022(t, client, respSalt, reqSalt, 0x01, now.Unix(), payload)
	r, err := client.readResponsePrologue(bytes.NewReader(good), reqSalt)
	if err != nil {
		t.Fatalf("good prologue: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("good payload = %q, %v", plain, err)
	}

	badType := craftResponse2022(t, client, respSalt, reqSalt, 0x00, now.Unix(), payload)
	if _, err := client.readResponsePrologue(bytes.NewReader(badType), reqSalt); !errors.Is(err, ErrProtocol) {
		t.Fatalf("bad type: got %v", err)
	}
	badEcho := craftResponse2022(t, client, respSalt, bytes.Repeat([]byte{0x33}, 32), 0x01, now.Unix(), payload)
	if _, err := client.readResponsePrologue(bytes.NewReader(badEcho), reqSalt); !errors.Is(err, ErrProtocol) {
		t.Fatalf("bad echoed salt: got %v", err)
	}
	stale := craftResponse2022(t, client, respSalt, reqSalt, 0x01, now.Unix()-31, payload)
	if _, err := client.readResponsePrologue(bytes.NewReader(stale), reqSalt); !errors.Is(err, ErrProtocol) {
		t.Fatalf("stale timestamp: got %v", err)
	}
	edge := craftResponse2022(t, client, respSalt, reqSalt, 0x01, now.Unix()-30, payload)
	if _, err := client.readResponsePrologue(bytes.NewReader(edge), reqSalt); err != nil {
		t.Fatalf("timestamp at exactly -30s must pass: %v", err)
	}
}

func TestChunkReaderCapEnforced(t *testing.T) {
	m, _ := LookupMethod("aes-256-gcm")
	master := EVPBytesToKey([]byte("pw"), m.KeyLen)
	salt := bytes.Repeat([]byte{0x44}, 32)
	sub := subkey2017(master, salt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		t.Fatal(err)
	}
	nonce := newNonceCounter(m.NonceLen)
	// Length chunk announcing more than the 2017 cap.
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(chunkCap2017+1))
	wire := a.Seal(nil, nonce.next(), lb[:], nil)
	wire = a.Seal(wire, nonce.next(), bytes.Repeat([]byte{1}, chunkCap2017+1), nil)
	cr := newChunkReader(bytes.NewReader(wire), a, newNonceCounter(m.NonceLen), chunkCap2017)
	if _, err := io.ReadAll(cr); !errors.Is(err, ErrProtocol) {
		t.Fatalf("over-cap chunk: got %v", err)
	}
}
