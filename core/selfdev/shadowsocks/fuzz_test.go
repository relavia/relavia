package shadowsocks

// Fuzz targets (spec section 4.5): every decoder entry point
// must survive arbitrary bytes without panics, hangs or
// unbounded allocation. Seed corpora come from the frozen
// vectors. CI runs each target for a bounded time before merge;
// release candidates accumulate the long quota recorded in the
// differential run log.

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func fuzzClient(t testTB, method, password string) *Client {
	t.Helper()
	c, err := NewClient(method, password)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1700000000, 0) }
	return c
}

func FuzzDecodePacket2017(f *testing.F) {
	c := fuzzClient(f, "aes-256-gcm", "relavia-test-2017")
	for _, v := range loadVectors(f) {
		if v.Category == "wire2017udp" {
			f.Add(vHex(f, v.Expected, "requestPacket"))
			if _, ok := v.Expected["responsePacket"]; ok {
				f.Add(vHex(f, v.Expected, "responsePacket"))
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _, _ = decodePacket2017(c.method, c.key, packet)
	})
}

func fuzzDecodePacket2022(f *testing.F, method, pw string) {
	c := fuzzClient(f, method, pw)
	pc := c.newPacketConn(nil)
	for _, v := range loadVectors(f) {
		if v.Category == "wire2022udp" && v.Method == method {
			if _, ok := v.Expected["requestPacket"]; ok {
				f.Add(vHex(f, v.Expected, "requestPacket"))
			}
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		// Fresh session state per input: replay-window and
		// session adoption must not leak across cases.
		fresh := c.newPacketConn(nil)
		fresh.clientSID = pc.clientSID
		_, _, _ = fresh.decodeLocked(packet)
	})
}

func FuzzDecodePacket2022AES(f *testing.F) {
	fuzzDecodePacket2022(f, "2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==")
}

func FuzzDecodePacket2022ChaCha(f *testing.F) {
	fuzzDecodePacket2022(f, "2022-blake3-chacha20-poly1305", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
}

func FuzzReadStream2017(f *testing.F) {
	c := fuzzClient(f, "aes-256-gcm", "relavia-test-2017")
	for _, v := range loadVectors(f) {
		if v.Category == "wire2017tcp" {
			if _, ok := v.Expected["responseStream"]; ok {
				f.Add(vHex(f, v.Expected, "responseStream"))
			}
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, stream []byte) {
		r, err := c.readResponsePrologue(bytes.NewReader(stream), nil)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
	})
}

func FuzzReadStream2022(f *testing.F) {
	c := fuzzClient(f, "2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	reqSalt := bytes.Repeat([]byte{0x11}, 32)
	for _, v := range loadVectors(f) {
		if v.Category == "wire2022tcp" {
			if _, ok := v.Expected["responseStream"]; ok {
				f.Add(vHex(f, v.Expected, "responseStream"))
			}
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, stream []byte) {
		r, err := c.readResponsePrologue(bytes.NewReader(stream), reqSalt)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
	})
}

func FuzzParseSocksAddr(f *testing.F) {
	f.Add([]byte{0x01, 127, 0, 0, 1, 0x00, 0x50})
	f.Add([]byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb})
	f.Add([]byte{0x04})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseSocksAddr(b)
	})
}
