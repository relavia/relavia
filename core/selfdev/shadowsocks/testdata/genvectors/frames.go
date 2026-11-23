package main

// Wire framing transcribed from SIP004 (TCP/UDP sections) and
// SIP022 sections 3.1 / 3.2 / 4.1. Deliberately naive: every
// stream is built in memory in one pass, in the exact order the
// specifications lay out the bytes, so a reader can diff this
// file against the SIP texts line by line.

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// socksAddr encodes a target in SOCKS5 address format
// (ATYP || address || port u16be), the address header form both
// editions use.
func socksAddr(host string, port int) []byte {
	out := []byte{}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 0x01)
			out = append(out, v4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			panic("domain too long")
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(out, p[:]...)
}

// --- Shadowsocks 2017 (SIP004) -----------------------------------

const chunkCap2017 = 0x3FFF

// encryptStream2017 encrypts a plaintext stream (whose first
// bytes are the address header) into the chunked AEAD stream
// that follows the salt: for each chunk, AEAD(u16be length) then
// AEAD(payload), nonce counting up once per AEAD operation.
func encryptStream2017(m methodInfo, subkey, plaintext []byte) []byte {
	a := newAEAD(m, subkey)
	nonce := newNonceCounter(m.nonceLen)
	out := []byte{}
	rest := plaintext
	for len(rest) > 0 {
		n := len(rest)
		if n > chunkCap2017 {
			n = chunkCap2017
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(n))
		out = a.Seal(out, nonce.next(), lb[:], nil)
		out = a.Seal(out, nonce.next(), rest[:n], nil)
		rest = rest[n:]
	}
	return out
}

// wire2017TCP builds a full one-direction 2017 TCP stream:
// salt || encrypted chunks of (address header || payload).
func wire2017TCP(m methodInfo, password string, salt []byte, host string, port int, payload []byte) []byte {
	master := evpBytesToKey([]byte(password), m.keyLen)
	subkey := hkdfSHA1Subkey(master, salt, m.keyLen)
	plain := append(socksAddr(host, port), payload...)
	return append(append([]byte{}, salt...), encryptStream2017(m, subkey, plain)...)
}

// wire2017TCPResponse builds a 2017 TCP RESPONSE stream:
// salt || encrypted chunks of the payload ONLY. Unlike the
// request direction, the response carries no address header
// (SIP004 defines one stream format; the address header is the
// client's first payload, and per-packet address headers exist
// only in UDP). Confirmed live against shadowsocks-rust
// v1.25.0 and sing-box by the differential rig, 2026-11-23 -
// see spec section 6 item 8.
func wire2017TCPResponse(m methodInfo, password string, salt []byte, payload []byte) []byte {
	master := evpBytesToKey([]byte(password), m.keyLen)
	subkey := hkdfSHA1Subkey(master, salt, m.keyLen)
	return append(append([]byte{}, salt...), encryptStream2017(m, subkey, payload)...)
}

// wire2017UDP builds a full 2017 UDP packet:
// salt || AEAD(nonce = 0, address header || payload).
func wire2017UDP(m methodInfo, password string, salt []byte, host string, port int, payload []byte) []byte {
	master := evpBytesToKey([]byte(password), m.keyLen)
	subkey := hkdfSHA1Subkey(master, salt, m.keyLen)
	a := newAEAD(m, subkey)
	plain := append(socksAddr(host, port), payload...)
	return a.Seal(append([]byte{}, salt...), make([]byte, m.nonceLen), plain, nil)
}

// --- Shadowsocks 2022 (SIP022) -----------------------------------

// encryptChunks2022 encrypts payload chunks for a 2022 stream
// whose nonce counter is already running (headers consumed the
// first counts). Chunks are length+payload pairs capped at
// chunkCap (the sender's choice; receivers must accept 0xFFFF).
func encryptChunks2022(a interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, nonce *nonceCounter, payload []byte, chunkCap int) []byte {
	out := []byte{}
	rest := payload
	for len(rest) > 0 {
		n := len(rest)
		if n > chunkCap {
			n = chunkCap
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(n))
		out = a.Seal(out, nonce.next(), lb[:], nil)
		out = a.Seal(out, nonce.next(), rest[:n], nil)
		rest = rest[n:]
	}
	return out
}

// wire2022TCPRequest builds a full 2022 TCP request stream:
// salt || AEAD(fixed header) || AEAD(variable header) ||
// data chunks. The variable header carries padding and the
// initial payload (SIP022 3.1.3); remaining payload, if any,
// goes in data chunks capped at 0x3FFF (sender's choice).
func wire2022TCPRequest(m methodInfo, psk, salt []byte, timestamp uint64, host string, port int, padding, initialPayload, restPayload []byte) []byte {
	subkey := blake3SessionKey(psk, salt, m.keyLen)
	a := newAEAD(m, subkey)
	nonce := newNonceCounter(m.nonceLen)

	varHeader := append(socksAddr(host, port), u16be(len(padding))...)
	varHeader = append(varHeader, padding...)
	varHeader = append(varHeader, initialPayload...)

	fixed := []byte{0x00}
	fixed = append(fixed, u64be(timestamp)...)
	fixed = append(fixed, u16be(len(varHeader))...)

	out := append([]byte{}, salt...)
	out = a.Seal(out, nonce.next(), fixed, nil)
	out = a.Seal(out, nonce.next(), varHeader, nil)
	out = append(out, encryptChunks2022(a, nonce, restPayload, chunkCap2017)...)
	return out
}

// wire2022TCPResponse builds a full 2022 TCP response stream:
// response salt || AEAD(fixed header acting as first length
// chunk) || AEAD(first payload chunk) || data chunks.
func wire2022TCPResponse(m methodInfo, psk, respSalt, reqSalt []byte, timestamp uint64, firstPayload, restPayload []byte) []byte {
	if len(firstPayload) > 0xFFFF {
		panic("first payload chunk too large")
	}
	subkey := blake3SessionKey(psk, respSalt, m.keyLen)
	a := newAEAD(m, subkey)
	nonce := newNonceCounter(m.nonceLen)

	fixed := []byte{0x01}
	fixed = append(fixed, u64be(timestamp)...)
	fixed = append(fixed, reqSalt...)
	fixed = append(fixed, u16be(len(firstPayload))...)

	out := append([]byte{}, respSalt...)
	out = a.Seal(out, nonce.next(), fixed, nil)
	out = a.Seal(out, nonce.next(), firstPayload, nil)
	out = append(out, encryptChunks2022(a, nonce, restPayload, chunkCap2017)...)
	return out
}

// wire2022UDPAES builds a 2022 UDP packet for the AES methods
// (SIP022 3.2): AES-block-encrypted separate header || AEAD body.
// For client-to-server, sessionID is the client session ID and
// the body header has no echoed session ID; for server-to-client
// the caller passes the server session ID and the client session
// ID to echo in the body.
func wire2022UDPAES(m methodInfo, psk []byte, sessionID, packetID uint64, timestamp uint64, serverToClient bool, clientSessionID uint64, padding, host string, port int, payload []byte) []byte {
	sep := append(u64be(sessionID), u64be(packetID)...)
	subkey := blake3SessionKey(psk, u64be(sessionID), m.keyLen)
	a := newAEAD(m, subkey)

	body := []byte{}
	if serverToClient {
		body = append(body, 0x01)
	} else {
		body = append(body, 0x00)
	}
	body = append(body, u64be(timestamp)...)
	if serverToClient {
		body = append(body, u64be(clientSessionID)...)
	}
	body = append(body, u16be(len(padding))...)
	body = append(body, padding...)
	body = append(body, socksAddr(host, port)...)
	body = append(body, payload...)

	nonce := sep[4:16]
	out := aesBlockEncrypt(psk, sep)
	return a.Seal(out, nonce, body, nil)
}

// wire2022UDPChaCha builds a 2022 UDP packet for
// 2022-blake3-chacha20-poly1305 (SIP022 4.1): random nonce ||
// XChaCha20-Poly1305(PSK) body whose head carries the session
// and packet IDs.
func wire2022UDPChaCha(m methodInfo, psk, nonce24 []byte, sessionID, packetID uint64, timestamp uint64, serverToClient bool, clientSessionID uint64, padding, host string, port int, payload []byte) []byte {
	// SIP022 4.1: UDP for the ChaCha method uses XChaCha20-Poly1305
	// keyed directly by the PSK (TCP uses the IETF variant over
	// the session subkey instead - see newAEAD).
	a, err := chacha20poly1305.NewX(psk)
	if err != nil {
		panic(err)
	}
	body := append(u64be(sessionID), u64be(packetID)...)
	if serverToClient {
		body = append(body, 0x01)
	} else {
		body = append(body, 0x00)
	}
	body = append(body, u64be(timestamp)...)
	if serverToClient {
		body = append(body, u64be(clientSessionID)...)
	}
	body = append(body, u16be(len(padding))...)
	body = append(body, padding...)
	body = append(body, socksAddr(host, port)...)
	body = append(body, payload...)
	return a.Seal(append([]byte{}, nonce24...), nonce24, body, nil)
}

func u16be(n int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return b[:]
}

func u64be(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}

// pattern is the deterministic payload filler used by all
// vectors: reproducible across runs and implementations.
func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i) ^ byte(i>>8) ^ seed
	}
	return out
}

// saltPattern makes a deterministic salt of the given length.
func saltPattern(base byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = base + byte(i)
	}
	return out
}

var _ = fmt.Sprintf
