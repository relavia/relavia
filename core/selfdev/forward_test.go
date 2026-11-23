// Copyright 2026 The Relavia Authors
// SPDX-License-Identifier: GPL-3.0-only

package selfdev

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"openproxy/core/selfdev/shadowsocks"
)

// TestParseSocksAddrBytesPayloadOffset pins the fix found by
// the phase-2 UDP differential rig's first CI run: the payload
// offset of a SOCKS UDP datagram must come from the address
// length itself. The previous code derived it from a
// bufio.Reader's Buffered() count, which caps at the 4096-byte
// buffer: any datagram larger than 4096 bytes had its payload
// silently cut to the packet's last 4090 bytes (IPv4). The
// 32 KiB rig exchange failed with exactly 4090 bytes on every
// method; small datagrams were unaffected, which is why local
// and small-payload runs never saw it.
func TestParseSocksAddrBytesPayloadOffset(t *testing.T) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i) ^ byte(i>>8) ^ 0x5a
	}
	cases := []struct {
		name string
		addr shadowsocks.Addr
	}{
		{"ipv4", shadowsocks.Addr{Host: "127.0.0.1", Port: 39115}},
		{"ipv6", shadowsocks.Addr{Host: "2001:db8::1", Port: 53}},
		{"domain", shadowsocks.Addr{Host: "echo.example.test", Port: 8080}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := []byte{0, 0, 0}
			wire = tc.addr.AppendSocks(wire)
			wire = append(wire, payload...)
			got, hdrLen, err := parseSocksAddrBytes(wire[3:])
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.addr {
				t.Fatalf("addr = %v, want %v", got, tc.addr)
			}
			if rest := wire[3+hdrLen:]; !bytes.Equal(rest, payload) {
				t.Fatalf("payload slice = %d bytes, want the full %d", len(rest), len(payload))
			}
		})
	}
	// Short and unknown inputs are rejected, never misparsed.
	for _, b := range [][]byte{
		{},
		{0x01, 1, 2},
		{0x04, 1, 2, 3},
		{0x03, 9, 'a'},
		{0x09, 1, 2, 3, 4, 5, 6, 7},
	} {
		if _, _, err := parseSocksAddrBytes(b); err == nil {
			t.Fatalf("input %x: want error", b)
		}
	}
}

// TestBufferedConnHalfCloseDelegates pins the fix found by the
// phase-2 mid-stream-death differential: the relay propagates
// end-of-stream by calling CloseWrite on the inbound
// connection, which is a *bufferedConn. Embedding the net.Conn
// interface does NOT promote CloseWrite, so without the
// explicit delegating methods the FIN never reaches the peer
// and it hangs until its own deadline.
func TestBufferedConnHalfCloseDelegates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	server := <-accepted
	defer server.Close()

	bc := &bufferedConn{Conn: raw, br: bufio.NewReader(raw)}
	cw, ok := any(bc).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("bufferedConn does not expose CloseWrite; relay half-close would silently no-op")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// The peer must observe EOF promptly.
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer read after delegated CloseWrite = %v, want io.EOF", err)
	}
}
