// Copyright 2026 The Relavia Authors
// SPDX-License-Identifier: GPL-3.0-only

package selfdev

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

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
