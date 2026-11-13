package openvpn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeMgmt is a scripted management-interface server on a loopback
// TCP port. script runs the server side of the conversation.
func fakeMgmt(t *testing.T, script func(r *bufio.Reader, w *bufio.Writer)) (addr string, events chan mgmtEvent, client *mgmtClient, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		fmt.Fprintf(w, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
		w.Flush()
		script(r, w)
	}()
	events = make(chan mgmtEvent, 64)
	client, err = dialMgmt(context.Background(), "tcp", ln.Addr().String(), "", authCreds{username: "alice", password: "s3\"cret", has: true}, events)
	if err != nil {
		t.Fatalf("dialMgmt: %v", err)
	}
	cleanup = func() { client.close(); ln.Close() }
	return ln.Addr().String(), events, client, cleanup
}

func readCmd(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Errorf("server read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func expectEvent(t *testing.T, events chan mgmtEvent, kind mgmtEventKind) mgmtEvent {
	t.Helper()
	select {
	case ev := <-events:
		if ev.Kind != kind {
			t.Fatalf("event kind = %v, want %v (event %+v)", ev.Kind, kind, ev)
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for event kind %v", kind)
		return mgmtEvent{}
	}
}

func TestMgmtStateAndBytes(t *testing.T) {
	_, events, client, cleanup := fakeMgmt(t, func(r *bufio.Reader, w *bufio.Writer) {
		// state on -> SUCCESS
		readCmd(t, r)
		fmt.Fprintf(w, "SUCCESS: real-time state notification set to ON\r\n")
		w.Flush()
		// Push a CONNECTED state and a bytecount.
		fmt.Fprintf(w, ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,127.0.0.1,1194,127.0.0.1,5000\r\n")
		fmt.Fprintf(w, ">BYTECOUNT:12345,6789\r\n")
		w.Flush()
		// state query
		readCmd(t, r)
		fmt.Fprintf(w, "1700000000,CONNECTED,SUCCESS,10.8.0.2,127.0.0.1,1194,127.0.0.1,5000\r\nEND\r\n")
		w.Flush()
		time.Sleep(200 * time.Millisecond)
	})
	defer cleanup()

	if _, err := client.command("state on", 3*time.Second); err != nil {
		t.Fatalf("state on: %v", err)
	}
	ev := expectEvent(t, events, mgmtEventState)
	if ev.State.Name != "CONNECTED" || ev.State.LocalIP != "10.8.0.2" || ev.State.RemotePort != 1194 {
		t.Errorf("state event = %+v", ev.State)
	}
	ev = expectEvent(t, events, mgmtEventBytes)
	if ev.BytesIn != 12345 || ev.BytesOut != 6789 {
		t.Errorf("bytes event = %+v", ev)
	}
	st, err := client.state()
	if err != nil {
		t.Fatalf("state(): %v", err)
	}
	if st.Name != "CONNECTED" {
		t.Errorf("state() = %+v", st)
	}
}

func TestMgmtPasswordAnswer(t *testing.T) {
	got := make(chan []string, 1)
	_, _, client, cleanup := fakeMgmt(t, func(r *bufio.Reader, w *bufio.Writer) {
		fmt.Fprintf(w, ">PASSWORD:Need 'Auth' username/password\r\n")
		w.Flush()
		u := readCmd(t, r)
		p := readCmd(t, r)
		got <- []string{u, p}
		time.Sleep(100 * time.Millisecond)
	})
	defer cleanup()
	_ = client
	select {
	case lines := <-got:
		if lines[0] != `username "Auth" "alice"` {
			t.Errorf("username line = %q", lines[0])
		}
		if lines[1] != `password "Auth" "s3\"cret"` {
			t.Errorf("password line = %q (escaping wrong)", lines[1])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("password was not answered")
	}
}

func TestMgmtHoldAndFatal(t *testing.T) {
	_, events, client, cleanup := fakeMgmt(t, func(r *bufio.Reader, w *bufio.Writer) {
		fmt.Fprintf(w, ">HOLD:Waiting for hold release:0\r\n")
		w.Flush()
		if cmd := readCmd(t, r); cmd != "hold release" {
			t.Errorf("hold reply = %q", cmd)
		}
		fmt.Fprintf(w, ">FATAL:Cannot allocate TUN/TAP dev dynamically\r\n")
		w.Flush()
		time.Sleep(100 * time.Millisecond)
	})
	defer cleanup()
	_ = client
	ev := expectEvent(t, events, mgmtEventFatal)
	if !strings.Contains(ev.Message, "TUN/TAP") {
		t.Errorf("fatal message = %q", ev.Message)
	}
}

func TestParseStateLine(t *testing.T) {
	st, ok := parseStateLine("1700000000,RECONNECTING,auth-failure,,,,,")
	if !ok || st.Name != "RECONNECTING" || st.Detail != "auth-failure" {
		t.Errorf("parse = %+v ok=%v", st, ok)
	}
	if _, ok := parseStateLine("junk"); ok {
		t.Error("expected parse failure on junk")
	}
}
