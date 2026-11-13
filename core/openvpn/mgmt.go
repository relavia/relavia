package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Management interface client.
//
// OpenVPN's management interface is a line protocol. Real-time
// notifications arrive as ">..." lines at any moment; command
// replies are plain lines terminated by "END" (multi-line) or a
// single "SUCCESS:"/"ERROR:" line. One reader goroutine demultiplexes:
// notifications go to the session supervisor, command replies to the
// one outstanding command (commands are serialised by the caller
// side mutex).
//
// The adapter depends on it for: state notifications (CONNECTED is
// the only success criterion for Start/TestHandshake — never log
// scraping), byte counters (the QueryTraffic source), username/
// password answers (credentials never touch a file or argv), hold
// release, and graceful shutdown via "signal SIGTERM".

// mgmtState is one parsed >STATE / state reply line:
//
//	<unix time>,<name>,<detail>,<local virtual IP>,<remote host>,<remote port>,...
type mgmtState struct {
	At         time.Time
	Name       string // CONNECTED, RECONNECTING, AUTH, GET_CONFIG, ASSIGN_IP, TCP_CONNECT, WAIT, RESOLVE, EXITING, ...
	Detail     string // e.g. SUCCESS, auth-failure, tls-error, connection-failed
	LocalIP    string
	RemoteIP   string
	RemotePort int
}

type mgmtEventKind int

const (
	mgmtEventState mgmtEventKind = iota
	mgmtEventBytes
	mgmtEventFatal // >FATAL: unrecoverable error reported by openvpn
	mgmtEventPasswordAuth
	mgmtEventPasswordKey // private-key password request: unsupported by this adapter
)

type mgmtEvent struct {
	Kind     mgmtEventKind
	State    mgmtState
	BytesIn  uint64
	BytesOut uint64
	Message  string
}

type mgmtClient struct {
	conn   net.Conn
	events chan mgmtEvent

	cmdMu  sync.Mutex // serialises commands
	mu     sync.Mutex // guards respCh
	respCh chan string
	done   chan struct{}
	once   sync.Once
}

// dialMgmt connects to the child's management endpoint and performs
// the greeting (password prompt when the endpoint is password
// protected, then the >INFO banner). creds are the node's
// username/password used to answer 'Auth' password requests; they
// are captured by the reader goroutine's answer logic.
func dialMgmt(ctx context.Context, network, address, password string, creds authCreds, events chan mgmtEvent) (*mgmtClient, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c := &mgmtClient{conn: conn, events: events, done: make(chan struct{})}
	br := bufio.NewReader(conn)
	// Greeting: either "ENTER PASSWORD:" (password-protected TCP
	// endpoint) or the ">INFO:" banner (unix socket endpoint).
	line, err := readLineTimeout(br, 10*time.Second, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("management greeting: %w", err)
	}
	if strings.HasPrefix(line, "ENTER PASSWORD:") {
		if _, err := io.WriteString(conn, password+"\r\n"); err != nil {
			conn.Close()
			return nil, fmt.Errorf("management password: %w", err)
		}
		line, err = readLineTimeout(br, 10*time.Second, conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("management password reply: %w", err)
		}
		if !strings.HasPrefix(line, "SUCCESS:") {
			conn.Close()
			return nil, fmt.Errorf("management password rejected: %s", line)
		}
		line, err = readLineTimeout(br, 10*time.Second, conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("management banner: %w", err)
		}
	}
	if !strings.HasPrefix(line, ">INFO:") {
		conn.Close()
		return nil, fmt.Errorf("unexpected management greeting: %q", line)
	}
	go c.readLoop(br, creds)
	return c, nil
}

func readLineTimeout(br *bufio.Reader, d time.Duration, conn net.Conn) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	defer conn.SetReadDeadline(time.Time{})
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type authCreds struct {
	username string
	password string
	has      bool
}

func (c *mgmtClient) readLoop(br *bufio.Reader, creds authCreds) {
	defer c.close()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ">") {
			c.handleNotification(line, creds)
			continue
		}
		c.mu.Lock()
		ch := c.respCh
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- line:
			case <-c.done:
				return
			}
		}
	}
}

func (c *mgmtClient) handleNotification(line string, creds authCreds) {
	emit := func(ev mgmtEvent) {
		select {
		case c.events <- ev:
		case <-c.done:
		}
	}
	switch {
	case strings.HasPrefix(line, ">STATE:"):
		if st, ok := parseStateLine(strings.TrimPrefix(line, ">STATE:")); ok {
			emit(mgmtEvent{Kind: mgmtEventState, State: st})
		}
	case strings.HasPrefix(line, ">BYTECOUNT:"):
		parts := strings.Split(strings.TrimPrefix(line, ">BYTECOUNT:"), ",")
		if len(parts) == 2 {
			in, e1 := strconv.ParseUint(parts[0], 10, 64)
			out, e2 := strconv.ParseUint(parts[1], 10, 64)
			if e1 == nil && e2 == nil {
				emit(mgmtEvent{Kind: mgmtEventBytes, BytesIn: in, BytesOut: out})
			}
		}
	case strings.HasPrefix(line, ">PASSWORD:"):
		rest := strings.TrimPrefix(line, ">PASSWORD:")
		switch {
		case strings.HasPrefix(rest, "Need 'Auth'"):
			if !creds.has {
				emit(mgmtEvent{Kind: mgmtEventPasswordAuth, Message: "server requested a username/password but the node carries none"})
				return
			}
			_ = c.writeLine(fmt.Sprintf("username \"Auth\" \"%s\"", mgmtEscape(creds.username)))
			_ = c.writeLine(fmt.Sprintf("password \"Auth\" \"%s\"", mgmtEscape(creds.password)))
		case strings.HasPrefix(rest, "Need 'Private Key'"):
			emit(mgmtEvent{Kind: mgmtEventPasswordKey, Message: "client private key is password-protected; encrypted client keys are not supported by this adapter"})
		case strings.HasPrefix(rest, "Verification Failed:") || strings.Contains(rest, "'Auth'"):
			// e.g. >PASSWORD:Verification Failed: 'Auth' — the
			// supervisor also sees the following state/log lines;
			// the auth-failure classification keys off them.
		}
	case strings.HasPrefix(line, ">HOLD:"):
		_ = c.writeLine("hold release")
	case strings.HasPrefix(line, ">FATAL:"):
		emit(mgmtEvent{Kind: mgmtEventFatal, Message: strings.TrimPrefix(line, ">FATAL:")})
	}
}

// mgmtEscape escapes a value for a quoted management command
// argument (backslash and double-quote).
func mgmtEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func parseStateLine(s string) (mgmtState, bool) {
	f := strings.Split(s, ",")
	if len(f) < 2 {
		return mgmtState{}, false
	}
	st := mgmtState{Name: f[1]}
	if ts, err := strconv.ParseInt(f[0], 10, 64); err == nil {
		st.At = time.Unix(ts, 0)
	}
	if len(f) > 2 {
		st.Detail = f[2]
	}
	if len(f) > 3 {
		st.LocalIP = f[3]
	}
	if len(f) > 4 {
		st.RemoteIP = f[4]
	}
	if len(f) > 5 {
		st.RemotePort, _ = strconv.Atoi(f[5])
	}
	return st, true
}

func (c *mgmtClient) writeLine(s string) error {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	return c.writeLineLocked(s)
}

func (c *mgmtClient) writeLineLocked(s string) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer c.conn.SetWriteDeadline(time.Time{})
	_, err := io.WriteString(c.conn, s+"\r\n")
	return err
}

// command sends one management command and collects its reply:
// lines up to END, or a single SUCCESS:/ERROR: line. It returns
// the reply lines (without the terminator).
func (c *mgmtClient) command(cmd string, timeout time.Duration) ([]string, error) {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	ch := make(chan string, 64)
	c.mu.Lock()
	c.respCh = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.respCh = nil
		c.mu.Unlock()
	}()
	if err := c.writeLineLocked(cmd); err != nil {
		return nil, err
	}
	var out []string
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case line := <-ch:
			if line == "END" {
				return out, nil
			}
			if strings.HasPrefix(line, "SUCCESS:") || strings.HasPrefix(line, "ERROR:") {
				return append(out, line), nil
			}
			out = append(out, line)
		case <-deadline.C:
			return out, errors.New("management command timed out: " + cmd)
		case <-c.done:
			return out, errors.New("management connection closed during: " + cmd)
		}
	}
}

// state queries the current state synchronously.
func (c *mgmtClient) state() (mgmtState, error) {
	lines, err := c.command("state", 5*time.Second)
	if err != nil {
		return mgmtState{}, err
	}
	for _, l := range lines {
		if st, ok := parseStateLine(l); ok {
			return st, nil
		}
	}
	return mgmtState{}, errors.New("state reply had no state line")
}

// signal asks openvpn to terminate itself gracefully.
func (c *mgmtClient) signal(sig string) error {
	_, err := c.command("signal "+sig, 3*time.Second)
	return err
}

func (c *mgmtClient) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}
