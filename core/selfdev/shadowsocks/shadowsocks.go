// Package shadowsocks is the project's self-developed
// Shadowsocks client engine (spec:
// docs/自研协议路线-01-shadowsocks.md). It implements the client
// outbound for the seven AEAD methods of spec section 2.2 -
// Shadowsocks AEAD (2017, SIP004) and Shadowsocks 2022 (SIP022),
// TCP and UDP - behind plain Go interfaces, so the composite
// adapter in core/selfdev can route Shadowsocks nodes to it
// while sing-box remains the fallback backend and differential
// control group.
//
// Cryptography is assembled exclusively from vetted primitives
// (Go standard library AES-GCM, golang.org/x/crypto
// ChaCha20-Poly1305, zeebo/blake3 in derive-key mode). Per the
// spec's red line (section 0), no cryptographic primitive is
// implemented in this package; only protocol framing, header
// handling and session management are.
//
// Credentials are passwords (spec 9.1): they are never logged,
// and test values in this package's tests are TEST-ONLY.
package shadowsocks

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"openproxy/core/kernel"
)

// Method describes one supported Shadowsocks method.
type Method struct {
	Name string
	// KeyLen is the master-key length (2017) or PSK length
	// (2022). The salt length always equals it.
	KeyLen   int
	NonceLen int
	Is2022   bool
	// ChaCha selects IETF ChaCha20-Poly1305; XChaCha selects
	// XChaCha20-Poly1305 (2017 only). Neither means AES-GCM.
	ChaCha  bool
	XChaCha bool
}

var methods = map[string]Method{
	"aes-128-gcm":                   {Name: "aes-128-gcm", KeyLen: 16, NonceLen: 12},
	"aes-256-gcm":                   {Name: "aes-256-gcm", KeyLen: 32, NonceLen: 12},
	"chacha20-ietf-poly1305":        {Name: "chacha20-ietf-poly1305", KeyLen: 32, NonceLen: 12, ChaCha: true},
	"xchacha20-ietf-poly1305":       {Name: "xchacha20-ietf-poly1305", KeyLen: 32, NonceLen: 24, XChaCha: true},
	"2022-blake3-aes-128-gcm":       {Name: "2022-blake3-aes-128-gcm", KeyLen: 16, NonceLen: 12, Is2022: true},
	"2022-blake3-aes-256-gcm":       {Name: "2022-blake3-aes-256-gcm", KeyLen: 32, NonceLen: 12, Is2022: true},
	"2022-blake3-chacha20-poly1305": {Name: "2022-blake3-chacha20-poly1305", KeyLen: 32, NonceLen: 12, Is2022: true, ChaCha: true},
}

// LookupMethod returns the method descriptor for a unified-model
// method name. ok=false means the method is outside this
// engine's support set (spec 2.2): legacy stream ciphers are
// refused exactly like the pinned sing-box refuses them.
func LookupMethod(name string) (Method, bool) {
	m, ok := methods[name]
	return m, ok
}

// SupportedMethods lists the seven in-scope method names.
func SupportedMethods() []string {
	out := make([]string, 0, len(methods))
	for name := range methods {
		out = append(out, name)
	}
	return out
}

// IsMultiPSK reports whether a 2022 password field carries a
// colon-joined PSK chain (relay/EIH form). Such nodes are out
// of the v1 scope (spec 1.3) and must route to the fallback
// backend, never be truncated or guessed at.
func IsMultiPSK(method, password string) bool {
	m, ok := LookupMethod(method)
	return ok && m.Is2022 && strings.Contains(password, ":")
}

// Client is a Shadowsocks client engine bound to one method and
// credential. It is safe for concurrent use; each Dial creates
// independent session state.
type Client struct {
	method Method
	// key holds the 2017 master key or the 2022 PSK.
	key []byte

	dialer *net.Dialer
	now    func() time.Time
	rand   io.Reader
}

// Option configures a Client.
type Option func(*Client)

// WithDialer sets the dialer used for server connections
// (socket protection on Android is the caller's concern, via
// the dialer's Control hook).
func WithDialer(d *net.Dialer) Option { return func(c *Client) { c.dialer = d } }

// WithClock overrides the wall clock (tests; SIP022 timestamps).
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// WithRand overrides the randomness source for salts, padding
// and session IDs (tests only - production must keep
// crypto/rand).
func WithRand(r io.Reader) Option { return func(c *Client) { c.rand = r } }

// NewClient validates the credential and builds a Client.
//
// Error classification (spec 3.4): an unknown or legacy method
// is KindUnsupported; an empty 2017 password, an undecodable
// 2022 PSK, or a PSK of the wrong length is KindInvalidConfig -
// all before any network activity. A colon-joined multi-PSK is
// KindUnsupported (the node is well-formed but out of scope).
func NewClient(method, password string, opts ...Option) (*Client, error) {
	m, ok := LookupMethod(method)
	if !ok {
		return nil, kernel.NewError(kernel.KindUnsupported, "shadowsocks.NewClient",
			fmt.Sprintf("method %q is not in the self-developed engine's support set", method), nil)
	}
	c := &Client{method: m, dialer: &net.Dialer{}, now: time.Now, rand: rand.Reader}
	for _, o := range opts {
		o(c)
	}
	if m.Is2022 {
		if strings.Contains(password, ":") {
			return nil, kernel.NewError(kernel.KindUnsupported, "shadowsocks.NewClient",
				"multi-PSK (colon-joined) Shadowsocks 2022 nodes are out of scope for the self-developed engine", nil)
		}
		psk, err := DecodePSK(password)
		if err != nil {
			return nil, kernel.NewError(kernel.KindInvalidConfig, "shadowsocks.NewClient",
				"Shadowsocks 2022 password is not valid base64", err)
		}
		if len(psk) != m.KeyLen {
			return nil, kernel.NewError(kernel.KindInvalidConfig, "shadowsocks.NewClient",
				fmt.Sprintf("Shadowsocks 2022 PSK length %d does not match method %s (want %d)", len(psk), m.Name, m.KeyLen), nil)
		}
		c.key = psk
	} else {
		if password == "" {
			return nil, kernel.NewError(kernel.KindInvalidConfig, "shadowsocks.NewClient",
				"shadowsocks password is empty", nil)
		}
		c.key = EVPBytesToKey([]byte(password), m.KeyLen)
	}
	return c, nil
}

// DecodePSK decodes a Shadowsocks 2022 base64 PSK. Both padded
// and unpadded standard base64 are accepted: shadowsocks-rust
// accepts both, and the spec's adjudication rule (section 4.5,
// recorded in section 6 item 7) follows rust where mainstream
// implementations differ. (sing-box accepts padded only; this
// is a deliberate, documented divergence of config acceptance,
// not of wire behaviour.)
func DecodePSK(s string) ([]byte, error) {
	if b, err := base64StdDecode(s); err == nil {
		return b, nil
	}
	return base64RawDecode(s)
}

// Method returns the client's method descriptor.
func (c *Client) Method() Method { return c.method }

// ErrAEADFailure marks an AEAD open failure (tampered stream,
// wrong key, wrong password - indistinguishable by design,
// spec 3.4).
var ErrAEADFailure = errors.New("shadowsocks: AEAD open failed")

// ErrProtocol marks a structurally invalid peer message (bad
// header type, bad echoed salt, stale timestamp, ...).
var ErrProtocol = errors.New("shadowsocks: protocol violation")

// handshakeErr wraps a protocol/data-path failure as
// KindHandshakeFailed.
func handshakeErr(op string, err error) error {
	return kernel.NewError(kernel.KindHandshakeFailed, op, err.Error(), err)
}

// kernelErrInternal wraps an internal failure as KindInternal
// (a bug by definition, spec 3.4 - never silently rerouted).
func kernelErrInternal(op, msg string, err error) error {
	return kernel.NewError(kernel.KindInternal, op, msg, err)
}

// DialTCP connects to the Shadowsocks server at serverAddr
// ("host:port") and returns a plaintext stream connection to
// target through it. The request header is written during the
// dial (with random padding standing in for payload on 2022,
// per SIP022 3.1.4); the response header is validated lazily on
// the first Read.
func (c *Client) DialTCP(ctx context.Context, serverAddr string, target Addr) (net.Conn, error) {
	raw, err := c.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, kernel.NewError(kernel.KindNetwork, "shadowsocks.DialTCP",
			"dial shadowsocks server", err)
	}
	conn, err := c.wrapTCP(raw, target)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// DialUDP creates a UDP session towards the Shadowsocks server
// at serverAddr. The returned PacketConn sends each packet to
// the per-call target and reports the responder's target
// address on reads.
func (c *Client) DialUDP(ctx context.Context, serverAddr string) (*PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "shadowsocks.DialUDP",
			"resolve shadowsocks server address", err)
	}
	raw, err := c.dialer.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		return nil, kernel.NewError(kernel.KindNetwork, "shadowsocks.DialUDP",
			"dial shadowsocks server", err)
	}
	pc, ok := raw.(*net.UDPConn)
	if !ok {
		_ = raw.Close()
		return nil, kernel.NewError(kernel.KindInternal, "shadowsocks.DialUDP",
			"unexpected packet conn type", nil)
	}
	return c.newPacketConn(pc), nil
}
