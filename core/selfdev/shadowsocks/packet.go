package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"openproxy/core/kernel"
)

// PacketConn is a UDP session to one Shadowsocks server.
// WriteTo encrypts one datagram for the given target; ReadFrom
// decrypts the next response datagram and reports the address
// it answers for. Safe for concurrent use (one reader, many
// writers, like a net.UDPConn).
type PacketConn struct {
	client *Client
	raw    *net.UDPConn

	mu         sync.Mutex
	clientSID  uint64       // 2022: our session ID
	packetID   uint64       // 2022: next packet ID (starts at 0)
	writeAEAD  cipher.AEAD  // 2022 AES: AEAD keyed by our session subkey
	blockEnc   cipher.Block // 2022 AES: PSK block cipher (separate header)
	curServer  *serverSession
	prevServer *serverSession
	prevSeen   time.Time
}

type serverSession struct {
	id     uint64
	aead   cipher.AEAD // 2022 AES only (ChaCha keys by PSK directly)
	window slidingWindow
}

func (c *Client) newPacketConn(raw *net.UDPConn) *PacketConn {
	p := &PacketConn{client: c, raw: raw}
	if c.method.Is2022 {
		var sid [8]byte
		_, _ = io.ReadFull(c.rand, sid[:])
		p.clientSID = binary.BigEndian.Uint64(sid[:])
		if !c.method.ChaCha {
			block, err := aes.NewCipher(c.key)
			if err == nil {
				p.blockEnc = block
			}
			sub := sessionKey2022(c.key, sid[:], c.method.KeyLen)
			if a, err := c.method.newAEAD(sub); err == nil {
				p.writeAEAD = a
			}
		}
	}
	return p
}

// LocalAddr returns the local socket address.
func (p *PacketConn) LocalAddr() net.Addr { return p.raw.LocalAddr() }

// Close closes the underlying socket.
func (p *PacketConn) Close() error { return p.raw.Close() }

// SetReadDeadline mirrors net.UDPConn.
func (p *PacketConn) SetReadDeadline(t time.Time) error { return p.raw.SetReadDeadline(t) }

// SetWriteDeadline mirrors net.UDPConn.
func (p *PacketConn) SetWriteDeadline(t time.Time) error { return p.raw.SetWriteDeadline(t) }

// SetDeadline mirrors net.UDPConn.
func (p *PacketConn) SetDeadline(t time.Time) error { return p.raw.SetDeadline(t) }

// WriteTo encrypts payload for target and sends it to the
// server. Returns len(payload) on success.
func (p *PacketConn) WriteTo(payload []byte, target Addr) (int, error) {
	p.mu.Lock()
	pkt, err := p.encodeLocked(target, payload)
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if _, err := p.raw.Write(pkt); err != nil {
		return 0, kernel.NewError(kernel.KindNetwork, "shadowsocks.UDP.WriteTo", "send packet", err)
	}
	return len(payload), nil
}

func (p *PacketConn) encodeLocked(target Addr, payload []byte) ([]byte, error) {
	c := p.client
	m := c.method
	if !m.Is2022 {
		salt := make([]byte, m.KeyLen)
		if _, err := io.ReadFull(c.rand, salt); err != nil {
			return nil, err
		}
		return encodePacket2017(m, c.key, salt, target, payload), nil
	}
	if m.ChaCha {
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		if _, err := io.ReadFull(c.rand, nonce); err != nil {
			return nil, err
		}
		pid := p.packetID
		p.packetID++
		return encodePacket2022ChaCha(c.key, nonce, p.clientSID, pid, uint64(c.now().Unix()), target, payload), nil
	}
	pid := p.packetID
	p.packetID++
	return encodePacket2022AES(m, p.blockEnc, p.writeAEAD, p.clientSID, pid, uint64(c.now().Unix()), target, payload), nil
}

// ReadFrom reads and decrypts the next response datagram.
// Invalid packets (AEAD failure, replay, stale timestamp, wrong
// echoed session) are returned as errors rather than silently
// dropped, matching the control implementation's behaviour so
// the differential error layer compares like with like.
func (p *PacketConn) ReadFrom(b []byte) (int, Addr, error) {
	buf := make([]byte, 64*1024)
	n, err := p.raw.Read(buf)
	if err != nil {
		return 0, Addr{}, kernel.NewError(kernel.KindNetwork, "shadowsocks.UDP.ReadFrom", "receive packet", err)
	}
	p.mu.Lock()
	addr, plain, err := p.decodeLocked(buf[:n])
	p.mu.Unlock()
	if err != nil {
		return 0, Addr{}, handshakeErr("shadowsocks.UDP.ReadFrom", err)
	}
	return copy(b, plain), addr, nil
}

func (p *PacketConn) decodeLocked(packet []byte) (Addr, []byte, error) {
	c := p.client
	m := c.method
	if !m.Is2022 {
		return decodePacket2017(m, c.key, packet)
	}
	if m.ChaCha {
		return p.decode2022ChaCha(packet)
	}
	return p.decode2022AES(packet)
}

// --- 2017 packets (SIP004 UDP section) ----------------------------

// encodePacket2017: salt || AEAD(nonce = 0, addr || payload).
func encodePacket2017(m Method, masterKey, salt []byte, target Addr, payload []byte) []byte {
	sub := subkey2017(masterKey, salt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		panic(err)
	}
	plain := target.appendSocks(nil)
	plain = append(plain, payload...)
	return a.Seal(append([]byte{}, salt...), make([]byte, m.NonceLen), plain, nil)
}

func decodePacket2017(m Method, masterKey, packet []byte) (Addr, []byte, error) {
	if len(packet) < m.KeyLen+tagSize {
		return Addr{}, nil, fmt.Errorf("%w: packet too short", ErrProtocol)
	}
	salt := packet[:m.KeyLen]
	sub := subkey2017(masterKey, salt, m.KeyLen)
	a, err := m.newAEAD(sub)
	if err != nil {
		return Addr{}, nil, err
	}
	plain, err := a.Open(nil, make([]byte, m.NonceLen), packet[m.KeyLen:], nil)
	if err != nil {
		return Addr{}, nil, fmt.Errorf("%w: UDP packet", ErrAEADFailure)
	}
	addr, n, err := parseSocksAddr(plain)
	if err != nil {
		return Addr{}, nil, err
	}
	return addr, plain[n:], nil
}

// --- 2022 AES packets (SIP022 3.2) ---------------------------------

// encodePacket2022AES builds one client-to-server packet:
// AES(PSK, sessionID || packetID) || AEAD(session subkey,
// nonce = separateHeader[4:16], body), where the body is
// type(0) || timestamp || paddingLen || padding || addr ||
// payload. Client packets carry no padding in this engine
// (padding is optional for clients; servers must parse it).
func encodePacket2022AES(m Method, block cipher.Block, aead cipher.AEAD, sessionID, packetID uint64, timestamp uint64, target Addr, payload []byte) []byte {
	sep := make([]byte, 16)
	binary.BigEndian.PutUint64(sep[0:8], sessionID)
	binary.BigEndian.PutUint64(sep[8:16], packetID)
	body := []byte{0x00}
	body = append(body, u64be(timestamp)...)
	body = append(body, 0x00, 0x00) // padding length 0
	body = target.appendSocks(body)
	body = append(body, payload...)
	out := make([]byte, 16)
	block.Encrypt(out, sep)
	return aead.Seal(out, sep[4:16], body, nil)
}

func (p *PacketConn) decode2022AES(packet []byte) (Addr, []byte, error) {
	c := p.client
	m := c.method
	// Minimum: 16 separate header + 26 body header (type,
	// timestamp, client session ID, padding length, shortest
	// address) + 16 tag.
	if len(packet) < 16+26+tagSize {
		return Addr{}, nil, fmt.Errorf("%w: packet too short", ErrProtocol)
	}
	sep := make([]byte, 16)
	p.blockEnc.Decrypt(sep, packet[:16])
	serverSID := binary.BigEndian.Uint64(sep[0:8])
	packetID := binary.BigEndian.Uint64(sep[8:16])

	sess := p.serverSessionLocked(serverSID)
	if sess == nil {
		sub := sessionKey2022(c.key, sep[0:8], m.KeyLen)
		a, err := m.newAEAD(sub)
		if err != nil {
			return Addr{}, nil, err
		}
		sess = &serverSession{id: serverSID, aead: a}
	}
	if !sess.window.check(packetID) {
		return Addr{}, nil, fmt.Errorf("%w: replayed or out-of-window packet ID", ErrProtocol)
	}
	body, err := sess.aead.Open(nil, sep[4:16], packet[16:], nil)
	if err != nil {
		return Addr{}, nil, fmt.Errorf("%w: UDP packet body", ErrAEADFailure)
	}
	addr, payload, err := parseServerBody(body, p.clientSID)
	if err != nil {
		return Addr{}, nil, err
	}
	if d := c.now().Unix() - int64(binary.BigEndian.Uint64(body[1:9])); d > 30 || d < -30 {
		return Addr{}, nil, fmt.Errorf("%w: packet timestamp outside the 30 s window", ErrProtocol)
	}
	// Header fully validated: only now may the window advance
	// (SIP022 3.2.4).
	sess.window.add(packetID)
	p.adoptServerSessionLocked(sess)
	return addr, payload, nil
}

// --- 2022 ChaCha packets (SIP022 4.1) -------------------------------

// encodePacket2022ChaCha: nonce || XChaCha20-Poly1305(PSK,
// nonce, body) with body = clientSessionID || packetID ||
// type(0) || timestamp || paddingLen || padding || addr ||
// payload.
func encodePacket2022ChaCha(psk, nonce []byte, sessionID, packetID uint64, timestamp uint64, target Addr, payload []byte) []byte {
	a, err := chacha20poly1305.NewX(psk)
	if err != nil {
		panic(err)
	}
	body := u64be(sessionID)
	body = append(body, u64be(packetID)...)
	body = append(body, 0x00)
	body = append(body, u64be(timestamp)...)
	body = append(body, 0x00, 0x00)
	body = target.appendSocks(body)
	body = append(body, payload...)
	return a.Seal(append([]byte{}, nonce...), nonce, body, nil)
}

func (p *PacketConn) decode2022ChaCha(packet []byte) (Addr, []byte, error) {
	c := p.client
	if len(packet) < chacha20poly1305.NonceSizeX+30+tagSize {
		return Addr{}, nil, fmt.Errorf("%w: packet too short", ErrProtocol)
	}
	nonce := packet[:chacha20poly1305.NonceSizeX]
	a, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return Addr{}, nil, err
	}
	body, err := a.Open(nil, nonce, packet[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return Addr{}, nil, fmt.Errorf("%w: UDP packet body", ErrAEADFailure)
	}
	if len(body) < 16+1+8+8+2 {
		return Addr{}, nil, fmt.Errorf("%w: packet body too short", ErrProtocol)
	}
	serverSID := binary.BigEndian.Uint64(body[0:8])
	packetID := binary.BigEndian.Uint64(body[8:16])
	sess := p.serverSessionLocked(serverSID)
	if sess == nil {
		sess = &serverSession{id: serverSID}
	}
	if !sess.window.check(packetID) {
		return Addr{}, nil, fmt.Errorf("%w: replayed or out-of-window packet ID", ErrProtocol)
	}
	// Body layout after the IDs: type || timestamp || client
	// session ID || padding || addr || payload.
	addr, payload, err := parseServerBody(body[16:], p.clientSID)
	if err != nil {
		return Addr{}, nil, err
	}
	if d := c.now().Unix() - int64(binary.BigEndian.Uint64(body[17:25])); d > 30 || d < -30 {
		return Addr{}, nil, fmt.Errorf("%w: packet timestamp outside the 30 s window", ErrProtocol)
	}
	sess.window.add(packetID)
	p.adoptServerSessionLocked(sess)
	return addr, payload, nil
}

// parseServerBody parses a server-to-client main header:
// type(1) || timestamp(8) || clientSessionID(8) ||
// paddingLen(2) || padding || addr || payload, verifying the
// type byte and the echoed client session ID.
func parseServerBody(body []byte, clientSID uint64) (Addr, []byte, error) {
	if len(body) < 1+8+8+2 {
		return Addr{}, nil, fmt.Errorf("%w: packet body too short", ErrProtocol)
	}
	if body[0] != 0x01 {
		return Addr{}, nil, fmt.Errorf("%w: packet type %d, want 1 (server)", ErrProtocol, body[0])
	}
	if binary.BigEndian.Uint64(body[9:17]) != clientSID {
		return Addr{}, nil, fmt.Errorf("%w: packet echoes a different client session ID", ErrProtocol)
	}
	padLen := int(binary.BigEndian.Uint16(body[17:19]))
	rest := body[19:]
	if len(rest) < padLen {
		return Addr{}, nil, fmt.Errorf("%w: padding overruns packet", ErrProtocol)
	}
	rest = rest[padLen:]
	addr, n, err := parseSocksAddr(rest)
	if err != nil {
		return Addr{}, nil, err
	}
	return addr, rest[n:], nil
}

// serverSessionLocked returns the tracked session for a server
// session ID (current or previous), or nil for a new one.
func (p *PacketConn) serverSessionLocked(id uint64) *serverSession {
	if p.curServer != nil && p.curServer.id == id {
		return p.curServer
	}
	if p.prevServer != nil && p.prevServer.id == id {
		return p.prevServer
	}
	return nil
}

// adoptServerSessionLocked installs sess as the current server
// session, demoting the old current one - unless the previous
// session was seen within the last minute, in which case a
// second change is refused (SIP022 3.2.4: clients track at most
// one old and one current server session). Refusal is silent
// here (the packet was already validated and delivered); the
// new session simply is not adopted.
func (p *PacketConn) adoptServerSessionLocked(sess *serverSession) {
	if p.curServer == sess {
		return
	}
	if p.curServer != nil {
		if time.Since(p.prevSeen) < time.Minute && p.prevServer != nil {
			return
		}
		p.prevServer = p.curServer
	}
	p.prevSeen = time.Now()
	p.curServer = sess
}

func u64be(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}
