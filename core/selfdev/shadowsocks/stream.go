package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Chunked AEAD stream machinery shared by both editions
// (SIP004 TCP section; SIP022 3.1). A chunk on the wire is
// AEAD(u16be length) || AEAD(payload); the nonce counts up once
// per AEAD operation. Editions differ in the length cap and in
// the header prologue, which the callers handle.

const (
	// chunkCap2017 is the SIP004 payload cap: the length field's
	// top two bits are reserved and must be zero.
	chunkCap2017 = 0x3FFF
	// chunkCap2022 is the SIP022 payload cap (3.1.2). Our sender
	// splits at chunkCap2017 anyway (a lawful sender choice that
	// keeps the structural layer comparable with the control
	// implementation); the receiver accepts up to this cap.
	chunkCap2022 = 0xFFFF
)

// chunkWriter encrypts a plaintext stream into AEAD chunks.
type chunkWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce *nonceCounter
	cap   int
	buf   []byte
	err   error
}

func newChunkWriter(w io.Writer, aead cipher.AEAD, nonce *nonceCounter, cap int) *chunkWriter {
	return &chunkWriter{w: w, aead: aead, nonce: nonce, cap: cap}
}

// Write buffers plaintext and emits full chunks; partial data
// is flushed when the buffer reaches the cap. Call Flush before
// expecting a response (request/response protocols).
func (w *chunkWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.cap {
		if err := w.emit(w.buf[:w.cap]); err != nil {
			w.err = err
			return 0, err
		}
		w.buf = w.buf[w.cap:]
	}
	return len(p), nil
}

// Flush emits any buffered plaintext as a final short chunk.
func (w *chunkWriter) Flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.buf) == 0 {
		return nil
	}
	if err := w.emit(w.buf); err != nil {
		w.err = err
		return err
	}
	w.buf = nil
	return nil
}

func (w *chunkWriter) emit(chunk []byte) error {
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(chunk)))
	out := make([]byte, 0, 2+tagSize+len(chunk)+tagSize)
	out = w.aead.Seal(out, w.nonce.next(), lb[:], nil)
	out = w.aead.Seal(out, w.nonce.next(), chunk, nil)
	_, err := w.w.Write(out)
	return err
}

// chunkReader decrypts an AEAD chunk stream.
type chunkReader struct {
	r      io.Reader
	aead   cipher.AEAD
	nonce  *nonceCounter
	maxLen int
	plain  []byte
	err    error
	// nextLen, when >= 0, is the plaintext length of the next
	// payload chunk announced out of band (the SIP022 response
	// fixed header doubles as the first length chunk). After
	// that chunk, lengths come from the stream again.
	nextLen int
}

func newChunkReader(r io.Reader, aead cipher.AEAD, nonce *nonceCounter, maxLen int) *chunkReader {
	return &chunkReader{r: r, aead: aead, nonce: nonce, maxLen: maxLen, nextLen: -1}
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if err := r.readChunk(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *chunkReader) readChunk() error {
	var plainLen int
	if r.nextLen >= 0 {
		plainLen = r.nextLen
		r.nextLen = -1
	} else {
		lenBuf := make([]byte, 2+tagSize)
		if _, err := io.ReadFull(r.r, lenBuf); err != nil {
			return wrapStreamEOF(err)
		}
		lb, err := r.aead.Open(nil, r.nonce.next(), lenBuf, nil)
		if err != nil {
			return fmt.Errorf("%w: length chunk", ErrAEADFailure)
		}
		plainLen = int(binary.BigEndian.Uint16(lb))
		if plainLen > r.maxLen {
			return fmt.Errorf("%w: chunk length %d exceeds cap %d", ErrProtocol, plainLen, r.maxLen)
		}
		if plainLen == 0 {
			return fmt.Errorf("%w: zero-length chunk", ErrProtocol)
		}
	}
	buf := make([]byte, plainLen+tagSize)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		return wrapStreamEOF(err)
	}
	plain, err := r.aead.Open(nil, r.nonce.next(), buf, nil)
	if err != nil {
		return fmt.Errorf("%w: payload chunk", ErrAEADFailure)
	}
	r.plain = plain
	return nil
}

// wrapStreamEOF normalizes stream termination: EOF exactly at a
// chunk boundary is a clean io.EOF; EOF anywhere inside a chunk
// is unexpected.
func wrapStreamEOF(err error) error {
	if err == io.EOF {
		return io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// --- connection assembly -----------------------------------------

// tcpConn is the plaintext net.Conn returned by DialTCP.
type tcpConn struct {
	raw     net.Conn
	w       *chunkWriter
	r       io.Reader
	reqSalt []byte
}

func (c *tcpConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write encrypts and sends p immediately (flushing the chunk
// buffer): proxy traffic is request/response-shaped, so holding
// a partial chunk back for coalescing would deadlock peers that
// answer before a full chunk accumulates.
func (c *tcpConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if err := c.w.Flush(); err != nil {
		return n, err
	}
	return n, nil
}
func (c *tcpConn) Close() error                       { return c.raw.Close() }
func (c *tcpConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *tcpConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *tcpConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *tcpConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *tcpConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// CloseWrite flushes pending chunks and half-closes the write
// side, so request/response protocols that rely on write-side
// EOF work through the tunnel.
func (c *tcpConn) CloseWrite() error {
	if err := c.w.Flush(); err != nil {
		return err
	}
	if tc, ok := c.raw.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

// wrapTCP writes the request prologue to raw and assembles the
// plaintext connection. The response prologue is parsed lazily
// on the first Read (a 2022 server sends it together with the
// first response payload, so Dial must not block on it).
func (c *Client) wrapTCP(raw net.Conn, target Addr) (net.Conn, error) {
	m := c.method
	salt := make([]byte, m.KeyLen)
	if _, err := io.ReadFull(c.rand, salt); err != nil {
		return nil, kernelErrInternal("shadowsocks.DialTCP", "generate salt", err)
	}
	var subkey []byte
	if m.Is2022 {
		subkey = sessionKey2022(c.key, salt, m.KeyLen)
	} else {
		subkey = subkey2017(c.key, salt, m.KeyLen)
	}
	aead, err := m.newAEAD(subkey)
	if err != nil {
		return nil, kernelErrInternal("shadowsocks.DialTCP", "build AEAD", err)
	}
	nonce := newNonceCounter(m.NonceLen)
	w := newChunkWriter(raw, aead, nonce, chunkCap2017)

	if m.Is2022 {
		if err := c.writeRequestHeader2022(raw, aead, nonce, salt, target); err != nil {
			return nil, handshakeErr("shadowsocks.DialTCP", err)
		}
	} else {
		// SIP004: the salt leads. The address header shares the
		// first payload chunk (receivers read a continuous
		// plaintext stream, so chunk boundaries are the sender's
		// choice; the merged first chunk is the shape the frozen
		// vectors and shadowsocks-rust use): seed the chunk
		// writer's buffer with the address bytes and let the
		// first payload Write/Flush carry them out.
		if _, err := raw.Write(salt); err != nil {
			return nil, handshakeErr("shadowsocks.DialTCP", err)
		}
		w.buf = target.appendSocks(w.buf)
	}

	conn := &tcpConn{raw: raw, w: w, reqSalt: salt}
	conn.r = &responseReader{client: c, raw: raw, reqSalt: salt, conn: conn}
	return conn, nil
}

// writeRequestHeader2022 writes salt || AEAD(fixed header) ||
// AEAD(variable header) in ONE write call (SIP022 3.1.4). With
// no initial payload available at dial time, a random padding
// of 1..900 bytes stands in (SIP022 3.1.4: either payload or
// non-zero padding must be present).
func (c *Client) writeRequestHeader2022(raw io.Writer, aead cipher.AEAD, nonce *nonceCounter, salt []byte, target Addr) error {
	padLen := 1 + int(readRandomUint16(c.rand)%900)
	padding := make([]byte, padLen)
	if _, err := io.ReadFull(c.rand, padding); err != nil {
		return err
	}
	return c.writeRequestHeader2022With(raw, aead, nonce, salt, target, padding, nil)
}

// writeRequestHeader2022With is the deterministic core of the
// 2022 request prologue (vector tests drive it directly).
func (c *Client) writeRequestHeader2022With(raw io.Writer, aead cipher.AEAD, nonce *nonceCounter, salt []byte, target Addr, padding, initialPayload []byte) error {
	varHeader := target.appendSocks(nil)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(padding)))
	varHeader = append(varHeader, lb[:]...)
	varHeader = append(varHeader, padding...)
	varHeader = append(varHeader, initialPayload...)
	if len(varHeader) > 0xFFFF {
		return fmt.Errorf("%w: variable header too large", ErrProtocol)
	}
	fixed := []byte{0x00}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(c.now().Unix()))
	fixed = append(fixed, ts[:]...)
	binary.BigEndian.PutUint16(lb[:], uint16(len(varHeader)))
	fixed = append(fixed, lb[:]...)

	out := append([]byte{}, salt...)
	out = aead.Seal(out, nonce.next(), fixed, nil)
	out = aead.Seal(out, nonce.next(), varHeader, nil)
	_, err := raw.Write(out)
	return err
}

// responseReader lazily parses the response prologue on the
// first Read, then delegates to the chunk reader.
type responseReader struct {
	client  *Client
	raw     io.Reader
	reqSalt []byte
	conn    *tcpConn
	inner   io.Reader
	err     error
}

func (r *responseReader) Read(p []byte) (int, error) {
	if r.inner == nil {
		if r.err != nil {
			return 0, r.err
		}
		inner, err := r.client.readResponsePrologue(r.raw, r.reqSalt)
		if err != nil {
			r.err = handshakeErr("shadowsocks.Read", err)
			return 0, r.err
		}
		r.inner = inner
	}
	return r.inner.Read(p)
}

// readResponsePrologue consumes the response salt and, for
// 2022, the fixed response header (validating type, timestamp
// window and the echoed request salt per SIP022 3.1.3), and
// returns the reader for the payload stream.
func (c *Client) readResponsePrologue(raw io.Reader, reqSalt []byte) (io.Reader, error) {
	m := c.method
	salt := make([]byte, m.KeyLen)
	if _, err := io.ReadFull(raw, salt); err != nil {
		return nil, wrapStreamEOF(err)
	}
	var subkey []byte
	if m.Is2022 {
		subkey = sessionKey2022(c.key, salt, m.KeyLen)
	} else {
		subkey = subkey2017(c.key, salt, m.KeyLen)
	}
	aead, err := m.newAEAD(subkey)
	if err != nil {
		return nil, err
	}
	nonce := newNonceCounter(m.NonceLen)
	if !m.Is2022 {
		// SIP004 TCP responses carry no address header (the
		// address exists only in the client's request stream;
		// per-packet address headers are a UDP property).
		// Verified live against shadowsocks-rust v1.25.0 and
		// sing-box by the differential rig - see spec section 6
		// item 8.
		return newChunkReader(raw, aead, nonce, chunkCap2017), nil
	}
	// 2022: the fixed response header is a standalone AEAD chunk
	// of 1 + 8 + saltLen + 2 bytes and doubles as the first
	// length chunk.
	hdrLen := 1 + 8 + m.KeyLen + 2
	buf := make([]byte, hdrLen+tagSize)
	if _, err := io.ReadFull(raw, buf); err != nil {
		return nil, wrapStreamEOF(err)
	}
	hdr, err := aead.Open(nil, nonce.next(), buf, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: response header chunk", ErrAEADFailure)
	}
	if hdr[0] != 0x01 {
		return nil, fmt.Errorf("%w: response header type %d, want 1", ErrProtocol, hdr[0])
	}
	ts := int64(binary.BigEndian.Uint64(hdr[1:9]))
	if d := c.now().Unix() - ts; d > 30 || d < -30 {
		return nil, fmt.Errorf("%w: response timestamp outside the 30 s window", ErrProtocol)
	}
	echoed := hdr[9 : 9+m.KeyLen]
	if !equalBytes(echoed, reqSalt) {
		return nil, fmt.Errorf("%w: response header echoes a different request salt", ErrProtocol)
	}
	firstLen := int(binary.BigEndian.Uint16(hdr[9+m.KeyLen:]))
	cr := newChunkReader(raw, aead, nonce, chunkCap2022)
	cr.nextLen = firstLen
	return cr, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readRandomUint16 reads two bytes from r as a uint16 (padding
// length selection; modulo bias is irrelevant there).
func readRandomUint16(r io.Reader) uint16 {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}
