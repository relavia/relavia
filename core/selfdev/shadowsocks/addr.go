package shadowsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Addr is a proxy target address (SOCKS5 address form, used by
// both Shadowsocks editions as their address header).
type Addr struct {
	Host string // IP literal or domain name
	Port int
}

// ParseAddr parses "host:port" (host may be an IP literal or a
// domain name; IPv6 literals need brackets, as usual).
func ParseAddr(s string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return Addr{}, fmt.Errorf("shadowsocks: bad port in address %q", s)
	}
	if host == "" {
		return Addr{}, fmt.Errorf("shadowsocks: empty host in address %q", s)
	}
	return Addr{Host: host, Port: port}, nil
}

// String returns the "host:port" form.
func (a Addr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

// UDPAddr converts to a *net.UDPAddr when Host is an IP literal.
func (a Addr) UDPAddr() (*net.UDPAddr, error) {
	ip := net.ParseIP(a.Host)
	if ip == nil {
		return nil, fmt.Errorf("shadowsocks: %q is not an IP literal", a.Host)
	}
	return &net.UDPAddr{IP: ip, Port: a.Port}, nil
}

// AppendSocks appends the SOCKS5 address encoding to dst
// (exported for the forwarding plane's UDP reply headers).
func (a Addr) AppendSocks(dst []byte) []byte { return a.appendSocks(dst) }

// socksLen is the encoded length of the address header.
func (a Addr) socksLen() int {
	if ip := net.ParseIP(a.Host); ip != nil {
		if ip.To4() != nil {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(a.Host) + 2
}

// appendSocks appends the SOCKS5 address encoding
// (ATYP || address || port u16be) to dst.
func (a Addr) appendSocks(dst []byte) []byte {
	if ip := net.ParseIP(a.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, 0x01)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, 0x04)
			dst = append(dst, ip.To16()...)
		}
	} else {
		dst = append(dst, 0x03, byte(len(a.Host)))
		dst = append(dst, a.Host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(a.Port))
	return append(dst, p[:]...)
}

// errShortAddress marks a truncated address header.
var errShortAddress = errors.New("shadowsocks: truncated address header")

// parseSocksAddr decodes one SOCKS5 address from the head of b,
// returning the address and the number of bytes consumed.
func parseSocksAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, errShortAddress
	}
	var host string
	var n int
	switch b[0] {
	case 0x01:
		if len(b) < 1+4+2 {
			return Addr{}, 0, errShortAddress
		}
		host = net.IP(b[1:5]).String()
		n = 1 + 4
	case 0x04:
		if len(b) < 1+16+2 {
			return Addr{}, 0, errShortAddress
		}
		host = net.IP(b[1:17]).String()
		n = 1 + 16
	case 0x03:
		if len(b) < 2 {
			return Addr{}, 0, errShortAddress
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return Addr{}, 0, errShortAddress
		}
		host = string(b[2 : 2+l])
		n = 2 + l
	default:
		return Addr{}, 0, fmt.Errorf("%w: unknown address type 0x%02x", ErrProtocol, b[0])
	}
	port := int(binary.BigEndian.Uint16(b[n : n+2]))
	return Addr{Host: host, Port: port}, n + 2, nil
}
