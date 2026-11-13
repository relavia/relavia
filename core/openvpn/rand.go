package openvpn

import (
	"crypto/rand"
	"encoding/hex"
)

// randomHex returns n random bytes hex-encoded (used for the
// management endpoint password on TCP-endpoint platforms).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "relavia-mgmt-fallback"
	}
	return hex.EncodeToString(b)
}
