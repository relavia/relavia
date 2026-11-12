//go:build with_quic

package singbox

// QUIC-family protocols (Hysteria2, TUIC) are compiled into
// sing-box only with the with_quic tag. The project's official
// build includes it (Step 7); these mirrors keep Capabilities()
// honest in any build.
const featureQUIC = true
