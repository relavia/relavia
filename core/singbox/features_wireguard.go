//go:build with_wireguard

package singbox

// The WireGuard endpoint is registered into sing-box only with
// the with_wireguard tag. The project's official build includes
// it (Step 7).
const featureWireGuard = true
