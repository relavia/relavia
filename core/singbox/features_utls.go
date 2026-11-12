//go:build with_utls

package singbox

// uTLS fingerprints and Reality are compiled into sing-box only
// with the with_utls tag (in sing-box 1.14 the Reality server also
// rides on it). The project's official build includes it (Step 7).
const featureUTLS = true
