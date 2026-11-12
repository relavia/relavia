package service

import (
	"openproxy/core/parsers"
	"openproxy/core/specnode"
)

// Node risk classification (UI execution point of the Step 5
// frozen ruling, completed by Step 8's parser warnings):
//
//   - A node whose Shadowsocks method is a legacy non-AEAD method
//     is WEAK. Such nodes are kept importable (lossless import of
//     existing subscriptions) but must be visibly marked in the UI
//     and must never be the default recommendation — see
//     AutoSelect for the selection-side half of the ruling.
//   - A node configured to skip TLS certificate verification is
//     INSECURE and is marked likewise.
//
// WeakSSMethods mirrors core/parsers' weakSSMethods exactly (the
// legacy subset of the schema's CredShadowsocks method enum). The
// parser already attaches a structured weak-encryption warning at
// import time; this set lets the service classify nodes that
// arrived by any path (file import, hand-built records, older
// stores) without trusting stored flags.
var WeakSSMethods = map[string]bool{
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"chacha20": true, "chacha20-ietf": true, "xchacha20": true,
	"rc4-md5": true, "none": true,
}

// WeakEncryption reports whether the node relies on a legacy weak
// cipher.
func WeakEncryption(n *specnode.Node) bool {
	if n == nil || n.Protocol != specnode.ProtocolShadowsocks || n.Shadowsocks == nil {
		return false
	}
	return WeakSSMethods[n.Shadowsocks.Method]
}

// InsecureSkipVerify reports whether the node skips TLS
// certificate verification.
func InsecureSkipVerify(n *specnode.Node) bool {
	return n != nil && n.Security != nil && n.Security.AllowInsecure
}

// WarningCodes recomputes the stable warning codes that apply to
// a node right now (parser warning codes, package parsers). The
// import path stores the codes the parser emitted; this function
// is the floor that always applies regardless of stored data.
func WarningCodes(n *specnode.Node) []string {
	var out []string
	if WeakEncryption(n) {
		out = append(out, parsers.WarnWeakEncryption)
	}
	if InsecureSkipVerify(n) {
		out = append(out, parsers.WarnInsecureSkipVerify)
	}
	return out
}

// mergeWarnings unions stored (parser-emitted) codes with the
// recomputed floor, preserving order and removing duplicates.
func mergeWarnings(stored []string, n *specnode.Node) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(stored)+2)
	for _, c := range append(append([]string{}, stored...), WarningCodes(n)...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
