package service

import (
	"crypto/ed25519"
	"encoding/base64"
)

// ============================================================================
// TEST-ONLY RELEASE KEY — NOT FOR PRODUCTION — TEST-ONLY RELEASE KEY
// ============================================================================
//
// ReleasePublicKeyB64 below is the Ed25519 public key of a
// THROWAWAY keypair generated solely so Step 16 (update
// mechanism) could implement and negatively test the full
// signature-verification chain end to end. The matching private
// key exists only inside update_test.go and signs test fixtures;
// it must never sign a real release.
//
// REPLACEMENT POINT (Step 15 / release owner): the production
// release pipeline generates the real release keypair, the
// private key stays in the release owner's custody (never in
// this repository, never in CI secrets beyond the signing job),
// and the production public key replaces the constant below —
// that single-line change is the entire client-side backfill.
// Until that happens, builds carry this test key and any
// "verified" update is only as real as this notice says.
// ============================================================================
const ReleasePublicKeyB64 = "iL7jVjaFnEBJPzNWK1wgdLq9kMOkFUxDsNZfrWxJvTo="

// ReleasePublicKey returns the embedded release-signing public
// key (currently the TEST-ONLY key above).
func ReleasePublicKey() ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(ReleasePublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}
