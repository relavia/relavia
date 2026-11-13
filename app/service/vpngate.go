package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"openproxy/core/parsers"
	"openproxy/core/specnode"

	"openproxy/plugins/vpngate"
)

// VPN Gate public-pool wiring (Step 14 plugin, previously
// unconnected: app/service and the UI held zero references to
// plugins/vpngate, so the pool existed only as a standalone
// component — docs/known-issues-beta.md KI-03). This file is
// the app-side integration:
//
//   - the plugin is registered as a first-class node source:
//     visible, enable/disable, refresh through the plugin's own
//     Fetcher (mirror rotation + anti-poisoning validation);
//   - the book 7.3 risk gate is the plugin's consent state
//     machine, untouched: the service only forwards Acknowledge
//     / Enable / Disable, and every gated operation surfaces
//     ErrConsentRequired — there is no service-side bypass and
//     no second, weaker gate;
//   - refreshed nodes land in the store with their source
//     registration (kind=plugin, ref=vpngate) and country
//     groups, plus the admission level actually established
//     for each node (TCP reachability at refresh; a later
//     successful engine handshake test upgrades a node to
//     handshake-verified, and refreshes never downgrade it).

// VPNGateSourceRef is the unified-model source reference of
// every pool node (plugins/vpngate manifest id; the Step 8
// parser stamps it on the nodes it produces for this source).
const VPNGateSourceRef = "vpngate"

// ErrVPNGateConsentRequired re-exports the plugin's consent
// sentinel so the UI can map it to its localized string without
// importing the plugin package.
var ErrVPNGateConsentRequired = vpngate.ErrConsentRequired

// NewVPNGatePlugin builds the production plugin with its file
// cache and file consent store rooted at dir (the app creates
// it next to the node store: <config>/Relavia/vpngate).
func NewVPNGatePlugin(dir string) (*vpngate.Plugin, error) {
	return vpngate.NewDefault(dir)
}

// AttachVPNGateDefault is the entry-point wiring helper: it
// builds the production plugin rooted in a "vpngate" directory
// next to the store file and attaches it to the service.
// Failure is deliberately non-fatal — the source then reports
// itself unattached in the sources view — because a broken
// plugin state directory must not take the whole client down.
func AttachVPNGateDefault(s *Service, storePath string) {
	dir := filepath.Join(filepath.Dir(storePath), "vpngate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.logf("vpngate: source unavailable (state dir): %v", err)
		return
	}
	p, err := NewVPNGatePlugin(dir)
	if err != nil {
		s.logf("vpngate: source unavailable: %v", err)
		return
	}
	s.SetVPNGate(p)
}

// IsVPNGateNode reports whether a node came from the VPN Gate
// pool (as opposed to a user import).
func IsVPNGateNode(n *specnode.Node) bool {
	return n != nil && n.Source.Ref == VPNGateSourceRef
}

// SetVPNGate attaches the VPN Gate plugin as a node source.
// Entry points call it once at startup; a nil plugin (or never
// calling this) leaves the source unavailable and every
// VPNGate* method reports that honestly.
func (s *Service) SetVPNGate(p *vpngate.Plugin) {
	s.vgMu.Lock()
	defer s.vgMu.Unlock()
	s.vg = p
}

func (s *Service) vpngatePlugin() *vpngate.Plugin {
	s.vgMu.Lock()
	defer s.vgMu.Unlock()
	return s.vg
}

// Consent state strings reported in VPNGateStatus (internal
// identifiers, never display text).
const (
	VPNGateConsentNone         = "none"
	VPNGateConsentAcknowledged = "acknowledged"
	VPNGateConsentRevoked      = "revoked"
	VPNGateConsentStale        = "stale"
)

// Admission levels recorded on pool nodes (the plugin's probe
// level identifiers, re-exported so the UI switches on the
// constants instead of spelling internal values).
const (
	AdmissionTCPConnect        = vpngate.ProbeLevelTCPConnect
	AdmissionHandshakeVerified = vpngate.ProbeLevelHandshakeVerified
	AdmissionNone              = vpngate.ProbeLevelNone
)

// VPNGateStatus is the sources-view snapshot of the pool.
type VPNGateStatus struct {
	Attached     bool
	Enabled      bool
	ConsentState string // VPNGateConsent* value
	NodeCount    int
	LastRefresh  time.Time // zero when never refreshed (or after disable)
	Stale        bool      // displayed nodes are a previous snapshot
	LastError    string    // last refresh failure detail, when Stale
}

// VPNGateStatus reports the pool's current state: live consent
// and enablement from the plugin, node count from the store,
// freshness from the persisted refresh bookkeeping.
func (s *Service) VPNGateStatus() VPNGateStatus {
	st := VPNGateStatus{ConsentState: VPNGateConsentNone}
	p := s.vpngatePlugin()
	if p == nil {
		return st
	}
	st.Attached = true
	st.Enabled = p.Enabled()
	switch p.Consent.State() {
	case vpngate.ConsentAcknowledged:
		st.ConsentState = VPNGateConsentAcknowledged
	case vpngate.ConsentRevoked:
		st.ConsentState = VPNGateConsentRevoked
	case vpngate.ConsentStale:
		st.ConsentState = VPNGateConsentStale
	}
	for _, rec := range s.store.Snapshot().Nodes {
		if IsVPNGateNode(rec.Node) {
			st.NodeCount++
		}
	}
	set := s.store.Settings()
	if set.VPNGateLastRefresh != "" {
		if t, err := time.Parse(time.RFC3339, set.VPNGateLastRefresh); err == nil {
			st.LastRefresh = t
		}
	}
	st.Stale = set.VPNGateStale
	st.LastError = set.VPNGateLastError
	return st
}

// AcknowledgeVPNGateRisk records the user's acknowledgement of
// the current risk text in the plugin's consent state machine.
// The UI renders the disclosure from the risk.vpngate.* i18n
// keys (the plugin's RiskKeys) and calls this on confirm — the
// acknowledgement itself is the plugin's, versioned against
// the risk text exactly as Step 14 built it.
func (s *Service) AcknowledgeVPNGateRisk() error {
	p := s.vpngatePlugin()
	if p == nil {
		return ErrVPNGateNotAttached
	}
	return p.Consent.Acknowledge(time.Now())
}

// ErrVPNGateNotAttached reports VPNGate operations on a build
// whose entry point never attached the plugin.
var ErrVPNGateNotAttached = errors.New("service: VPN Gate source not attached")

// ErrVPNGateFetchFailed wraps a total list-fetch failure (no
// endpoint reachable, no cache to fall back on) so the UI can
// map it to its localized string; the underlying fetch detail
// is preserved in the wrap and in the status bookkeeping.
var ErrVPNGateFetchFailed = errors.New("service: VPN Gate list fetch failed")

// EnableVPNGate switches the pool source on. Hard gate: without
// a current risk acknowledgement the plugin refuses with
// ErrConsentRequired and so does this method.
func (s *Service) EnableVPNGate() error {
	p := s.vpngatePlugin()
	if p == nil {
		return ErrVPNGateNotAttached
	}
	if err := p.Enable(); err != nil {
		return err
	}
	s.logf("vpngate: source enabled")
	return nil
}

// DisableVPNGate switches the pool off with the plugin's full
// disable semantics: consent revoked, fetch cache purged. The
// pool nodes already imported are removed from the store as
// well — a revoked source must be unusable, not merely
// unrefreshable — so re-enabling later starts from the risk
// gate and a fresh refresh, exactly like the plugin's own
// lifecycle prescribes.
func (s *Service) DisableVPNGate() error {
	p := s.vpngatePlugin()
	if p == nil {
		return ErrVPNGateNotAttached
	}
	if err := p.Disable(time.Now()); err != nil {
		return err
	}
	removed := s.removeVPNGateNodes()
	s.store.UpdateSettings(func(st *Settings) {
		st.VPNGateLastRefresh = ""
		st.VPNGateStale = false
		st.VPNGateLastError = ""
	})
	_ = s.store.Save()
	s.logf("vpngate: source disabled (consent revoked, cache purged, %d pool nodes removed)", removed)
	return nil
}

// removeVPNGateNodes deletes every pool node from the store and
// reports how many were removed. Caller persists. IDs are
// collected before deleting: Store.Snapshot shares its slice
// backing with the live document, so deleting mid-iteration
// would shift elements under the iterator and skip nodes.
func (s *Service) removeVPNGateNodes() int {
	var ids []string
	for _, rec := range s.store.Snapshot().Nodes {
		if IsVPNGateNode(rec.Node) {
			ids = append(ids, rec.Node.ID)
		}
	}
	removed := 0
	for _, id := range ids {
		if s.store.DeleteNode(id) {
			removed++
		}
	}
	return removed
}

// VPNGateRefresh summarizes one pool refresh for the UI.
type VPNGateRefresh struct {
	NodeCount       int
	GroupCount      int
	RowErrors       int
	FetchedAt       time.Time
	FromCache       bool
	Stale           bool
	LastError       string
	ProbedReachable int
}

// RefreshVPNGate pulls the official list through the plugin and
// folds it into the store. Failure honesty:
//
//   - consent missing/revoked: ErrConsentRequired, nothing
//     touched;
//   - every endpoint failed with no cache anywhere: the fetch
//     error is returned, the previously imported nodes stay in
//     place and are marked stale (never silently dropped, never
//     presented as fresh);
//   - endpoints failed but a cache existed: the plugin serves
//     the cache labelled Stale — the refresh succeeds with the
//     stale snapshot, the result and the status both carry the
//     Stale flag and the failure detail.
//
// On success each node's admission level is (re)established by
// the plugin's TCP reachability probe — labelled tcp-connect,
// never a handshake claim; a previously handshake-verified node
// keeps its higher level.
func (s *Service) RefreshVPNGate(ctx context.Context, force bool) (*VPNGateRefresh, error) {
	p := s.vpngatePlugin()
	if p == nil {
		return nil, ErrVPNGateNotAttached
	}
	cat, err := p.Refresh(ctx, force)
	if err != nil {
		if errors.Is(err, vpngate.ErrConsentRequired) {
			return nil, err
		}
		// Total fetch failure: keep the old snapshot, mark it
		// stale with the reason, and surface the error.
		s.store.UpdateSettings(func(st *Settings) {
			st.VPNGateStale = true
			st.VPNGateLastError = err.Error()
		})
		_ = s.store.Save()
		s.logf("vpngate: refresh failed, previous snapshot kept and marked stale: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrVPNGateFetchFailed, err)
	}

	// Fold the catalog into the store: convert through the
	// shared schema round trip, register country groups,
	// replace the pool wholesale (nodes that vanished from the
	// official list vanish here too).
	type probeTarget struct {
		pn *parsers.Node
		id string
	}
	var targets []probeTarget
	newIDs := map[string]bool{}
	for _, pn := range cat.Nodes {
		sn, err := toSpecNode(pn)
		if err != nil {
			s.logf("vpngate: node %s failed model conversion: %v", pn.ID, err)
			continue
		}
		s.store.AddNode(sn, nil)
		newIDs[sn.ID] = true
		targets = append(targets, probeTarget{pn: pn, id: sn.ID})
	}
	for _, g := range cat.Groups {
		s.store.AddGroup(g.Name)
	}
	// Collect-then-delete for the same shared-slice reason as
	// removeVPNGateNodes.
	var vanished []string
	for _, rec := range s.store.Snapshot().Nodes {
		if IsVPNGateNode(rec.Node) && !newIDs[rec.Node.ID] {
			vanished = append(vanished, rec.Node.ID)
		}
	}
	for _, id := range vanished {
		s.store.DeleteNode(id)
	}

	// Admission probing (TCP reachability, bounded concurrency).
	prober := s.vgProber
	if prober == nil {
		prober = &vpngate.Prober{}
	}
	var reached int64
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(pn *parsers.Node, id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			res := prober.Probe(ctx, pn)
			if rec, ok := s.store.NodeByID(id); ok &&
				rec.Admission == vpngate.ProbeLevelHandshakeVerified {
				// A refresh never downgrades an established
				// handshake verification.
				if res.Reachable {
					atomic.AddInt64(&reached, 1)
				}
				return
			}
			level := vpngate.ProbeLevelNone
			if res.Reachable {
				level = vpngate.ProbeLevelTCPConnect
				atomic.AddInt64(&reached, 1)
			}
			s.store.SetAdmission(id, level)
		}(t.pn, t.id)
	}
	wg.Wait()

	s.store.UpdateSettings(func(st *Settings) {
		st.VPNGateLastRefresh = cat.Info.FetchedAt.UTC().Format(time.RFC3339)
		st.VPNGateStale = cat.Info.Stale
		st.VPNGateLastError = cat.Info.LastError
	})
	_ = s.store.Save()
	rep := &VPNGateRefresh{
		NodeCount:       len(targets),
		GroupCount:      len(cat.Groups),
		RowErrors:       cat.RowErrors,
		FetchedAt:       cat.Info.FetchedAt,
		FromCache:       cat.Info.FromCache,
		Stale:           cat.Info.Stale,
		LastError:       cat.Info.LastError,
		ProbedReachable: int(reached),
	}
	if rep.Stale {
		s.logf("vpngate: refreshed from stale cache: %d nodes / %d groups (%s)", rep.NodeCount, rep.GroupCount, rep.LastError)
	} else {
		s.logf("vpngate: refreshed: %d nodes / %d groups, %d tcp-reachable", rep.NodeCount, rep.GroupCount, rep.ProbedReachable)
	}
	return rep, nil
}
