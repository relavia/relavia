package vpngate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMappingOnRealSample runs the mapping over the real excerpt
// captured from the official endpoint on 2026-11-12
// (testdata/vpngate-sample-2026-11-12.csv: header + 10 rows).
func TestMappingOnRealSample(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := BuildCatalog(samplePayload(t), ListInfo{FetchedAt: time.Now(), Endpoint: "test"}, m)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	if len(cat.Nodes) == 0 {
		t.Fatal("no nodes mapped")
	}
	if len(cat.Nodes)+cat.RowErrors != 10 {
		t.Fatalf("nodes %d + rowErrors %d != 10 sample rows", len(cat.Nodes), cat.RowErrors)
	}
	// Every node: OpenVPN, unified model, config body riding on
	// the credential (configContent mode), plugin source ref,
	// volunteer tag, country group.
	for i, n := range cat.Nodes {
		if n.Protocol != "openvpn" {
			t.Errorf("node %d protocol = %q", i, n.Protocol)
		}
		var cred struct {
			ConfigContent string `json:"configContent"`
		}
		if err := json.Unmarshal(n.Credential, &cred); err != nil || !strings.Contains(cred.ConfigContent, "remote ") {
			t.Errorf("node %d credential lacks the .ovpn body: err=%v", i, err)
		}
		if n.Source.Kind != "plugin" || n.Source.Authorization != "vpngate-official-csv" {
			t.Errorf("node %d source = %+v", i, n.Source)
		}
		if !hasTag(n.Tags, "volunteer") {
			t.Errorf("node %d missing volunteer tag", i)
		}
		if n.Group == "" {
			t.Errorf("node %d has no country group", i)
		}
		if cat.Meta[i].HostName == "" || !cat.Meta[i].Volunteer {
			t.Errorf("meta %d misaligned: %+v", i, cat.Meta[i])
		}
	}
	// Source registration: grade A per book 7.1, manifest
	// enrichment applied.
	src := cat.Source
	if src.Authorization.Status != "A" || src.Authorization.Basis != "vpngate-official-csv" {
		t.Errorf("source authorization = %+v", src.Authorization)
	}
	if src.Authorization.TermsURL == nil || *src.Authorization.TermsURL != m.Authorization.TermsURL {
		t.Errorf("source termsUrl not enriched from manifest: %+v", src.Authorization.TermsURL)
	}
	if src.Operator == nil || *src.Operator != "VPN Gate (University of Tsukuba)" {
		t.Errorf("source operator = %v", src.Operator)
	}
	if src.UpdateIntervalMinutes == nil || *src.UpdateIntervalMinutes != 60 {
		t.Errorf("source update interval = %v", src.UpdateIntervalMinutes)
	}
	// Grouping: the sample is all-Japan rows; groups cover every
	// node exactly once and point back at the source.
	total := 0
	foundJP := false
	for _, g := range cat.Groups {
		total += len(g.NodeIDs)
		if g.Name == "Japan" {
			foundJP = true
		}
		if g.SourceID == nil || *g.SourceID != src.ID {
			t.Errorf("group %q sourceId mismatch", g.Name)
		}
	}
	if !foundJP {
		t.Errorf("no Japan group in %+v", cat.Groups)
	}
	if total != len(cat.Nodes) {
		t.Errorf("groups cover %d nodes, catalog has %d", total, len(cat.Nodes))
	}
	// The CSV's own declared packet-log retention rides along
	// per node (real list: "2weeks").
	if cat.Meta[0].LogType != "2weeks" {
		t.Errorf("meta[0].LogType = %q, want 2weeks (as declared in the real CSV)", cat.Meta[0].LogType)
	}
	if !strings.Contains(cat.Nodes[0].Name, "[JP]") {
		t.Errorf("first node name = %q, want country-coded VPN Gate naming", cat.Nodes[0].Name)
	}
}

func TestManifestGradeAndPermissions(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.RiskText.Version != RiskTextVersion {
		t.Fatalf("manifest risk version %q != code %q", m.RiskText.Version, RiskTextVersion)
	}
	if len(RiskKeys()) != 6 {
		t.Fatalf("risk key set = %v", RiskKeys())
	}
	for _, k := range RiskKeys() {
		if !strings.HasPrefix(k, m.RiskText.I18nKeyPrefix) {
			t.Fatalf("key %q outside manifest prefix %q", k, m.RiskText.I18nKeyPrefix)
		}
	}
}

// TestPluginEnableGate exercises the full lifecycle against a
// fake server: no consent -> cannot enable or refresh; consent
// -> enable + refresh; disable -> gate closed, cache purged,
// refresh refused again.
func TestPluginEnableGate(t *testing.T) {
	payload := samplePayload(t)
	srv := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	dir := t.TempDir()

	newPlugin := func() *Plugin {
		consent, err := NewConsent(&FileConsentStore{Path: dir + "/consent.json"})
		if err != nil {
			t.Fatal(err)
		}
		p, err := New(&Fetcher{Endpoints: []string{srv.URL}, Cache: &FileCache{Dir: dir}}, consent)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	p := newPlugin()
	if err := p.Enable(); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("Enable before consent: %v", err)
	}
	if _, err := p.Refresh(context.Background(), false); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("Refresh before consent: %v", err)
	}
	if err := p.Consent.Acknowledge(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.Enable(); err != nil {
		t.Fatalf("Enable after consent: %v", err)
	}
	cat, err := p.Refresh(context.Background(), false)
	if err != nil {
		t.Fatalf("Refresh after enable: %v", err)
	}
	if len(cat.Nodes) == 0 || cat.Info.Stale {
		t.Fatalf("catalog = %d nodes, info %+v", len(cat.Nodes), cat.Info)
	}
	// Disable: consent revoked + cache purged.
	if err := p.Disable(time.Now()); err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Fatal("plugin still enabled after Disable")
	}
	if _, err := p.Refresh(context.Background(), false); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("Refresh after disable: %v", err)
	}
	p2 := newPlugin() // fresh instances over the same dir: nothing may survive
	if p2.Consent.State() != ConsentRevoked {
		t.Fatalf("persisted consent state = %v, want Revoked", p2.Consent.State())
	}
	if _, info, err := (&FileCache{Dir: dir}).Load(); err != nil || info.FetchedAt.IsZero() == false {
		t.Fatalf("cache survived disable: info=%+v err=%v", info, err)
	}
}
