package vpngate

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"openproxy/core/parsers"
)

// NodeMeta carries the per-server list metadata the CSV itself
// publishes (score, operator-reported ping/speed, session count
// and the operator's declared log-retention type). It travels
// alongside the unified-model node; nothing here is measured by
// us — SourceReported fields are the source's own figures and
// are labelled as such for the UI.
type NodeMeta struct {
	HostName     string
	IP           string
	CountryShort string
	CountryLong  string
	Operator     string
	Message      string
	// LogType is the operator's declared packet-log retention
	// from the CSV (the 2026-11-12 real list declares "2weeks"
	// for every server). Surfaced verbatim so the UI can show
	// the retention next to each node.
	LogType string
	// Volunteer is always true for this source: every VPN Gate
	// relay runs on a volunteer's own computer (book 7.3
	// requires the volunteer attribute to be labelled).
	Volunteer bool

	ScoreReported    int64
	PingMsReported   int64
	SpeedBpsReported int64
	SessionsReported int64
}

// Catalog is one parsed, grouped snapshot of the VPN Gate list.
type Catalog struct {
	Source *parsers.Source
	Nodes  []*parsers.Node
	// Meta is parallel to the parser's item order filtered to
	// usable nodes: Meta[i] describes Nodes[i].
	Meta   []NodeMeta
	Groups []parsers.Group
	Info   ListInfo
	// RowErrors counts CSV data rows that produced no node
	// (bad embedded config etc.); they are skipped, never
	// silently turned into nodes.
	RowErrors int
}

// Plugin is the VPN Gate source plugin facade. Lifecycle:
//
//	New -> (risk page shown) -> Consent.Acknowledge ->
//	Enable -> Refresh... -> Disable (revokes consent, purges
//	cache, source off).
type Plugin struct {
	Manifest *Manifest
	Fetcher  *Fetcher
	Consent  *Consent

	enabled bool
}

// New builds a plugin from the embedded manifest with the given
// fetch/consent wiring.
func New(fetcher *Fetcher, consent *Consent) (*Plugin, error) {
	m, err := LoadManifest()
	if err != nil {
		return nil, err
	}
	if fetcher == nil || consent == nil {
		return nil, fmt.Errorf("vpngate: fetcher and consent are required")
	}
	if len(fetcher.Endpoints) == 0 {
		fetcher.Endpoints = append([]string{}, m.Endpoints...)
	}
	return &Plugin{Manifest: m, Fetcher: fetcher, Consent: consent}, nil
}

// NewDefault wires the plugin with a file cache and file
// consent store rooted at dir (the plugin's local state
// directory).
func NewDefault(dir string) (*Plugin, error) {
	consent, err := NewConsent(&FileConsentStore{Path: dir + "/consent.json"})
	if err != nil {
		return nil, err
	}
	fetcher := &Fetcher{Cache: &FileCache{Dir: dir}}
	return New(fetcher, consent)
}

// Enabled reports whether the source is currently switched on.
// It re-checks consent on every call: a revocation or a risk
// text version bump switches the source off immediately.
func (p *Plugin) Enabled() bool {
	if !p.enabled {
		return false
	}
	if p.Consent.Require() != nil {
		p.enabled = false
		return false
	}
	return true
}

// Enable switches the source on. Hard gate of book 7.3: without
// a current risk acknowledgement this fails with
// ErrConsentRequired — there is no path around it.
func (p *Plugin) Enable() error {
	if err := p.Consent.Require(); err != nil {
		return err
	}
	p.enabled = true
	return nil
}

// Disable switches the source off, revokes the risk
// acknowledgement and purges the fetch cache (book 7.2
// self-check: disabling removes cached source data; a later
// re-enable must pass the risk gate again).
func (p *Plugin) Disable(at time.Time) error {
	p.enabled = false
	var firstErr error
	if err := p.Consent.Revoke(at); err != nil && firstErr == nil {
		firstErr = err
	}
	if p.Fetcher != nil && p.Fetcher.Cache != nil {
		if err := p.Fetcher.Cache.Purge(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Refresh fetches (or serves the cache), parses and groups the
// list. It refuses to run while the source is not enabled.
func (p *Plugin) Refresh(ctx context.Context, force bool) (*Catalog, error) {
	if !p.Enabled() {
		if err := p.Consent.Require(); err != nil {
			return nil, err
		}
		return nil, ErrConsentRequired
	}
	payload, info, err := p.Fetcher.Fetch(ctx, force)
	if err != nil {
		return nil, err
	}
	return BuildCatalog(payload, info, p.Manifest)
}

// BuildCatalog turns a validated CSV payload into the catalog:
// nodes come exclusively from the Step 8 parser (never
// re-implemented here); this layer adds the source registration
// enrichment, the per-row metadata zip and country grouping.
func BuildCatalog(payload []byte, info ListInfo, m *Manifest) (*Catalog, error) {
	res := parsers.ParseVPNGateCSV(string(payload), parsers.Options{})
	if res.SourceRecord == nil {
		return nil, fmt.Errorf("%w: no source registration produced", ErrInvalidPayload)
	}
	src := res.SourceRecord
	// Enrich the parser's registration with the manifest's
	// registration data (book 7.2 manifest fields the format
	// parser does not know): terms URL, homepage, update
	// interval. Status/basis stay exactly as the parser set
	// them (A / vpngate-official-csv).
	if m != nil {
		if src.Authorization.TermsURL == nil && m.Authorization.TermsURL != "" {
			terms := m.Authorization.TermsURL
			src.Authorization.TermsURL = &terms
		}
		if src.Homepage == nil && m.Homepage != "" {
			home := m.Homepage
			src.Homepage = &home
		}
		if src.UpdateIntervalMinutes == nil && m.UpdateIntervalMinutes > 0 {
			iv := m.UpdateIntervalMinutes
			src.UpdateIntervalMinutes = &iv
		}
	}

	metas := scanRowMeta(string(payload))
	cat := &Catalog{Source: src, Info: info}
	groups := map[string]*parsers.Group{}
	var groupOrder []string
	mi := 0 // index into res.Items (one item per processed data row)
	for _, item := range res.Items {
		var meta NodeMeta
		if mi < len(metas) {
			meta = metas[mi]
		}
		mi++
		if item.Node == nil {
			cat.RowErrors++
			continue
		}
		node := item.Node
		// Volunteer labelling (book 7.3) and country grouping.
		if !hasTag(node.Tags, "volunteer") {
			node.Tags = append(node.Tags, "volunteer")
		}
		groupName := meta.CountryLong
		if groupName == "" {
			groupName = "Unknown region"
		}
		node.Group = groupName
		g, ok := groups[groupName]
		if !ok {
			gid := deterministicUUID("group|vpngate|" + groupName)
			g = &parsers.Group{
				SchemaVersion: "1.0",
				ID:            gid,
				Name:          groupName,
				SourceID:      &src.ID,
				Description:   "VPN Gate volunteer relays in " + groupName + " (grouped by list country/region)",
			}
			groups[groupName] = g
			groupOrder = append(groupOrder, groupName)
		}
		g.NodeIDs = append(g.NodeIDs, node.ID)
		cat.Nodes = append(cat.Nodes, node)
		cat.Meta = append(cat.Meta, meta)
	}
	sort.Strings(groupOrder)
	for _, name := range groupOrder {
		cat.Groups = append(cat.Groups, *groups[name])
	}
	if len(cat.Nodes) == 0 {
		return nil, fmt.Errorf("%w: parses to zero usable nodes", ErrInvalidPayload)
	}
	return cat, nil
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// scanRowMeta is a metadata-only pass over the CSV: it reads
// the list columns (country, score, operator, log type, ...)
// in exactly the row sequence the Step 8 parser consumes for
// node construction, so Meta[i] lines up with Items[i]. Node
// construction itself is never duplicated here.
func scanRowMeta(content string) []NodeMeta {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil
	}
	col := map[string]int{}
	hdrIdx := -1
	for i, rec := range records {
		for j, c := range rec {
			// The real header's first column is "#HostName".
			col[strings.TrimPrefix(strings.TrimSpace(c), "#")] = j
		}
		if _, ok := col["OpenVPN_ConfigData_Base64"]; ok {
			hdrIdx = i
			break
		}
		col = map[string]int{}
	}
	if hdrIdx < 0 {
		return nil
	}
	get := func(rec []string, name string) string {
		j, ok := col[name]
		if !ok || j >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[j])
	}
	cfgCol := col["OpenVPN_ConfigData_Base64"]
	var out []NodeMeta
	for i, rec := range records {
		if i <= hdrIdx {
			continue
		}
		if cfgCol >= len(rec) || strings.TrimSpace(rec[cfgCol]) == "" {
			continue // same skip rule as the Step 8 parser
		}
		if len(out) >= 500 { // parser's row cap
			break
		}
		atoi := func(name string) int64 {
			v, _ := strconv.ParseInt(get(rec, name), 10, 64)
			return v
		}
		out = append(out, NodeMeta{
			HostName:         get(rec, "HostName"),
			IP:               get(rec, "IP"),
			CountryShort:     get(rec, "CountryShort"),
			CountryLong:      get(rec, "CountryLong"),
			Operator:         get(rec, "Operator"),
			Message:          get(rec, "Message"),
			LogType:          get(rec, "LogType"),
			Volunteer:        true,
			ScoreReported:    atoi("Score"),
			PingMsReported:   atoi("Ping"),
			SpeedBpsReported: atoi("Speed"),
			SessionsReported: atoi("NumVpnSessions"),
		})
	}
	return out
}

// deterministicUUID derives a stable RFC 4122 version-5-shaped
// UUID from a seed string (same presentation shape the Step 8
// parser uses for its registrations, independently computed).
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
