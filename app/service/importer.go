package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"openproxy/core/parsers"
	"openproxy/core/specnode"
)

// ImportReport summarizes one import operation for the UI. Failed
// items keep the parser's stable error code so the UI can count
// and log them without parsing message strings.
type ImportReport struct {
	Added  []string // node IDs added (or refreshed)
	Failed []ImportFailure
}

// ImportFailure is one rejected item.
type ImportFailure struct {
	Index  int
	Code   string
	Detail string
}

// OK returns how many nodes were imported.
func (r *ImportReport) OK() int { return len(r.Added) }

// toSpecNode converts a parser node (schema-shaped, credential as
// raw JSON) into the unified-model Go type via a JSON round trip.
// Both types mirror the same frozen schema, so the conversion is
// lossless; a malformed node fails here instead of reaching the
// store.
func toSpecNode(pn *parsers.Node) (*specnode.Node, error) {
	data, err := json.Marshal(pn)
	if err != nil {
		return nil, err
	}
	var n specnode.Node
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, err
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

// ingest folds a parser BatchResult into the store.
func (s *Service) ingest(res *parsers.BatchResult) *ImportReport {
	rep := &ImportReport{}
	if res == nil {
		return rep
	}
	for _, item := range res.Items {
		if item.Err != nil {
			rep.Failed = append(rep.Failed, ImportFailure{
				Index: item.Index, Code: item.Err.Code, Detail: item.Err.Detail,
			})
			continue
		}
		if item.Node == nil {
			continue
		}
		n, err := toSpecNode(item.Node)
		if err != nil {
			rep.Failed = append(rep.Failed, ImportFailure{
				Index: item.Index, Code: "model-conversion", Detail: err.Error(),
			})
			continue
		}
		var codes []string
		for _, w := range item.Warnings {
			codes = append(codes, w.Code)
		}
		s.store.AddNode(n, codes)
		if n.Group != "" {
			s.store.AddGroup(n.Group)
		}
		rep.Added = append(rep.Added, n.ID)
	}
	return rep
}

// ingestLink folds a single-link parse result into the store.
func (s *Service) ingestLink(res parsers.LinkResult) *ImportReport {
	batch := &parsers.BatchResult{}
	item := parsers.ItemResult{Index: 0, Node: res.Node, Warnings: res.Warnings, Err: res.Err}
	batch.Items = append(batch.Items, item)
	return s.ingest(batch)
}

// ImportText imports pasted content: a single share link, a list
// of links, or a whole subscription body (base64 / Clash YAML /
// sing-box JSON). The Step 8 parsers identify the format.
func (s *Service) ImportText(text string) *ImportReport {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return &ImportReport{Failed: []ImportFailure{{Code: parsers.ErrEmptyInput, Detail: "empty input"}}}
	}
	// A single line containing a scheme is a single link;
	// everything else goes through the subscription dispatcher,
	// which itself handles plain link lists. (An http(s) URL the
	// user means as a subscription address goes through
	// ImportSubscriptionURL instead — the UI keeps the two intents
	// on separate buttons.)
	if !strings.Contains(trimmed, "\n") && strings.Contains(trimmed, "://") {
		return s.finishImport(s.ingestLink(parsers.ParseLink(trimmed, parsers.Options{})))
	}
	res := parsers.ParseSubscription([]byte(trimmed), parsers.SubscriptionOptions{})
	return s.finishImport(s.ingest(res))
}

// ImportFile imports a local file's content. The format is chosen
// by extension, then by content sniffing (.conf may be WireGuard
// or a subscription body).
func (s *Service) ImportFile(name string, content []byte) *ImportReport {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".ovpn"):
		return s.finishImport(s.ingestLink(parsers.ParseOpenVPNConf(string(content), parsers.Options{Name: baseName(name)})))
	case strings.HasSuffix(lower, ".conf") && strings.Contains(string(content), "[Interface]"):
		return s.finishImport(s.ingest(parsers.ParseWireGuardConf(string(content), parsers.Options{Name: baseName(name)})))
	default:
		return s.finishImport(s.ingest(parsers.ParseSubscription(content, parsers.SubscriptionOptions{})))
	}
}

// ImportSubscriptionURL fetches a subscription over HTTP(S) and
// imports it, recording the subscription registration. The fetch
// is a plain GET with a bounded body; anything else (auth,
// proxies for the fetch itself) is out of this step's scope.
func (s *Service) ImportSubscriptionURL(ctx context.Context, rawURL, name string) (*ImportReport, error) {
	if s.httpClient == nil {
		return nil, fmt.Errorf("service: no HTTP client configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Relavia/0.1 (+https://github.com/relavia/relavia)")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("service: subscription fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	res := parsers.ParseSubscription(body, parsers.SubscriptionOptions{URL: rawURL, Name: name})
	rep := s.ingest(res)
	if res.Subscription != nil {
		s.store.UpsertSubscription(SubscriptionRecord{
			ID:            res.Subscription.ID,
			Name:          res.Subscription.Name,
			URL:           rawURL,
			Format:        res.Subscription.Format,
			GroupName:     res.Subscription.GroupName,
			LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	return s.finishImport(rep), nil
}

// finishImport persists and logs the outcome.
func (s *Service) finishImport(rep *ImportReport) *ImportReport {
	_ = s.store.Save()
	s.logf("import: %d ok, %d failed", rep.OK(), len(rep.Failed))
	for _, f := range rep.Failed {
		s.logf("import: item %d rejected [%s] %s", f.Index, f.Code, f.Detail)
	}
	return rep
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
