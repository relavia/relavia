package i18n_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"openproxy/app/i18n"
	"openproxy/app/locales"
)

// The shipped packs must be perfectly aligned: this is the
// automated half of the book-14 Step 9 multilingual acceptance
// (key-set consistency + no empty values). The third leg — the
// hardcoded-string scan — lives in tools/i18ncheck and runs in CI.
func TestShippedPacksAligned(t *testing.T) {
	reports, err := i18n.CheckPacks(locales.FS, locales.Supported, locales.Source)
	if err != nil {
		t.Fatalf("CheckPacks: %v", err)
	}
	if len(reports) != len(locales.Supported) {
		t.Fatalf("reports = %d, want %d", len(reports), len(locales.Supported))
	}
	var sourceKeys int
	for _, rep := range reports {
		if rep.Lang == locales.Source {
			sourceKeys = rep.Keys
		}
		if !rep.OK() {
			t.Errorf("pack %s: missing=%v extra=%v empty=%v",
				rep.Lang, rep.MissingKeys, rep.ExtraKeys, rep.EmptyKeys)
		}
	}
	if sourceKeys == 0 {
		t.Fatal("source pack is empty")
	}
	for _, rep := range reports {
		if rep.Keys != sourceKeys {
			t.Errorf("pack %s has %d keys, source has %d", rep.Lang, rep.Keys, sourceKeys)
		}
	}
}

func TestRuntimeSwitchAndFallback(t *testing.T) {
	fsys := fstest.MapFS{
		"en/messages.json":      {Data: []byte(`{"hello":"Hello {name}","only_en":"Only EN"}`)},
		"zh-Hans/messages.json": {Data: []byte(`{"hello":"你好 {name}"}`)},
	}
	tr, err := i18n.New(fsys, []string{"en", "zh-Hans"}, "zh-Hans", "en")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tr.T("hello", map[string]string{"name": "世界"}); got != "你好 世界" {
		t.Errorf("T(hello) = %q", got)
	}
	// Missing in active -> English fallback.
	if got := tr.T("only_en", nil); got != "Only EN" {
		t.Errorf("fallback T(only_en) = %q", got)
	}
	// Missing everywhere -> the key itself (diagnosable bug).
	if got := tr.T("no.such.key", nil); got != "no.such.key" {
		t.Errorf("missing key should surface as itself, got %q", got)
	}
	// Runtime switch without restart.
	if err := tr.SetLang("en"); err != nil {
		t.Fatalf("SetLang: %v", err)
	}
	if got := tr.T("hello", map[string]string{"name": "world"}); got != "Hello world" {
		t.Errorf("after switch T(hello) = %q", got)
	}
	if err := tr.SetLang("fr"); err == nil {
		t.Error("SetLang(fr) should fail for an unloaded language")
	}
	if tr.Lang() != "en" {
		t.Errorf("active language changed after failed switch: %q", tr.Lang())
	}
}

func TestDirectionReservation(t *testing.T) {
	if i18n.DirectionOf("zh-Hans") != i18n.LTR || i18n.DirectionOf("en") != i18n.LTR {
		t.Error("shipped languages must be LTR")
	}
	for _, lang := range []string{"ar", "ar-EG", "fa", "he"} {
		if i18n.DirectionOf(lang) != i18n.RTL {
			t.Errorf("DirectionOf(%q) should be RTL (architecture reservation)", lang)
		}
	}
}

// Risk-disclosure strings must exist in every shipped pack; they
// are the strings the book forbids from shipping machine
// translated, so their presence is asserted explicitly.
func TestRiskStringsPresentEverywhere(t *testing.T) {
	for _, lang := range locales.Supported {
		p, err := i18n.LoadPack(locales.FS, lang)
		if err != nil {
			t.Fatalf("LoadPack(%s): %v", lang, err)
		}
		for _, key := range []string{"risk.weak_encryption", "risk.insecure_skip_verify", "risk.node_trust"} {
			v := p.Messages[key]
			if strings.TrimSpace(v) == "" {
				t.Errorf("pack %s: risk string %q missing/empty", lang, key)
			}
			if len([]rune(v)) < 30 {
				t.Errorf("pack %s: risk string %q looks truncated (%q)", lang, key, v)
			}
		}
	}
}
