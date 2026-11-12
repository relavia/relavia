// Package i18n is the client's runtime localization engine
// (proposal book 3.6 / 8.1: multilingual-native).
//
// Design rules enforced here:
//   - All user-visible strings come from language packs; UI code
//     never hardcodes display text (checked by tools/i18ncheck).
//   - Language can be switched at runtime without restart: the
//     Translator swaps its active pack atomically and every view
//     re-renders with the new strings on its next frame.
//   - Fallback chain: active language -> English -> the key itself
//     (a visible key is a bug, but a diagnosable one).
//   - Layout direction is NOT hardcoded anywhere in the UI; this
//     package reports the writing direction of a language
//     (Direction) so the future RTL packs can flip layouts without
//     restructuring views (RTL is an architecture reservation in
//     this step; no RTL pack ships yet).
package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

// Direction is the writing direction a layout must use.
type Direction int

const (
	LTR Direction = iota
	RTL
)

// rtlLanguages are the base languages whose packs will need RTL
// layout when the community translations land (book 8.1 candidate
// list). No pack for them ships in this step.
var rtlLanguages = map[string]bool{
	"ar": true, "fa": true, "he": true, "ur": true,
}

// DirectionOf reports the writing direction for a language tag.
func DirectionOf(lang string) Direction {
	base := strings.SplitN(lang, "-", 2)[0]
	if rtlLanguages[strings.ToLower(base)] {
		return RTL
	}
	return LTR
}

// Pack is one parsed language pack.
type Pack struct {
	Lang     string
	Messages map[string]string
}

// LoadPack reads and parses <lang>/messages.json from fsys.
func LoadPack(fsys fs.FS, lang string) (*Pack, error) {
	data, err := fs.ReadFile(fsys, lang+"/messages.json")
	if err != nil {
		return nil, fmt.Errorf("i18n: read pack %s: %w", lang, err)
	}
	msgs := map[string]string{}
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil, fmt.Errorf("i18n: parse pack %s: %w", lang, err)
	}
	return &Pack{Lang: lang, Messages: msgs}, nil
}

// Translator resolves keys against the active pack with English
// fallback. Safe for concurrent use; SetLang is atomic so a view
// never observes a half-swapped pack.
type Translator struct {
	mu       sync.RWMutex
	packs    map[string]*Pack
	active   string
	fallback string
}

// New loads the given packs from fsys and activates initial.
func New(fsys fs.FS, langs []string, initial, fallback string) (*Translator, error) {
	t := &Translator{packs: map[string]*Pack{}, fallback: fallback}
	for _, lang := range langs {
		p, err := LoadPack(fsys, lang)
		if err != nil {
			return nil, err
		}
		t.packs[lang] = p
	}
	if _, ok := t.packs[initial]; !ok {
		return nil, fmt.Errorf("i18n: initial language %q not loaded", initial)
	}
	if _, ok := t.packs[fallback]; !ok {
		return nil, fmt.Errorf("i18n: fallback language %q not loaded", fallback)
	}
	t.active = initial
	return t, nil
}

// Lang returns the active language tag.
func (t *Translator) Lang() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

// SetLang switches the active language at runtime. Unknown
// languages are refused and the active language is left unchanged.
func (t *Translator) SetLang(lang string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.packs[lang]; !ok {
		return fmt.Errorf("i18n: language %q not loaded", lang)
	}
	t.active = lang
	return nil
}

// Languages returns the loaded language tags, sorted.
func (t *Translator) Languages() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.packs))
	for lang := range t.packs {
		out = append(out, lang)
	}
	sort.Strings(out)
	return out
}

// Direction returns the writing direction of the active language.
func (t *Translator) Direction() Direction { return DirectionOf(t.Lang()) }

// T resolves a key. Placeholders of the form {name} are replaced
// from args (name -> value pairs passed as a map); unresolved
// placeholders are left in place so missing arguments are visible.
func (t *Translator) T(key string, args map[string]string) string {
	t.mu.RLock()
	active, fallback := t.active, t.fallback
	packs := t.packs
	t.mu.RUnlock()

	s, ok := lookup(packs, active, key)
	if !ok {
		s, ok = lookup(packs, fallback, key)
	}
	if !ok {
		return key
	}
	for name, val := range args {
		s = strings.ReplaceAll(s, "{"+name+"}", val)
	}
	return s
}

func lookup(packs map[string]*Pack, lang, key string) (string, bool) {
	p, ok := packs[lang]
	if !ok {
		return "", false
	}
	s, ok := p.Messages[key]
	return s, ok
}

// ----------------------------------------------------------------
// Pack integrity checking (shared by tests and tools/i18ncheck)
// ----------------------------------------------------------------

// PackReport describes one pack's integrity against the source.
type PackReport struct {
	Lang         string
	Keys         int
	MissingKeys  []string // in source but absent here
	ExtraKeys    []string // here but absent in source
	EmptyKeys    []string // present but empty/whitespace
	DuplicateRaw []string // duplicated keys in the raw JSON (best effort)
}

// CheckPacks loads every pack in langs from fsys and compares key
// sets and values against the source language pack.
func CheckPacks(fsys fs.FS, langs []string, source string) ([]PackReport, error) {
	src, err := LoadPack(fsys, source)
	if err != nil {
		return nil, err
	}
	reports := make([]PackReport, 0, len(langs))
	for _, lang := range langs {
		p, err := LoadPack(fsys, lang)
		if err != nil {
			return nil, err
		}
		rep := PackReport{Lang: lang, Keys: len(p.Messages)}
		for k := range src.Messages {
			v, ok := p.Messages[k]
			if !ok {
				rep.MissingKeys = append(rep.MissingKeys, k)
			} else if strings.TrimSpace(v) == "" {
				rep.EmptyKeys = append(rep.EmptyKeys, k)
			}
		}
		for k := range p.Messages {
			if _, ok := src.Messages[k]; !ok {
				rep.ExtraKeys = append(rep.ExtraKeys, k)
			}
		}
		sort.Strings(rep.MissingKeys)
		sort.Strings(rep.ExtraKeys)
		sort.Strings(rep.EmptyKeys)
		reports = append(reports, rep)
	}
	return reports, nil
}

// OK reports whether the pack is complete and clean.
func (r PackReport) OK() bool {
	return len(r.MissingKeys) == 0 && len(r.ExtraKeys) == 0 && len(r.EmptyKeys) == 0
}
