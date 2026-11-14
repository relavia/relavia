package ui

// Glyph-coverage gate (KI-21): every character the UI can show
// must have a real glyph in the registered font collection —
// a missing glyph is a tofu box on a user's screen, and before
// this gate existed exactly that shipped to Android because the
// collection silently depended on OS font directories.
//
// Character sources:
//   - every string value in the three shipped locale packs
//     (zh-Hans / zh-Hant / en) — the whole UI copy surface;
//   - non-ASCII literals hard-coded in the UI code (separators
//     and status symbols drawn as text);
//   - representative user-content samples: node names are
//     arbitrary text from subscriptions and the public pool, so
//     the samples span Simplified / Traditional / Japanese /
//     Korean names plus rare CJK characters and the project
//     slogan. A font subsetted to the UI's own strings would
//     fail here, by design.
//
// The check is done through opentype NominalGlyph (the cmap
// lookup) on the very faces FontCollection registers, so it
// cannot be satisfied by a font that merely exists on the
// machine running the test.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"gioui.org/font"
	"gioui.org/font/opentype"
	"gioui.org/text"
	"golang.org/x/image/math/fixed"

	"openproxy/app/locales"
)

var coverageSamples = []string{
	// Project slogan.
	"希望所有人都可以看见不一样的世界",
	// Node names as they arrive from subscriptions / the pool.
	"东京樱花节点 · 高速专线",
	"臺北101 · 臺灣高速節點",
	"渋谷スクエア接続テスト",
	"서울 한강 프리미엄 노드",
	"香港國際機場 · 繁體中文",
	// Rare / extension characters a user can put in a name.
	"生僻字：龘喆燚淼犇骉鑫贔",
	// Non-ASCII literals hard-coded in UI code (views.go).
	"·—…↑↓⚠✓",
}

func coverageRunes(t *testing.T) map[rune]bool {
	t.Helper()
	set := map[rune]bool{}
	add := func(s string) {
		for _, r := range s {
			if r < 0x20 || (r >= 0x7f && r < 0xa0) {
				continue // layout controls, never shaped as text
			}
			set[r] = true
		}
	}
	for _, lang := range locales.Supported {
		data, err := locales.FS.ReadFile(lang + "/messages.json")
		if err != nil {
			t.Fatalf("read %s pack: %v", lang, err)
		}
		var pack map[string]string
		if err := json.Unmarshal(data, &pack); err != nil {
			t.Fatalf("parse %s pack: %v", lang, err)
		}
		for k, v := range pack {
			add(k)
			add(v)
		}
	}
	for _, s := range coverageSamples {
		add(s)
	}
	return set
}

func glyphLookup(faces []font.FontFace, r rune) bool {
	for _, ff := range faces {
		of, ok := ff.Face.(opentype.Face)
		if !ok {
			continue
		}
		if _, ok := of.Face().NominalGlyph(r); ok {
			return true
		}
	}
	return false
}

func TestBundledCJKFacesRegistered(t *testing.T) {
	faces := BundledCJK()
	if len(faces) != 10 {
		t.Fatalf("bundled CJK faces = %d, want 10 (5 regions x 2 weights)", len(faces))
	}
	// Order is pinned: by region (SC, TC, HK, JP, KR), then by
	// weight (Normal before Bold) — see fonts.go.
	wantRegions := []string{"SC", "TC", "HK", "JP", "KR"}
	wantWeights := []font.Weight{font.Normal, font.Bold}
	for i, region := range wantRegions {
		for j, weight := range wantWeights {
			f := faces[i*2+j].Font
			if got := string(f.Typeface); got != "Noto Sans CJK "+region {
				t.Errorf("face[%d] typeface = %q, want %q", i*2+j, got, "Noto Sans CJK "+region)
			}
			if f.Weight != weight {
				t.Errorf("face[%d] weight = %v, want %v", i*2+j, f.Weight, weight)
			}
		}
	}
	weights := map[font.Weight]int{}
	for _, ff := range faces {
		weights[ff.Font.Weight]++
	}
	if weights[font.Normal] != 5 || weights[font.Bold] != 5 {
		t.Errorf("bundled weights = %v, want 5 Normal + 5 Bold", weights)
	}
}

func TestGlyphCoverage(t *testing.T) {
	runes := coverageRunes(t)
	collection := FontCollection()
	var missing []rune
	for r := range runes {
		if !glyphLookup(collection, r) {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		var b strings.Builder
		for _, r := range missing {
			fmt.Fprintf(&b, "%c (U+%04X) ", r, r)
		}
		t.Fatalf("%d of %d characters have NO glyph in the registered font collection (tofu on device): %s",
			len(missing), len(runes), b.String())
	}
	t.Logf("coverage: %d distinct characters, all with glyphs", len(runes))
}

// The production shaper (ui.NewShaper: NoSystemFonts + the
// registered collection, nothing else) must shape the shipped
// languages' text end to end — one glyph per shaped cluster
// run, no empty output. This exercises the exact construction
// all three entry points use.
func TestProductionShaperShapesCJK(t *testing.T) {
	shaper := NewShaper()
	for _, s := range []string{
		"一键连接免费节点",
		"繁體中文節點列表",
		"日本語ノード・テスト",
		"한국어 노드 목록",
		"Connect to a free node",
	} {
		shaper.LayoutString(text.Parameters{
			Font:    font.Font{Typeface: "", Style: font.Regular, Weight: font.Normal},
			PxPerEm: fixed.I(16),
		}, s)
		n, runes := 0, 0
		for {
			g, ok := shaper.NextGlyph()
			if !ok {
				break
			}
			n++
			runes += int(g.Runes)
		}
		if n == 0 {
			t.Errorf("shaped %q: zero glyphs", s)
		}
		if want := len([]rune(s)); runes != want {
			t.Errorf("shaped %q: glyphs account for %d runes, want %d", s, runes, want)
		}
	}
}

// CJK-family characters must be covered by the BUNDLED faces
// alone — coverage that only exists via the Go fonts or via an
// OS font on the test machine would not exist on a phone.
func TestGlyphCoverageBundledOnly(t *testing.T) {
	bundled := BundledCJK()
	var checked, missing []rune
	for _, s := range coverageSamples {
		for _, r := range s {
			if r < 0x2e80 { // CJK radicals and everything beyond
				continue
			}
			checked = append(checked, r)
			if !glyphLookup(bundled, r) {
				missing = append(missing, r)
			}
		}
	}
	if len(missing) > 0 {
		t.Fatalf("bundled CJK faces lack glyphs for: %q", string(missing))
	}
	t.Logf("bundled-only coverage: %d CJK sample characters, all with glyphs", len(checked))
}
