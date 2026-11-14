package ui

import (
	_ "embed"
	"sort"
	"strings"
	"sync"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/text"
)

// Font strategy: the Go fonts Gio ships have no CJK glyphs, and
// a shaper is only as good as the collection registered with it.
// Until 2026-11-14 the registered collection came from two
// uncontrolled sources, and on Android both failed at once
// (real-device finding, KI-21 — every Chinese character a tofu
// box): (1) this package tried to load a CJK font from OS font
// directories via a path table naming only Windows / macOS /
// desktop-Linux locations — Android fell into the desktop-Linux
// branch, none of whose paths exist on a phone; (2) Gio's
// shaper by default also scans the OS's system fonts (go-text
// fontscan) — on the desktop check machines that scan found a
// locally installed Noto Sans CJK and quietly masked defect
// (1) in every frame check, while on the user's phone it
// rescued nothing. Source (2) is now disabled at every shaper
// construction site (see NewShaper), and source (1) is gone.
//
// The client therefore BUNDLES its CJK font and registers the
// exact same collection on every platform: the Go fonts first
// (Latin), then the bundled Noto Sans CJK faces (Regular + Bold).
// Nothing is read from OS font directories any more, so rendering
// cannot silently depend on what a machine happens to have
// installed. Glyph coverage of everything the UI can show is
// pinned by fonts_coverage_test.go.
//
// The bundled files are the upstream pan-CJK collections
// (app/ui/fontdata/, SIL OFL 1.1 — see THIRD_PARTY_NOTICES.md and
// docs/licenses/OFL-1.1.txt): each .ttc carries JP / KR / SC /
// TC / HK faces plus Mono variants. The Mono faces are not
// registered (the UI has no monospace CJK surface; log text falls
// back to the proportional faces). The proportional faces are
// ordered SC, TC, HK, JP, KR so code points whose glyph differs
// by region render in the form closest to the product's shipped
// languages (zh-Hans source, zh-Hant second); every face covers
// the full CJK range, so the order only picks regional variants,
// never availability.
//
// Size: the two files add 39,535,544 bytes (Regular 19,484,784 +
// Bold 20,050,760) to every binary that embeds the UI — the
// Android APK grows by the same amount once (the bytes live in
// the Go binary, not per-ABI). Full coverage is deliberate: node
// names and subscription content are arbitrary user text, so
// subsetting to the UI's own strings would re-break on the first
// unusual node name. Any future diet must keep the coverage test
// green.

//go:embed fontdata/NotoSansCJK-Regular.ttc
var notoCJKRegularTTC []byte

//go:embed fontdata/NotoSansCJK-Bold.ttc
var notoCJKBoldTTC []byte

var (
	cjkFacesOnce sync.Once
	cjkFaces     []font.FontFace
)

// regionRank orders the pan-CJK faces of one weight: Simplified
// first (the product's source language), then Traditional and
// Hong Kong, then Japanese and Korean as full-range fallbacks.
var regionRank = map[string]int{
	"Noto Sans CJK SC": 0,
	"Noto Sans CJK TC": 1,
	"Noto Sans CJK HK": 2,
	"Noto Sans CJK JP": 3,
	"Noto Sans CJK KR": 4,
}

// bundledCJKFaces parses the embedded Noto Sans CJK collections
// once and returns the proportional faces sorted by region rank,
// then by weight (Normal before Bold within a region).
func bundledCJKFaces() []font.FontFace {
	cjkFacesOnce.Do(func() {
		var faces []font.FontFace
		for _, data := range [][]byte{notoCJKRegularTTC, notoCJKBoldTTC} {
			parsed, err := opentype.ParseCollection(data)
			if err != nil {
				continue
			}
			faces = append(faces, parsed...)
		}
		kept := faces[:0]
		for _, f := range faces {
			if _, ok := regionRank[string(f.Font.Typeface)]; ok {
				kept = append(kept, f)
			}
		}
		sort.SliceStable(kept, func(i, j int) bool {
			ri, rj := regionRank[string(kept[i].Font.Typeface)], regionRank[string(kept[j].Font.Typeface)]
			if ri != rj {
				return ri < rj
			}
			return kept[i].Font.Weight < kept[j].Font.Weight
		})
		cjkFaces = kept
	})
	return cjkFaces
}

// FontCollection returns the one font collection every platform
// registers with the text shaper: Go fonts (Latin) followed by
// the bundled Noto Sans CJK faces. It reads no OS paths.
func FontCollection() []font.FontFace {
	faces := gofont.Collection()
	return append(faces, bundledCJKFaces()...)
}

// NewShaper builds the text shaper every entry point must use.
// The NoSystemFonts option is load-bearing, not decorative:
// Gio's default is to ALSO scan and register the OS's system
// fonts (go-text fontscan), which is a second, uncontrolled
// font source — on desktop machines it silently papered over
// this collection's missing CJK for years, and on the user's
// Android phone it did not, producing the KI-21 tofu. With it
// disabled, what renders is exactly FontCollection() on every
// platform, which is what the coverage gate in
// fonts_coverage_test.go verifies.
func NewShaper() *text.Shaper {
	return text.NewShaper(text.NoSystemFonts(), text.WithCollection(FontCollection()))
}

// BundledCJK reports the bundled CJK faces that made it into the
// collection (used for a startup log line and by tests).
func BundledCJK() []font.FontFace {
	return bundledCJKFaces()
}

// BundledCJKDescription is a one-line summary of the bundled CJK
// faces for the startup log, e.g. "SC/TC/HK/JP/KR Normal+Bold".
// Empty when parsing failed (which the coverage test would have
// caught long before release).
func BundledCJKDescription() string {
	faces := bundledCJKFaces()
	if len(faces) == 0 {
		return ""
	}
	seenRegion := map[string]bool{}
	seenWeight := map[string]bool{}
	var regions, weights []string
	for _, f := range faces {
		// Typeface is "Noto Sans CJK SC" etc.; region is the
		// last field.
		fields := strings.Fields(string(f.Font.Typeface))
		region := fields[len(fields)-1]
		if !seenRegion[region] {
			seenRegion[region] = true
			regions = append(regions, region)
		}
		weight := f.Font.Weight.String()
		if !seenWeight[weight] {
			seenWeight[weight] = true
			weights = append(weights, weight)
		}
	}
	return strings.Join(regions, "/") + " " + strings.Join(weights, "+")
}
