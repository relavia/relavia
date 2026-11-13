package ui

// WCAG AA contrast audit for the four background tiers (v3).
// Method follows the Step 18 baseline: relative luminance per
// WCAG 2.x, ratio (L1+0.05)/(L2+0.05), every text/background
// pair the UI actually composes must reach 4.5:1. Inactive
// (disabled) controls are exempt per WCAG and are not in the
// table; the Disabled token renders only unavailable options
// whose reason is ALSO carried by the Warn line next to them.

import (
	"image/color"
	"math"
	"testing"
)

func relLuminance(c color.NRGBA) float64 {
	lin := func(v uint8) float64 {
		s := float64(v) / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.R) + 0.7152*lin(c.G) + 0.0722*lin(c.B)
}

func contrastRatio(a, b color.NRGBA) float64 {
	la, lb := relLuminance(a), relLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestPaletteContrastAA(t *testing.T) {
	palettes := map[string]Palette{
		"light": paletteLight,
		"navy":  paletteNavy,
		"ink":   paletteInk,
	}
	type pair struct {
		name string
		fg   func(Palette) color.NRGBA
		bg   func(Palette) color.NRGBA
	}
	pairs := []pair{
		{"Text/Bg", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.Bg }},
		{"Text/Card", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.Card }},
		{"Text/PrimaryLite", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.PrimaryLite }},
		{"Text/InputBg", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.InputBg }},
		{"Text/SuccessBg", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.SuccessBg }},
		{"Text/WarnBg", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.WarnBg }},
		{"Text/DangerBg", func(p Palette) color.NRGBA { return p.Text }, func(p Palette) color.NRGBA { return p.DangerBg }},
		{"Secondary/Bg", func(p Palette) color.NRGBA { return p.Secondary }, func(p Palette) color.NRGBA { return p.Bg }},
		{"Secondary/Card", func(p Palette) color.NRGBA { return p.Secondary }, func(p Palette) color.NRGBA { return p.Card }},
		{"Secondary/PrimaryLite", func(p Palette) color.NRGBA { return p.Secondary }, func(p Palette) color.NRGBA { return p.PrimaryLite }},
		{"Secondary/InputBg", func(p Palette) color.NRGBA { return p.Secondary }, func(p Palette) color.NRGBA { return p.InputBg }},
		{"Secondary/PillIdle", func(p Palette) color.NRGBA { return p.Secondary }, func(p Palette) color.NRGBA { return p.PillIdle }},
		{"Hint/Bg", func(p Palette) color.NRGBA { return p.Hint }, func(p Palette) color.NRGBA { return p.Bg }},
		{"Hint/Card", func(p Palette) color.NRGBA { return p.Hint }, func(p Palette) color.NRGBA { return p.Card }},
		{"Hint/InputBg", func(p Palette) color.NRGBA { return p.Hint }, func(p Palette) color.NRGBA { return p.InputBg }},
		{"PrimaryText/PrimaryLite", func(p Palette) color.NRGBA { return p.PrimaryText }, func(p Palette) color.NRGBA { return p.PrimaryLite }},
		{"Success/SuccessBg", func(p Palette) color.NRGBA { return p.Success }, func(p Palette) color.NRGBA { return p.SuccessBg }},
		{"Success/Card", func(p Palette) color.NRGBA { return p.Success }, func(p Palette) color.NRGBA { return p.Card }},
		{"Success/Bg", func(p Palette) color.NRGBA { return p.Success }, func(p Palette) color.NRGBA { return p.Bg }},
		{"Warn/WarnBg", func(p Palette) color.NRGBA { return p.Warn }, func(p Palette) color.NRGBA { return p.WarnBg }},
		{"Warn/Card", func(p Palette) color.NRGBA { return p.Warn }, func(p Palette) color.NRGBA { return p.Card }},
		{"Warn/Bg", func(p Palette) color.NRGBA { return p.Warn }, func(p Palette) color.NRGBA { return p.Bg }},
		{"Danger/DangerBg", func(p Palette) color.NRGBA { return p.Danger }, func(p Palette) color.NRGBA { return p.DangerBg }},
		{"Danger/Card", func(p Palette) color.NRGBA { return p.Danger }, func(p Palette) color.NRGBA { return p.Card }},
		{"Danger/Bg", func(p Palette) color.NRGBA { return p.Danger }, func(p Palette) color.NRGBA { return p.Bg }},
		{"White/Primary", func(p Palette) color.NRGBA { return p.White }, func(p Palette) color.NRGBA { return p.Primary }},
		{"White/DangerFill", func(p Palette) color.NRGBA { return p.White }, func(p Palette) color.NRGBA { return p.DangerFill }},
	}
	for name, p := range palettes {
		for _, pr := range pairs {
			r := contrastRatio(pr.fg(p), pr.bg(p))
			t.Logf("%s %s = %.2f", name, pr.name, r)
			if r < 4.5 {
				t.Errorf("%s: %s contrast %.2f < 4.5 (WCAG AA)", name, pr.name, r)
			}
		}
	}
}
