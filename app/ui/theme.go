package ui

// Visual layer for the product UI, implementing the approved
// mockups in docs/ui-mockups/ (user ruling 2026-11-14: design
// mockups first, implementation follows the approved images).
// All colors, radii and spacings come from the design tokens in
// docs/ui-mockups/README.md; the few derived neutrals (input
// fill, disabled text, warning tint, idle pill fill) are marked
// as such where defined. This file holds presentation only —
// every widget here forwards clicks to the same Clickables and
// service calls the plain material layout used.

import (
	"image"
	"image/color"
	"math"
	"time"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// Design tokens (docs/ui-mockups/README.md).
//
// v3: the tokens live in a Palette so the four user-selectable
// backgrounds (light / navy / ink / follow-system; user ruling
// 2026-11-14) switch as a complete set. `pal` is the active
// palette; the App re-resolves it from the persisted theme
// setting at the start of every frame (all rendering happens on
// the UI goroutine, so no synchronization is needed). Every
// text/surface pair in every palette is verified >= WCAG AA
// 4.5:1 by palette_test.go; the audit table is recorded in
// docs (android UI integration doc, v3 section).

// Palette is one complete background tier's token set.
//
// v4 ("Tongxin", docs/ui-mockups/README.md v4 chapter): the
// page background is a two-stop vertical gradient (BgTop ->
// Bg), cards carry a real shadow on the light tier (Shadow;
// zero alpha on the dark tiers, which separate by border
// instead), and the first-screen hero is a deep brand-blue
// gradient panel (HeroA -> HeroB at 57% -> HeroC) in every
// tier — the screen's single visual protagonist.
type Palette struct {
	Bg          color.NRGBA // page background gradient bottom
	BgTop       color.NRGBA // page background gradient top
	Card        color.NRGBA // card / sheet surface
	Border      color.NRGBA // hairlines, card edges
	Primary     color.NRGBA // filled primary actions
	PrimaryText color.NRGBA // accent text on Lite surfaces
	PrimaryLite color.NRGBA // tinted surface (selected, badges)
	Text        color.NRGBA // primary text
	Secondary   color.NRGBA // secondary text
	Hint        color.NRGBA // captions, placeholders (AA-verified)
	Success     color.NRGBA
	SuccessBg   color.NRGBA
	Warn        color.NRGBA
	WarnBg      color.NRGBA
	Danger      color.NRGBA
	DangerBg    color.NRGBA
	DangerFill  color.NRGBA // filled danger actions (dark tiers use a deep red, not the light text tint)
	White       color.NRGBA // text on filled Primary/Danger
	InputBg     color.NRGBA
	PillIdle    color.NRGBA
	Disabled    color.NRGBA // inactive controls (WCAG-exempt)
	Scrim       color.NRGBA // modal scrim over the page
	HeroA       color.NRGBA // hero gradient start (top)
	HeroB       color.NRGBA // hero gradient middle (57%)
	HeroC       color.NRGBA // hero gradient end (bottom)
	Shadow      color.NRGBA // card shadow (light tier only)
	HeroShadow  color.NRGBA // hero panel shadow (light tier only)
}

func nrgba(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }

// paletteLight is the original v2 light set. Four text colors
// were deepened from the v2 drawing values so every pair
// passes WCAG AA (Hint #949CA8 -> #6A7280, Warn #C97C12 ->
// #9A6206, Success #12966C -> #0B7050, Danger #D03C3C ->
// #BE3232); hues are unchanged, only luminance moved.
// v4 light tier (token table in docs/ui-mockups/README.md).
// Two micro-adjustments under the Step 18 method, same as the
// v3 deepening precedent: Warn text is one notch deeper
// (#8F5A05) so the table's #FBEED3 tint still clears AA
// (#9A6206 on #FBEED3 measures 4.43), Hint is #646C78 so it
// clears AA on the new gradient top #EDF0F7 (#6A7280 measures
// ~4.25 there), and the hero gradient's lightest stop is
// #4669E6 so white body text on the panel clears AA at every
// stop (#5279F2 measures ~3.9).
var paletteLight = Palette{
	Bg:          nrgba(0xF6, 0xF7, 0xF9),
	BgTop:       nrgba(0xED, 0xF0, 0xF7),
	Card:        nrgba(0xFF, 0xFF, 0xFF),
	Border:      nrgba(0xE3, 0xE7, 0xF0),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x23, 0x40, 0xB4),
	PrimaryLite: nrgba(0xE8, 0xEE, 0xFE),
	Text:        nrgba(0x1A, 0x1D, 0x21),
	Secondary:   nrgba(0x62, 0x6A, 0x78),
	Hint:        nrgba(0x64, 0x6C, 0x78),
	Success:     nrgba(0x0B, 0x70, 0x50),
	SuccessBg:   nrgba(0xDE, 0xF5, 0xEC),
	Warn:        nrgba(0x8F, 0x5A, 0x05),
	WarnBg:      nrgba(0xFB, 0xEE, 0xD3),
	Danger:      nrgba(0xBE, 0x32, 0x32),
	DangerBg:    nrgba(0xFC, 0xE9, 0xE9),
	DangerFill:  nrgba(0xBE, 0x32, 0x32),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0xF9, 0xFA, 0xFB),
	PillIdle:    nrgba(0xED, 0xEF, 0xF2),
	Disabled:    nrgba(0xB6, 0xBD, 0xC9),
	Scrim:       color.NRGBA{A: 0x66},
	HeroA:       nrgba(0x23, 0x2F, 0x6E),
	HeroB:       nrgba(0x2E, 0x54, 0xEB),
	HeroC:       nrgba(0x46, 0x69, 0xE6),
	Shadow:      color.NRGBA{R: 0x17, G: 0x20, B: 0x4D, A: 0x12},
	HeroShadow:  color.NRGBA{R: 0x23, G: 0x2F, B: 0x6E, A: 0x59},
}

// paletteNavy is the deep-blue tier sampled from the approved
// competitor reference (teardown notes): blue-black surfaces,
// never pure black, light-blue accent text on dark surfaces.
// v4 deep-blue tier (token table in docs/ui-mockups/README.md):
// blue-tinted surfaces, brighter semantic text on the table's
// dark tints, no shadows (the brighter border separates
// layers instead).
var paletteNavy = Palette{
	Bg:          nrgba(0x11, 0x15, 0x1D),
	BgTop:       nrgba(0x0C, 0x10, 0x17),
	Card:        nrgba(0x17, 0x1C, 0x26),
	Border:      nrgba(0x26, 0x2D, 0x3D),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x8F, 0xA9, 0xFF),
	PrimaryLite: nrgba(0x22, 0x33, 0x5F),
	Text:        nrgba(0xED, 0xF1, 0xF7),
	Secondary:   nrgba(0x9A, 0xA6, 0xBC),
	Hint:        nrgba(0x8E, 0x99, 0xAE),
	Success:     nrgba(0x4C, 0xC3, 0x8A),
	SuccessBg:   nrgba(0x12, 0x35, 0x28),
	Warn:        nrgba(0xE8, 0xB3, 0x4B),
	WarnBg:      nrgba(0x3A, 0x2C, 0x10),
	Danger:      nrgba(0xFF, 0x9D, 0x8A),
	DangerBg:    nrgba(0x3D, 0x1A, 0x1A),
	DangerFill:  nrgba(0xC2, 0x43, 0x43),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0x10, 0x14, 0x1D),
	PillIdle:    nrgba(0x1C, 0x23, 0x31),
	Disabled:    nrgba(0x5A, 0x65, 0x77),
	Scrim:       color.NRGBA{A: 0x99},
	HeroA:       nrgba(0x14, 0x1B, 0x45),
	HeroB:       nrgba(0x27, 0x43, 0xB8),
	HeroC:       nrgba(0x3D, 0x63, 0xD8),
}

// paletteInk is the v4 ink-black tier: pure-black page
// gradient, neutral grey surfaces, for OLED battery saving.
// Semantic tints match the deep-blue tier per the v4 token
// table.
var paletteInk = Palette{
	Bg:          nrgba(0x0A, 0x0A, 0x0A),
	BgTop:       nrgba(0x00, 0x00, 0x00),
	Card:        nrgba(0x14, 0x14, 0x14),
	Border:      nrgba(0x26, 0x26, 0x26),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x8F, 0xA9, 0xFF),
	PrimaryLite: nrgba(0x1D, 0x2A, 0x52),
	Text:        nrgba(0xF2, 0xF2, 0xF2),
	Secondary:   nrgba(0x9A, 0x9A, 0x9A),
	Hint:        nrgba(0x8F, 0x8F, 0x8F),
	Success:     nrgba(0x4C, 0xC3, 0x8A),
	SuccessBg:   nrgba(0x12, 0x35, 0x28),
	Warn:        nrgba(0xE8, 0xB3, 0x4B),
	WarnBg:      nrgba(0x3A, 0x2C, 0x10),
	Danger:      nrgba(0xFF, 0x9D, 0x8A),
	DangerBg:    nrgba(0x3D, 0x1A, 0x1A),
	DangerFill:  nrgba(0xC2, 0x43, 0x43),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0x0A, 0x0A, 0x0A),
	PillIdle:    nrgba(0x1C, 0x1C, 0x1C),
	Disabled:    nrgba(0x59, 0x59, 0x59),
	Scrim:       color.NRGBA{A: 0xB3},
	HeroA:       nrgba(0x10, 0x13, 0x2E),
	HeroB:       nrgba(0x22, 0x37, 0x9E),
	HeroC:       nrgba(0x33, 0x50, 0xC8),
}

// pal is the active palette (see the Palette comment). It
// starts at light - the pre-v3 default - and the App switches
// it per frame from the persisted setting.
var pal = paletteLight

const (
	dpMargin     = 16 // page content margin
	dpCardGap    = 10 // vertical gap between cards
	dpCardRad    = 20 // card corner radius (v4 token)
	dpBtnRad     = 12 // button corner radius (v4 token)
	dpBtnH       = 48 // standard action button height
	dpChipH      = 40 // group filter chip visual height (hit area 48)
	dpHeroH      = 56 // risk-sheet primary button height (v4 touch table)
	dpRowH       = 72 // two-line node row height (warning rows: 84)
	dpRadiusHero = 16 // risk-sheet button corner radius
	dpHeroRad    = 24 // v4 hero panel corner radius
	dpPanelBtnH  = 60 // v4 hero panel main button height
	dpTabBarH    = 64 // v4 bottom tab bar height (plus bottom safe inset)
	dpBadge      = 96 // v4 pupil status badge size
)

// lbl builds a label with explicit size, weight and color.
func (a *App) lbl(size unit.Sp, w font.Weight, c color.NRGBA, text string) material.LabelStyle {
	l := material.Label(a.th, size, text)
	l.Font.Weight = w
	l.Color = c
	return l
}

// lblMax is lbl with a line cap (and ellipsis truncation). Rows
// and the footer use it so a label can never wrap unboundedly
// and inflate its container — the failure mode behind the
// real-device layout defects of 2026-11-14 (width-starved text
// wrapping per-character and exploding row heights).
func (a *App) lblMax(size unit.Sp, w font.Weight, c color.NRGBA, text string, maxLines int) material.LabelStyle {
	l := a.lbl(size, w, c, text)
	l.MaxLines = maxLines
	l.Truncator = "…"
	return l
}

// lbl1 is a single-line truncating label (names, addresses,
// footer lines).
func (a *App) lbl1(size unit.Sp, w font.Weight, c color.NRGBA, text string) material.LabelStyle {
	return a.lblMax(size, w, c, text, 1)
}

// lblWrap is lblMax with an explicit line height (unit.Sp),
// for the multi-line description texts whose spacing the v3
// mockups fix (settings option groups, hero descriptions).
func (a *App) lblWrap(size, lineHeight unit.Sp, w font.Weight, c color.NRGBA, text string, maxLines int) material.LabelStyle {
	l := a.lblMax(size, w, c, text, maxLines)
	l.LineHeight = lineHeight
	return l
}

// fillTopRRect paints a filled rect rounded only at the top
// corners (bottom-sheet panels).
func fillTopRRect(gtx layout.Context, size image.Point, rad int, col color.NRGBA) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	r := gtx.Dp(unit.Dp(rad))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, size.X, size.Y),
		NE:   r, NW: r, SE: 0, SW: 0,
	}
	paint.FillShape(gtx.Ops, col, rr.Op(gtx.Ops))
}

// fillShape paints a filled rounded rect over the given size.
func fillRRect(gtx layout.Context, size image.Point, rad int, col color.NRGBA) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	r := gtx.Dp(unit.Dp(rad))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, size.X, size.Y),
		NE:   r, NW: r, SE: r, SW: r,
	}
	paint.FillShape(gtx.Ops, col, rr.Op(gtx.Ops))
}

// strokeRRect paints a 1dp rounded-rect outline over the size.
func strokeRRect(gtx layout.Context, size image.Point, rad int, col color.NRGBA) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	r := gtx.Dp(unit.Dp(rad))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, size.X, size.Y),
		NE:   r, NW: r, SE: r, SW: r,
	}
	path := rr.Path(gtx.Ops)
	paint.FillShape(gtx.Ops, col, clip.Stroke{Path: path, Width: float32(gtx.Dp(unit.Dp(1)))}.Op())
}

// shadowRRect paints a soft card shadow: Gio has no blur, so
// the shadow is a few rounded rects at growing offsets and
// shrinking alpha (v4 implementation note in the mockup
// README). The shadow color carries the total alpha; tiers
// with a zero-alpha shadow color (deep blue / ink) skip it.
func shadowRRect(gtx layout.Context, size image.Point, rad int, col color.NRGBA, dyDp int) {
	if col.A == 0 || size.X <= 0 || size.Y <= 0 {
		return
	}
	steps := 3
	for i := steps; i >= 1; i-- {
		c := col
		c.A = col.A / uint8(steps+1) * uint8(steps+1-i)
		if c.A == 0 {
			continue
		}
		off := gtx.Dp(unit.Dp(dyDp * i / steps))
		spread := gtx.Dp(unit.Dp(2 * i / steps))
		rect := image.Rect(-spread, off-spread, size.X+spread, size.Y+off+spread)
		r := gtx.Dp(unit.Dp(rad + 2*i/steps))
		rr := clip.RRect{Rect: rect, NE: r, NW: r, SE: r, SW: r}
		paint.FillShape(gtx.Ops, c, rr.Op(gtx.Ops))
	}
}

// fillVGradient paints a two-stop vertical gradient over the
// size (top -> bottom).
func fillVGradient(gtx layout.Context, size image.Point, top, bottom color.NRGBA) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	paint.LinearGradientOp{
		Stop1:  f32.Pt(0, 0),
		Color1: top,
		Stop2:  f32.Pt(0, float32(size.Y)),
		Color2: bottom,
	}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

// fillHeroGradient paints the v4 hero panel: the palette's
// three-stop deep-blue gradient (A -> B at 57% -> C), clipped
// to the panel's rounded outline.
func fillHeroGradient(gtx layout.Context, size image.Point, rad int) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	r := gtx.Dp(unit.Dp(rad))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, size.X, size.Y),
		NE:   r, NW: r, SE: r, SW: r,
	}
	defer rr.Push(gtx.Ops).Pop()
	mid := size.Y * 57 / 100
	// Top segment A -> B.
	func() {
		defer clip.Rect(image.Rect(0, 0, size.X, mid+1)).Push(gtx.Ops).Pop()
		paint.LinearGradientOp{
			Stop1:  f32.Pt(0, 0),
			Color1: pal.HeroA,
			Stop2:  f32.Pt(0, float32(mid)),
			Color2: pal.HeroB,
		}.Add(gtx.Ops)
		paint.PaintOp{}.Add(gtx.Ops)
	}()
	// Bottom segment B -> C.
	func() {
		defer clip.Rect(image.Rect(0, mid, size.X, size.Y)).Push(gtx.Ops).Pop()
		paint.LinearGradientOp{
			Stop1:  f32.Pt(0, float32(mid)),
			Color1: pal.HeroB,
			Stop2:  f32.Pt(0, float32(size.Y)),
			Color2: pal.HeroC,
		}.Add(gtx.Ops)
		paint.PaintOp{}.Add(gtx.Ops)
	}()
}

// buttonEdge paints the v4 filled-button treatment: a 2dp
// darker strip along the bottom edge, clipped to the button's
// rounded outline (the mockup README's implementation note
// replacing a drop shadow on filled buttons).
func buttonEdge(gtx layout.Context, size image.Point, rad int, bg color.NRGBA) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	darker := bg
	darker.R = uint8(uint16(bg.R) * 82 / 100)
	darker.G = uint8(uint16(bg.G) * 82 / 100)
	darker.B = uint8(uint16(bg.B) * 82 / 100)
	r := gtx.Dp(unit.Dp(rad))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, size.X, size.Y),
		NE:   r, NW: r, SE: r, SW: r,
	}
	defer rr.Push(gtx.Ops).Pop()
	edge := image.Rect(0, size.Y-gtx.Dp(unit.Dp(2)), size.X, size.Y)
	paint.FillShape(gtx.Ops, darker, clip.Rect(edge).Op())
}

// fullWidth forces a widget to the full available width by
// raising the minimum width constraint to the maximum. Several
// Gio widgets (editors, clickables) otherwise size to their
// content when measured as plain Rigids, which left the import
// cards' fields and buttons shrunk to text width (frame-probe
// finding, 2026-11-14).
func fullWidth(gtx layout.Context, w layout.Widget) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return w(gtx)
}

// surface draws the card background (white fill + border, plus
// an optional full-height accent bar on the left edge in the
// given color; zero color = no accent) under the content widget.
func surface(gtx layout.Context, accent color.NRGBA, w layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			shadowRRect(gtx, size, dpCardRad, pal.Shadow, 2)
			fillRRect(gtx, size, dpCardRad, pal.Card)
			if accent.A != 0 {
				// Accent bar: a plain rect at the left edge,
				// clipped by the card's rounded outline.
				r := gtx.Dp(unit.Dp(dpCardRad))
				rr := clip.RRect{
					Rect: image.Rect(0, 0, size.X, size.Y),
					NE:   r, NW: r, SE: r, SW: r,
				}
				defer rr.Push(gtx.Ops).Pop()
				bar := image.Rect(0, 0, gtx.Dp(unit.Dp(4)), size.Y)
				paint.FillShape(gtx.Ops, accent, clip.Rect(bar).Op())
			}
			strokeRRect(gtx, size, dpCardRad, pal.Border)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			// Card content always spans the card: without the
			// forced minimum, rows inside size to their widest
			// child and some cards render narrower than others
			// (frame-probe finding, 2026-11-14).
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return layout.Inset{
				Left: unit.Dp(14), Right: unit.Dp(14),
				Top: unit.Dp(12), Bottom: unit.Dp(12),
			}.Layout(gtx, w)
		}),
	)
}

// cardShell is surface() without content insets: the card
// chrome (fill, border, shadow, radius) with the content
// spanning the full card — for grouped-row cards whose rows
// and dividers manage their own insets (v4 settings groups,
// import method card, log list card).
func cardShell(gtx layout.Context, w layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			shadowRRect(gtx, size, dpCardRad, pal.Shadow, 2)
			fillRRect(gtx, size, dpCardRad, pal.Card)
			strokeRRect(gtx, size, dpCardRad, pal.Border)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return w(gtx)
		}),
	)
}

// On-white button text colors for the hero panel: the panel
// button is white-filled in EVERY tier, so its text colors
// are tier-independent deep tones that clear AA on white
// (the dark tiers' PrimaryText/Danger tints are tuned for
// dark surfaces and would fail on white).
var (
	onWhitePrimary = nrgba(0x23, 0x40, 0xB4)
	onWhiteDanger  = nrgba(0xBE, 0x32, 0x32)
)

// panelBtnKind enumerates the v4 hero panel's main buttons.
type panelBtnKind int

const (
	panelBtnSolid   panelBtnKind = iota // white fill, primary text
	panelBtnDanger                      // white fill, danger text (disconnect)
	panelBtnOutline                     // transparent, white outline + text (cancel)
)

// panelButton is the hero panel's main action: 60dp tall,
// radius 16, white-filled on the deep-blue gradient (v4). The
// outline kind is the connecting state's cancel action.
func (a *App) panelButton(gtx layout.Context, btn *widget.Clickable, ic iconKind, label string, kind panelBtnKind) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{Alignment: layout.Center}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				switch kind {
				case panelBtnOutline:
					// 1.5dp white outline at 70% alpha.
					oc := color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xB3}
					r := gtx.Dp(unit.Dp(dpRadiusHero))
					rr := clip.RRect{
						Rect: image.Rect(0, 0, size.X, size.Y),
						NE:   r, NW: r, SE: r, SW: r,
					}
					path := rr.Path(gtx.Ops)
					paint.FillShape(gtx.Ops, oc, clip.Stroke{Path: path, Width: float32(gtx.Dp(unit.Dp(1.5)))}.Op())
				default:
					fillRRect(gtx, size, dpRadiusHero, pal.White)
				}
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min = image.Pt(gtx.Constraints.Max.X, gtx.Dp(unit.Dp(dpPanelBtnH)))
				fg := onWhitePrimary
				if kind == panelBtnDanger {
					fg = onWhiteDanger
				}
				if kind == panelBtnOutline {
					fg = pal.White
				}
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					if ic == iconNone {
						return a.lbl(16, font.Bold, fg, label).Layout(gtx)
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return iconLayout(gtx, ic, 22, fg)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Rigid(a.lbl(16, font.Bold, fg, label).Layout),
					)
				})
			}),
		)
	})
}

// latencyState is a node row's right-column latency reading.
type latencyState int

const (
	latencyUntested latencyState = iota // hollow pill: not checked yet
	latencyOK                           // <= 80 ms, green
	latencySlow                         // 81..200 ms, amber
	latencyBad                          // no response / check failed, red
)

// latencyPill renders the v4 node-row latency capsule (26dp):
// measured values are tinted by band, "no response" is red,
// and an unchecked node gets a hollow outline pill so the
// empty state reads as "not measured", not "fast".
func (a *App) latencyPill(gtx layout.Context, st latencyState, text string) layout.Dimensions {
	var bg, fg color.NRGBA
	hollow := false
	switch st {
	case latencyOK:
		bg, fg = pal.SuccessBg, pal.Success
	case latencySlow:
		bg, fg = pal.WarnBg, pal.Warn
	case latencyBad:
		bg, fg = pal.DangerBg, pal.Danger
	default:
		hollow = true
		fg = pal.Hint
	}
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			if hollow {
				strokeRRect(gtx, size, 13, pal.Border)
			} else {
				fillRRect(gtx, size, 13, bg)
			}
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(26))
			return layout.Inset{Left: unit.Dp(9), Right: unit.Dp(9)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, a.lbl1(11.5, font.Bold, fg, text).Layout)
				})
		}),
	)
}

// pill renders a small capsule label (status pills, state
// pills). Height is fixed by design so the capsule radius is
// exact.
func (a *App) pill(gtx layout.Context, text string, bg, fg color.NRGBA, heightDp int) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			fillRRect(gtx, size, heightDp/2, bg)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(heightDp))
			return layout.Inset{Left: unit.Dp(9), Right: unit.Dp(9)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, a.lbl(11.5, font.Bold, fg, text).Layout)
				})
		}),
	)
}

// dotPill is the header status pill: a colored dot + label.
func (a *App) dotPill(gtx layout.Context, text string, bg, fg, dot color.NRGBA) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			fillRRect(gtx, size, 13, bg)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(26))
			return layout.Inset{Left: unit.Dp(11), Right: unit.Dp(11)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							d := gtx.Dp(unit.Dp(7))
							paint.FillShape(gtx.Ops, dot, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
							return layout.Dimensions{Size: image.Pt(d, d)}
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Rigid(a.lbl(12.5, font.Bold, fg, text).Layout),
					)
				})
		}),
	)
}

// badge is the small protocol tag on node cards.
func (a *App) badge(gtx layout.Context, text string) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			fillRRect(gtx, size, 4, pal.PrimaryLite)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Left: unit.Dp(6), Right: unit.Dp(6),
				Top: unit.Dp(2), Bottom: unit.Dp(2),
			}.Layout(gtx, a.lbl(10.5, font.Bold, pal.PrimaryText, text).Layout)
		}),
	)
}

// btnKind enumerates the button presentations of the mockups.
type btnKind int

const (
	btnPrimary btnKind = iota
	btnDanger
	btnDangerOutline // danger text + border on card fill (disconnect)
	btnOutline
	btnDisabled
	btnTabOff // inactive tab: white fill, secondary label
)

// bigButton is a tab/action-row button: fixed height, rounded,
// bold centered icon + label (2026-11-14 design ruling: every
// major button carries an icon image plus text; iconNone draws
// text only). Clicks go to the caller's Clickable; the disabled
// kind still reports clicks (the service layer's busy guard
// already swallows them) — only the presentation changes.
func (a *App) bigButton(gtx layout.Context, btn *widget.Clickable, ic iconKind, text string, kind btnKind) layout.Dimensions {
	return a.bigButtonSized(gtx, btn, ic, text, kind, 15, 19, 10, 7)
}

// bigButtonCompact is bigButton with tighter metrics for the
// node row's three-way action strip: at 360dp wide the strip
// leaves each button ~89dp, where the standard metrics
// (15sp label + 19dp icon + 10dp pads) truncate the longest
// label ("检查延迟" / "Check latency"). Compact metrics
// (13.5sp + 16dp + 6dp pads) fit all three languages.
func (a *App) bigButtonCompact(gtx layout.Context, btn *widget.Clickable, ic iconKind, text string, kind btnKind) layout.Dimensions {
	return a.bigButtonSized(gtx, btn, ic, text, kind, 13.5, 16, 6, 5)
}

func (a *App) bigButtonSized(gtx layout.Context, btn *widget.Clickable, ic iconKind, text string, kind btnKind, labelSp, iconDp, padDp, gapDp float32) layout.Dimensions {
	// In a Flexed slot the size is already exact (Min == Max)
	// and forcing width inside the button's Stack corrupts the
	// slot layout (tab row regression, frame probe 2026-11-14);
	// as a plain Rigid the button must span the available
	// width itself.
	rigidCtx := gtx.Constraints.Min.X < gtx.Constraints.Max.X
	var bg, fg, border color.NRGBA
	switch kind {
	case btnPrimary:
		bg, fg = pal.Primary, pal.White
	case btnDanger:
		bg, fg = pal.DangerFill, pal.White
	case btnDangerOutline:
		bg, fg, border = pal.Card, pal.Danger, pal.Danger
	case btnDisabled:
		bg, fg, border = pal.Card, pal.Disabled, pal.Border
	case btnTabOff:
		bg, fg, border = pal.Card, pal.Secondary, pal.Border
	default: // btnOutline
		bg, fg, border = pal.Card, pal.Text, pal.Border
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{Alignment: layout.Center}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				fillRRect(gtx, size, dpBtnRad, bg)
				if kind == btnPrimary || kind == btnDanger {
					buttonEdge(gtx, size, dpBtnRad, bg)
				}
				if border.A != 0 {
					strokeRRect(gtx, size, dpBtnRad, border)
				}
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				// Stack zeroes Min for Stacked children and
				// sizes itself from them alone, so the child
				// itself carries the button height (and, in a
				// Rigid context, the full width) — otherwise
				// the fill paints at content height inside a
				// taller layout box.
				gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(dpBtnH))
				if rigidCtx {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
				}
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: unit.Dp(padDp), Right: unit.Dp(padDp)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							children := []layout.FlexChild{
								layout.Flexed(1, layout.Spacer{}.Layout),
							}
							if ic != iconNone {
								children = append(children,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, ic, int(iconDp), fg)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(gapDp)}.Layout),
								)
							}
							children = append(children,
								layout.Rigid(a.lbl1(unit.Sp(labelSp), font.Bold, fg, text).Layout),
								layout.Flexed(1, layout.Spacer{}.Layout),
							)
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
						})
				})
			}),
		)
	})
}

// iconTextButton is a compact icon + label button for row
// actions and inline commands (test / delete / revoke / clear).
// The visual row stays compact, but the hit area is at least
// 48dp tall (v4 touch table; Step 18 debt repaid in this
// batch).
func (a *App) iconTextButton(gtx layout.Context, btn *widget.Clickable, ic iconKind, text string, fg color.NRGBA) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(48))
		return layout.Inset{
			Left: unit.Dp(5), Right: unit.Dp(5),
			Top: unit.Dp(5), Bottom: unit.Dp(5),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			// Baseline-anchored icon (see graphicBesideLabel):
			// a box-centered icon renders low against the
			// label's visible glyphs with the bundled font.
			return graphicBesideLabel(gtx, 15, 4, 12.5,
				func(gtx layout.Context) layout.Dimensions {
					return iconLayout(gtx, ic, 15, fg)
				},
				a.lbl1(12.5, font.Bold, fg, text).Layout)
		})
	})
}

// textButton is a borderless colored label button (node row
// actions, revoke/import links). Hit area at least 48dp tall
// (v4 touch table).
func (a *App) textButton(gtx layout.Context, btn *widget.Clickable, text string, fg color.NRGBA) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(48))
		return layout.Inset{
			Left: unit.Dp(6), Right: unit.Dp(6),
			Top: unit.Dp(6), Bottom: unit.Dp(6),
		}.Layout(gtx, a.lbl(13.5, font.Bold, fg, text).Layout)
	})
}

// chip is a group filter pill: selected = solid primary fill
// with white text (v4), unselected = card fill with border.
func (a *App) chip(gtx layout.Context, btn *widget.Clickable, text string, selected bool) layout.Dimensions {
	bg, fg := pal.Card, pal.Text
	var border color.NRGBA
	if selected {
		bg, fg = pal.Primary, pal.White
	} else {
		border = pal.Border
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		// The capsule visual is 40dp; the clickable itself is
		// 48dp tall with the capsule centered (v4 touch table).
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(48))
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = 0
			gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(dpChipH))
			return chipBody(gtx, bg, fg, border, text, a)
		})
	})
}

// chipBody is the chip's 40dp visual capsule.
func chipBody(gtx layout.Context, bg, fg color.NRGBA, border color.NRGBA, text string, a *App) layout.Dimensions {
	return layout.Stack{Alignment: layout.Center}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			fillRRect(gtx, size, dpChipH/2, bg)
			if border.A != 0 {
				strokeRRect(gtx, size, dpChipH/2, border)
			}
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(dpChipH))
			return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx,
					a.lbl(13, font.Bold, fg, text).Layout)
			})
		}),
	)
}

// radioRing draws the 19dp settings radio: a 2dp ring in the
// given color, with a filled primary center dot when dot is
// true.
func radioRing(gtx layout.Context, ring color.NRGBA, dot bool) layout.Dimensions {
	d := gtx.Dp(unit.Dp(19))
	paint.FillShape(gtx.Ops, ring, clip.Stroke{
		Path:  clip.Ellipse(image.Rect(0, 0, d, d)).Path(gtx.Ops),
		Width: float32(gtx.Dp(unit.Dp(2))),
	}.Op())
	if dot {
		dd := gtx.Dp(unit.Dp(9))
		off := (d - dd) / 2
		paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(off, off, off+dd, off+dd)).Op(gtx.Ops))
	}
	return layout.Dimensions{Size: image.Pt(d, d)}
}

// graphicBesideLabel lays out a square graphic of graphicDp
// beside a single-line label, anchoring the graphic's center
// to the label's ink center.
//
// Why not a Middle-aligned Flex: the bundled CJK font's line
// box carries its leading almost entirely below the glyphs,
// so a box-centered graphic renders ~10dp low against the
// visible glyphs (frame-verified on the v4 settings and log
// pages). A Gio label reports its baseline in its Dimensions;
// for this font the glyph ink center sits ~0.39em above the
// baseline at any size, which is stable. Stacked children run
// in order, so the label is laid out first and the graphic is
// then offset from the recorded baseline. emDp is the label's
// font size. Note Gio reports Dimensions.Baseline as the
// distance from the BOTTOM of the label box to the baseline,
// so the baseline's distance from the top is Size.Y-Baseline
// (probe-verified: 16.4dp at 14sp for the bundled font).
func graphicBesideLabel(gtx layout.Context, graphicDp, gapDp, emDp float32, graphic, labelW layout.Widget) layout.Dimensions {
	inkCenter := 0
	return layout.Stack{}.Layout(gtx,
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(graphicDp + gapDp)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				d := labelW(gtx)
				inkCenter = d.Size.Y - d.Baseline - gtx.Dp(unit.Dp(0.39*emDp))
				return d
			})
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			half := gtx.Dp(unit.Dp(graphicDp)) / 2
			y := inkCenter - half
			defer op.Offset(image.Pt(0, y)).Push(gtx.Ops).Pop()
			return graphic(gtx)
		}),
	)
}

// radioRow is a settings language row: ring + dot when
// selected, compressed to a single line at least 56dp tall
// (v4), the selected row tinted like every settings row.
func (a *App) radioRow(gtx layout.Context, btn *widget.Clickable, text string, selected bool) layout.Dimensions {
	body := func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(56))
		return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				return graphicBesideLabel(gtx, 19, 10, 14,
					func(gtx layout.Context) layout.Dimensions {
						ring := pal.Hint
						if selected {
							ring = pal.Primary
						}
						return radioRing(gtx, ring, selected)
					},
					a.lbl(14, font.Normal, pal.Text, text).Layout)
			})
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		if !selected {
			return body(gtx)
		}
		return selectedTint(gtx, body)
	})
}

// selectedTint paints the v4 selected-row treatment behind a
// settings row: a PrimaryLite rounded rect inset 6dp/3dp
// inside the row's own bounds (the row lives in a card; the
// tint never touches the card edge).
func selectedTint(gtx layout.Context, w layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			mx := gtx.Dp(unit.Dp(6))
			my := gtx.Dp(unit.Dp(3))
			rect := image.Rect(mx, my, size.X-mx, size.Y-my)
			r := gtx.Dp(unit.Dp(12))
			rr := clip.RRect{Rect: rect, NE: r, NW: r, SE: r, SW: r}
			paint.FillShape(gtx.Ops, pal.PrimaryLite, rr.Op(gtx.Ops))
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(w),
	)
}

// radioDescRow is the v4 settings option row — the single
// row type for every settings group: radio ring + title + one
// line of plain-language description under it, at least 56dp
// tall, the selected row tinted inside its card. Disabled
// rows (a choice the platform cannot honor) render dimmed
// with an amber reason line inside the row, and are not
// clickable — a listed-but-honest absence, never a dead
// switch.
func (a *App) radioDescRow(gtx layout.Context, btn *widget.Clickable, title, desc, reason string, selected, enabled bool) layout.Dimensions {
	content := func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(56))
		return layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				titleCol, descCol := pal.Text, pal.Secondary
				if !enabled {
					titleCol, descCol = pal.Disabled, pal.Disabled
				}
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(2)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							ring := pal.Hint
							if !enabled {
								ring = pal.Disabled
							} else if selected {
								ring = pal.Primary
							}
							return radioRing(gtx, ring, selected && enabled)
						})
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						rows := []layout.FlexChild{
							layout.Rigid(a.lbl(14.5, font.Normal, titleCol, title).Layout),
						}
						if desc != "" {
							rows = append(rows,
								layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
								layout.Rigid(a.lblMax(12, font.Normal, descCol, desc, 2).Layout),
							)
						}
						if !enabled && reason != "" {
							rows = append(rows,
								layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
								layout.Rigid(a.lblMax(12, font.Normal, pal.Warn, reason, 2).Layout),
							)
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					}),
				)
			})
	}
	wrapped := func(gtx layout.Context) layout.Dimensions {
		if !selected {
			return content(gtx)
		}
		return selectedTint(gtx, content)
	}
	if !enabled {
		return wrapped(gtx)
	}
	return btn.Layout(gtx, wrapped)
}

// editorBox frames an editor with the mockups' light fill and
// border. maxYDp > 0 caps the box height (multi-line input).
func (a *App) editorBox(gtx layout.Context, ed *widget.Editor, hint string, maxYDp int) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			fillRRect(gtx, size, dpBtnRad, pal.InputBg)
			strokeRRect(gtx, size, dpBtnRad, pal.Border)
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			// Same Stack Min-zeroing: re-raise so the editor
			// field spans the card, not its hint text.
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			if maxYDp > 0 {
				gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(maxYDp))
			}
			return layout.Inset{
				Left: unit.Dp(10), Right: unit.Dp(10),
				Top: unit.Dp(8), Bottom: unit.Dp(8),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				e := material.Editor(a.th, ed, hint)
				e.TextSize = unit.Sp(13.5)
				e.Color = pal.Text
				e.HintColor = pal.Hint
				e.SelectionColor = pal.PrimaryLite
				return e.Layout(gtx)
			})
		}),
	)
}

// progressBarLayout is the thin indeterminate bar under the
// tabs while a connection is being established (mockup 04).
// The fraction sweeps on the wall clock; entry points
// invalidate frames about once a second, so the motion is
// steppy but live.
func progressBarLayout(gtx layout.Context) layout.Dimensions {
	height := gtx.Dp(unit.Dp(3))
	width := gtx.Constraints.Max.X
	ms := time.Now().UnixMilli() % 1400
	frac := 0.08 + 0.84*float32(ms)/1400.0
	fillW := int(float32(width) * frac)
	paint.FillShape(gtx.Ops, pal.PrimaryLite, clip.Rect(image.Rect(0, 0, width, height)).Op())
	if fillW > 0 {
		paint.FillShape(gtx.Ops, pal.Primary, clip.Rect(image.Rect(0, 0, fillW, height)).Op())
	}
	return layout.Dimensions{Size: image.Pt(width, height)}
}

// --- Icon set --------------------------------------------------------
//
// One icon family for every button (2026-11-14 design ruling:
// major buttons are icon image + text, never bare text or plain
// color blocks). All icons share one language: a 24-unit grid,
// 2-unit strokes, round joins, no fills except the favorite
// star. They are drawn, not raster assets, so they stay crisp
// at any density and in every build.

type iconKind int

const (
	iconNone iconKind = iota - 1
	iconPower
	iconTarget
	iconGauge
	iconPulse
	iconTrash
	iconLink
	iconDownload
	iconFileText
	iconFolder
	iconRefresh
	iconShield
	iconCheck
	iconClose
	iconSearch
	iconGlobe
	iconList
	iconGear
	iconBook
	iconChevron
	iconDots
	iconArrowCircle
	iconRss
	iconWarn
)

// iconLayout draws one icon at sizeDp in the given color.
func iconLayout(gtx layout.Context, kind iconKind, sizeDp int, col color.NRGBA) layout.Dimensions {
	s := gtx.Dp(unit.Dp(sizeDp))
	u := float32(s) / 24 // one grid unit in px
	stroke := func(build func(p *clip.Path)) {
		var p clip.Path
		p.Begin(gtx.Ops)
		build(&p)
		paint.FillShape(gtx.Ops, col, clip.Stroke{Path: p.End(), Width: 2 * u}.Op())
	}
	pt := func(x, y float32) f32.Point { return f32.Point{X: x * u, Y: y * u} }
	circle := func(cx, cy, r float32) {
		paint.FillShape(gtx.Ops, col, clip.Stroke{
			Path:  clip.Ellipse(image.Rect(int((cx-r)*u), int((cy-r)*u), int((cx+r)*u), int((cy+r)*u))).Path(gtx.Ops),
			Width: 2 * u,
		}.Op())
	}
	dot := func(cx, cy, r float32) {
		paint.FillShape(gtx.Ops, col, clip.Ellipse(image.Rect(int((cx-r)*u), int((cy-r)*u), int((cx+r)*u), int((cy+r)*u))).Op(gtx.Ops))
	}
	arc := func(cx, cy, r, a0, a1 float32) {
		stroke(func(p *clip.Path) { arcTo(p, pt(cx, cy), r*u, a0, a1) })
	}
	switch kind {
	case iconPower:
		arc(12, 13, 8, -1.02, 4.16) // full sweep leaving a gap at the top
		stroke(func(p *clip.Path) { p.MoveTo(pt(12, 3)); p.LineTo(pt(12, 11)) })
	case iconTarget:
		circle(12, 12, 8.5)
		circle(12, 12, 4.5)
		dot(12, 12, 1.6)
	case iconGauge:
		arc(12, 14, 8.5, 3.14, 6.28) // upper semicircle (through the top)
		stroke(func(p *clip.Path) { p.MoveTo(pt(12, 14)); p.LineTo(pt(16.5, 8.5)) })
		dot(12, 14, 1.6)
	case iconPulse:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(2.5, 12))
			p.LineTo(pt(7, 12))
			p.LineTo(pt(10, 5.5))
			p.LineTo(pt(14, 18))
			p.LineTo(pt(16.5, 12))
			p.LineTo(pt(21.5, 12))
		})
	case iconTrash:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(4, 6.5))
			p.LineTo(pt(20, 6.5))
			p.MoveTo(pt(9.5, 6.5))
			p.LineTo(pt(10.5, 20))
			p.LineTo(pt(13.5, 20))
			p.LineTo(pt(14.5, 6.5))
			p.MoveTo(pt(9, 6.5))
			p.LineTo(pt(9.8, 3.8))
			p.LineTo(pt(14.2, 3.8))
			p.LineTo(pt(15, 6.5))
		})
	case iconLink:
		circle(9, 15, 5.5)
		circle(15, 9, 5.5)
	case iconDownload:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(12, 3.5))
			p.LineTo(pt(12, 14.5))
			p.MoveTo(pt(7, 10))
			p.LineTo(pt(12, 15))
			p.LineTo(pt(17, 10))
			p.MoveTo(pt(4.5, 19.5))
			p.LineTo(pt(19.5, 19.5))
		})
	case iconFileText:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(6, 3))
			p.LineTo(pt(14.5, 3))
			p.LineTo(pt(18.5, 7))
			p.LineTo(pt(18.5, 21))
			p.LineTo(pt(6, 21))
			p.LineTo(pt(6, 3))
			p.MoveTo(pt(14.5, 3))
			p.LineTo(pt(14.5, 7))
			p.LineTo(pt(18.5, 7))
			p.MoveTo(pt(9, 12.5))
			p.LineTo(pt(15.5, 12.5))
			p.MoveTo(pt(9, 16.5))
			p.LineTo(pt(15.5, 16.5))
		})
	case iconFolder:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(3.5, 6))
			p.LineTo(pt(9.5, 6))
			p.LineTo(pt(11.5, 8.5))
			p.LineTo(pt(20.5, 8.5))
			p.LineTo(pt(20.5, 19))
			p.LineTo(pt(3.5, 19))
			p.LineTo(pt(3.5, 6))
		})
	case iconRefresh:
		arc(12, 12, 8.2, -0.6, 4.4)
		stroke(func(p *clip.Path) {
			// Arrowhead at the arc's end (top-left, angle 4.4).
			p.MoveTo(pt(9.5, 4.2))
			p.LineTo(pt(14.1, 3.3))
			p.MoveTo(pt(9.5, 4.2))
			p.LineTo(pt(10.7, 8.8))
		})
	case iconShield:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(12, 3))
			p.QuadTo(pt(16.5, 4.6), pt(19.5, 5.2))
			p.QuadTo(pt(19.2, 14.5), pt(12, 21))
			p.QuadTo(pt(4.8, 14.5), pt(4.5, 5.2))
			p.QuadTo(pt(7.5, 4.6), pt(12, 3))
			p.MoveTo(pt(8.8, 11.6))
			p.LineTo(pt(11.2, 14.2))
			p.LineTo(pt(15.4, 9.4))
		})
	case iconCheck:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(4.5, 12.8))
			p.LineTo(pt(9.8, 18))
			p.LineTo(pt(19.5, 6.5))
		})
	case iconClose:
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(6, 6))
			p.LineTo(pt(18, 18))
			p.MoveTo(pt(18, 6))
			p.LineTo(pt(6, 18))
		})
	case iconSearch:
		circle(10.8, 10.8, 6.8)
		stroke(func(p *clip.Path) { p.MoveTo(pt(15.8, 15.8)); p.LineTo(pt(20.5, 20.5)) })
	case iconGlobe:
		circle(12, 12, 9)
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(3.2, 12))
			p.LineTo(pt(20.8, 12))
			p.MoveTo(pt(12, 3))
			p.QuadTo(pt(17.5, 8), pt(12, 21))
			p.MoveTo(pt(12, 3))
			p.QuadTo(pt(6.5, 8), pt(12, 21))
		})
	case iconList:
		stroke(func(p *clip.Path) {
			for _, y := range []float32{7, 12, 17} {
				p.MoveTo(pt(8.5, y))
				p.LineTo(pt(20.5, y))
			}
		})
		dot(5, 7, 1.5)
		dot(5, 12, 1.5)
		dot(5, 17, 1.5)
	case iconGear:
		circle(12, 12, 3.6)
		stroke(func(p *clip.Path) {
			for _, a := range []float32{0, 1.05, 2.09, 3.14, 4.19, 5.24} {
				x0, y0 := polar(12, 12, 6.4, a)
				x1, y1 := polar(12, 12, 9.6, a)
				p.MoveTo(pt(x0, y0))
				p.LineTo(pt(x1, y1))
			}
		})
	case iconBook: // open book (illustrated-guide entry)
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(12, 5.5))
			p.CubeTo(pt(9.8, 3.6), pt(6, 3.2), pt(3.5, 4.2))
			p.LineTo(pt(3.5, 19))
			p.CubeTo(pt(6, 17.9), pt(9.8, 18.2), pt(12, 20))
			p.LineTo(pt(12, 5.5))
			p.MoveTo(pt(12, 5.5))
			p.CubeTo(pt(14.2, 3.6), pt(18, 3.2), pt(20.5, 4.2))
			p.LineTo(pt(20.5, 19))
			p.CubeTo(pt(18, 17.9), pt(14.2, 18.2), pt(12, 20))
		})
	case iconChevron: // right-pointing chevron (row affordance)
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(9, 4.5))
			p.LineTo(pt(16.5, 12))
			p.LineTo(pt(9, 19.5))
		})
	case iconDots: // vertical overflow dots
		dot(12, 5, 1.7)
		dot(12, 12, 1.7)
		dot(12, 19, 1.7)
	case iconArrowCircle: // filled disc + arrow (picked-row connect)
		dot(12, 12, 10.5)
		var p clip.Path
		p.Begin(gtx.Ops)
		p.MoveTo(pt(8, 12))
		p.LineTo(pt(15.5, 12))
		p.MoveTo(pt(12.3, 8.2))
		p.LineTo(pt(16, 12))
		p.LineTo(pt(12.3, 15.8))
		paint.FillShape(gtx.Ops, pal.White, clip.Stroke{Path: p.End(), Width: 2 * u}.Op())
	case iconRss: // broadcast dot + arcs (subscription method)
		dot(6, 18, 1.8)
		arc(6, 18, 6.5, -1.57, 0)
		arc(6, 18, 11.5, -1.57, 0)
	case iconWarn: // warning triangle with exclamation
		stroke(func(p *clip.Path) {
			p.MoveTo(pt(12, 3.5))
			p.LineTo(pt(21.5, 20))
			p.LineTo(pt(2.5, 20))
			p.Close()
			p.MoveTo(pt(12, 10))
			p.LineTo(pt(12, 14.5))
		})
		dot(12, 17.3, 1.3)
	}
	return layout.Dimensions{Size: image.Pt(s, s)}
}

// polar returns the point at radius r and angle a (radians,
// 0 = east, counter-clockwise in math orientation; screen y is
// flipped, which only mirrors the gear — visually irrelevant).
func polar(cx, cy, r, a float32) (float32, float32) {
	return cx + r*cosf(a), cy + r*sinf(a)
}

func cosf(a float32) float32 { return float32(math.Cos(float64(a))) }
func sinf(a float32) float32 { return float32(math.Sin(float64(a))) }

// arcTo appends a circular arc to p (screen coordinates: angles
// grow clockwise because y points down), approximated with
// quadratic segments of at most ~45 degrees.
func arcTo(p *clip.Path, c f32.Point, r float32, a0, a1 float32) {
	steps := int((a1 - a0) / 0.785)
	if steps < 1 {
		steps = 1
	}
	sx, sy := c.X+r*cosf(a0), c.Y+r*sinf(a0)
	p.MoveTo(f32.Point{X: sx, Y: sy})
	for i := 1; i <= steps; i++ {
		am := a0 + (a1-a0)*float32(i)/float32(steps)
		ap := a0 + (a1-a0)*float32(i-1)/float32(steps)
		// Control point: intersection of the endpoint tangents,
		// at distance r/cos(step/2) along the mid-angle.
		mid := (am + ap) / 2
		k := r / cosf((am-ap)/2)
		cx, cy := c.X+k*cosf(mid), c.Y+k*sinf(mid)
		ex, ey := c.X+r*cosf(am), c.Y+r*sinf(am)
		p.QuadTo(f32.Point{X: cx, Y: cy}, f32.Point{X: ex, Y: ey})
	}
}

// starIcon draws the favorite star: filled in the primary color
// when the node is a favorite, outline in the hint color when
// not. It is the row's bookmark affordance (design ruling).
func starIcon(gtx layout.Context, fav bool, sizeDp int) layout.Dimensions {
	s := gtx.Dp(unit.Dp(sizeDp))
	cx, cy := float32(s)/2, float32(s)/2
	rOut, rIn := float32(s)*0.44, float32(s)*0.19
	var p clip.Path
	p.Begin(gtx.Ops)
	for i := 0; i < 10; i++ {
		a := -1.5708 + float32(i)*0.6283
		r := rOut
		if i%2 == 1 {
			r = rIn
		}
		x, y := cx+r*cosf(a), cy+r*sinf(a)
		if i == 0 {
			p.MoveTo(f32.Point{X: x, Y: y})
		} else {
			p.LineTo(f32.Point{X: x, Y: y})
		}
	}
	p.Close()
	spec := p.End()
	if fav {
		paint.FillShape(gtx.Ops, pal.Primary, clip.Outline{Path: spec}.Op())
	} else {
		paint.FillShape(gtx.Ops, pal.Hint, clip.Stroke{Path: spec, Width: float32(gtx.Dp(unit.Dp(1.6)))}.Op())
	}
	return layout.Dimensions{Size: image.Pt(s, s)}
}

// eyeGlyph draws the brand eye (Step 3 direction 1: two
// eyelid arcs converging on a pupil = the node) at w x h in
// the given color. pupil=false draws the lids only (the hero
// badge draws its own state ring in the pupil's place);
// solidPupil adds the center dot inside the ring. Never a
// realistic eyeball (mockup README).
func eyeGlyph(gtx layout.Context, wDp, hDp int, col color.NRGBA, pupil, solidPupil bool, strokeDp float32) {
	w := gtx.Dp(unit.Dp(wDp))
	h := gtx.Dp(unit.Dp(hDp))
	fw, fh := float32(w), float32(h)
	var p clip.Path
	p.Begin(gtx.Ops)
	// Upper lid: left corner -> top arc -> right corner.
	p.MoveTo(f32.Point{X: fw * 0.03, Y: fh * 0.5})
	p.QuadTo(f32.Point{X: fw * 0.5, Y: -fh * 0.42}, f32.Point{X: fw * 0.97, Y: fh * 0.5})
	// Lower lid: right corner -> bottom arc -> left corner.
	p.QuadTo(f32.Point{X: fw * 0.5, Y: fh * 1.42}, f32.Point{X: fw * 0.03, Y: fh * 0.5})
	stroke := clip.Stroke{Path: p.End(), Width: float32(gtx.Dp(unit.Dp(strokeDp)))}
	paint.FillShape(gtx.Ops, col, stroke.Op())
	if !pupil {
		return
	}
	// Pupil ring.
	rd := w * 11 / 34
	off := image.Pt((w-rd)/2, (h-rd)/2)
	paint.FillShape(gtx.Ops, col, clip.Stroke{
		Path:  clip.Ellipse(image.Rect(off.X, off.Y, off.X+rd, off.Y+rd)).Path(gtx.Ops),
		Width: float32(gtx.Dp(unit.Dp(strokeDp * 0.9))),
	}.Op())
	if solidPupil {
		// Pupil dot (the node everything converges on).
		dd := w * 4 / 34
		off2 := image.Pt((w-dd)/2, (h-dd)/2)
		paint.FillShape(gtx.Ops, col, clip.Ellipse(image.Rect(off2.X, off2.Y, off2.X+dd, off2.Y+dd)).Op(gtx.Ops))
	}
}

// eyeMark is the header brand mark (34x24, primary color,
// solid pupil).
func eyeMark(gtx layout.Context) layout.Dimensions {
	eyeGlyph(gtx, 34, 24, pal.Primary, true, true, 2.2)
	return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(34)), gtx.Dp(unit.Dp(24)))}
}

// pupilState is the hero badge's connection state (v4: the
// pupil ring IS the connection state — color, shape and the
// panel's text agree, so state never rides on color alone).
type pupilState int

const (
	pupilIdle pupilState = iota
	pupilConnecting
	pupilConnected
	pupilFailed
)

// heroBadge draws the v4 "Tongxin" status badge on the hero
// panel: a 96dp disc (white at 12%) holding the white eye
// glyph and the pupil ring that carries the state — idle:
// hollow ring + hollow pupil; connecting: white arc sweeping
// over a faint track + solid small pupil; connected: full
// success-green ring + solid green pupil + halo; failed:
// danger ring + an x pupil. Only the connecting state
// animates, on a restrained ~1.1s sweep driven by frame
// invalidation.
func (a *App) heroBadge(gtx layout.Context, st pupilState) layout.Dimensions {
	d := gtx.Dp(unit.Dp(dpBadge))
	size := image.Pt(d, d)
	cx, cy := float32(d)/2, float32(d)/2
	white := pal.White
	// Halo (connected only): a soft success disc behind.
	if st == pupilConnected {
		halo := pal.Success
		halo.A = 0x2E
		hd := d + gtx.Dp(unit.Dp(16))
		off := (d - hd) / 2
		paint.FillShape(gtx.Ops, halo, clip.Ellipse(image.Rect(off, off, off+hd, off+hd)).Op(gtx.Ops))
	}
	// Disc.
	disc := white
	disc.A = 0x1F
	paint.FillShape(gtx.Ops, disc, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
	// Eye glyph (white), pupil area left to the ring below.
	eyeW, eyeH := 62, 44
	off := image.Pt((d-gtx.Dp(unit.Dp(eyeW)))/2, (d-gtx.Dp(unit.Dp(eyeH)))/2)
	func() {
		defer op.Offset(off).Push(gtx.Ops).Pop()
		eyeGlyph(gtx, eyeW, eyeH, white, false, false, 2.6)
	}()
	// Pupil ring: radius 10dp around the center.
	ringR := float32(gtx.Dp(unit.Dp(10)))
	ringW := float32(gtx.Dp(unit.Dp(3)))
	ring := func(col color.NRGBA, a0, a1 float32) {
		var p clip.Path
		p.Begin(gtx.Ops)
		arcTo(&p, f32.Point{X: cx, Y: cy}, ringR, a0, a1)
		paint.FillShape(gtx.Ops, col, clip.Stroke{Path: p.End(), Width: ringW}.Op())
	}
	dot := func(col color.NRGBA, rDp float32) {
		rd := gtx.Dp(unit.Dp(rDp))
		o := image.Pt((d-rd)/2, (d-rd)/2)
		paint.FillShape(gtx.Ops, col, clip.Ellipse(image.Rect(o.X, o.Y, o.X+rd, o.Y+rd)).Op(gtx.Ops))
	}
	switch st {
	case pupilIdle:
		c := white
		c.A = 0x61 // white 38%
		ring(c, 0, 2*math.Pi)
		// Hollow small pupil: ring only.
		var p clip.Path
		p.Begin(gtx.Ops)
		arcTo(&p, f32.Point{X: cx, Y: cy}, ringR*0.42, 0, 2*math.Pi)
		paint.FillShape(gtx.Ops, c, clip.Stroke{Path: p.End(), Width: float32(gtx.Dp(unit.Dp(1.6)))}.Op())
	case pupilConnecting:
		track := white
		track.A = 0x4D // white 30%
		ring(track, 0, 2*math.Pi)
		// Sweeping arc: ~100 degrees, rotating once per ~1.1s.
		ms := time.Now().UnixMilli() % 1100
		a0 := float32(ms) / 1100 * 2 * math.Pi
		ring(white, a0, a0+1.75)
		dot(white, 4.5)
		gtx.Execute(op.InvalidateCmd{At: time.Now().Add(33 * time.Millisecond)})
	case pupilConnected:
		green := nrgba(0x3E, 0xD5, 0x98)
		ring(green, 0, 2*math.Pi)
		dot(green, 7)
	case pupilFailed:
		red := nrgba(0xFF, 0x9D, 0x8A)
		ring(red, 0, 2*math.Pi)
		// x pupil.
		var p clip.Path
		p.Begin(gtx.Ops)
		r := ringR * 0.42
		p.MoveTo(f32.Point{X: cx - r, Y: cy - r})
		p.LineTo(f32.Point{X: cx + r, Y: cy + r})
		p.MoveTo(f32.Point{X: cx + r, Y: cy - r})
		p.LineTo(f32.Point{X: cx - r, Y: cy + r})
		paint.FillShape(gtx.Ops, red, clip.Stroke{Path: p.End(), Width: float32(gtx.Dp(unit.Dp(2.2)))}.Op())
	}
	return layout.Dimensions{Size: size}
}

// watermarkEye draws the large faint eye used by the v4 empty
// states (log page, zero-node first screen): the brand glyph
// at 120x86 in the border tone — present, quiet, never
// competing with the one line of text under it.
func watermarkEye(gtx layout.Context) layout.Dimensions {
	eyeGlyph(gtx, 120, 86, pal.Border, true, false, 3)
	return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(120)), gtx.Dp(unit.Dp(86)))}
}

// --- v3 components (first-screen hero, option groups, sheets) ---

// heroButton is the first screen's one primary action: 56dp
// tall, radius 16, power icon + 16sp bold label (teardown
// button tokens). Gio's Stack sizes itself from its Stacked
// children only (the incoming Min is applied afterwards via
// Constrain, which grows the layout box but NOT the Expanded
// fill), so the Stacked child itself is given the exact
// button size and centers the label row inside it.
func (a *App) heroButton(gtx layout.Context, btn *widget.Clickable, ic iconKind, label string, kind btnKind) layout.Dimensions {
	var bg, fg color.NRGBA
	border := color.NRGBA{}
	switch kind {
	case btnDanger:
		bg, fg = pal.DangerFill, pal.White
	case btnOutline:
		bg, fg, border = pal.Card, pal.Text, pal.Border
	default:
		bg, fg = pal.Primary, pal.White
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{Alignment: layout.Center}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				fillRRect(gtx, size, dpRadiusHero, bg)
				if kind == btnPrimary || kind == btnDanger {
					buttonEdge(gtx, size, dpRadiusHero, bg)
				}
				if border.A != 0 {
					strokeRRect(gtx, size, dpRadiusHero, border)
				}
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min = image.Pt(gtx.Constraints.Max.X, gtx.Dp(unit.Dp(dpHeroH)))
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return iconLayout(gtx, ic, 22, fg)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Rigid(a.lbl(16, font.Bold, fg, label).Layout),
					)
				})
			}),
		)
	})
}

// swatch draws one background-tier swatch in the settings
// page: a 56dp mini UI preview (the tier's own page gradient,
// a card title bar, a primary button pill) so the four tiers
// read apart at a glance — deep blue vs ink especially (v4
// A7: the v3 swatches were indistinguishable and the selected
// check was clipped at the corner). Everything is clipped to
// the swatch's rounded outline; the selected check sits
// INSIDE the preview, bottom-right, a primary disc with a
// white ring. The "system" tier passes split=true and shows
// light on the left half, navy on the right.
func (a *App) swatch(gtx layout.Context, p Palette, split bool, selected bool) layout.Dimensions {
	w := gtx.Dp(unit.Dp(56))
	h := gtx.Dp(unit.Dp(56))
	size := image.Pt(w, h)
	r := gtx.Dp(unit.Dp(10))
	rr := clip.RRect{Rect: image.Rect(0, 0, w, h), NE: r, NW: r, SE: r, SW: r}
	defer rr.Push(gtx.Ops).Pop()
	u := func(dp int) int { return gtx.Dp(unit.Dp(dp)) }
	drawHalf := func(x0, x1 int, pp Palette) {
		stack := clip.Rect{Min: image.Pt(x0, 0), Max: image.Pt(x1, h)}.Push(gtx.Ops)
		paint.FillShape(gtx.Ops, pp.BgTop, clip.Rect{Min: image.Pt(0, 0), Max: size}.Op())
		// Card title bar.
		bar := image.Rect(u(8), u(9), w-u(8), u(21))
		paint.FillShape(gtx.Ops, pp.Card, clip.RRect{Rect: bar, NE: 3, NW: 3, SE: 3, SW: 3}.Op(gtx.Ops))
		// Text line under the bar.
		line := image.Rect(u(8), u(27), u(26), u(31))
		paint.FillShape(gtx.Ops, pp.Border, clip.RRect{Rect: line, NE: 2, NW: 2, SE: 2, SW: 2}.Op(gtx.Ops))
		// Primary button pill.
		btn := image.Rect(u(8), u(37), u(30), u(48))
		paint.FillShape(gtx.Ops, pp.Primary, clip.RRect{Rect: btn, NE: 4, NW: 4, SE: 4, SW: 4}.Op(gtx.Ops))
		stack.Pop()
	}
	if split {
		drawHalf(0, w/2, paletteLight)
		drawHalf(w/2, w, paletteNavy)
	} else {
		drawHalf(0, w, p)
	}
	strokeRRect(gtx, size, 10, pal.Border)
	if selected {
		// Inset check badge: white ring + primary disc + white
		// check, fully inside the preview (never clipped).
		bd := u(19)
		cx, cy := w-u(13), h-u(13)
		paint.FillShape(gtx.Ops, pal.White, clip.Ellipse(image.Rect(cx-bd/2, cy-bd/2, cx+bd/2, cy+bd/2)).Op(gtx.Ops))
		id := u(16)
		paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(cx-id/2, cy-id/2, cx+id/2, cy+id/2)).Op(gtx.Ops))
		st := op.Offset(image.Pt(cx-u(5), cy-u(5))).Push(gtx.Ops)
		iconLayout(gtx, iconCheck, 10, pal.White)
		st.Pop()
	}
	return layout.Dimensions{Size: size}
}

func ternary[T any](cond bool, x, y T) T {
	if cond {
		return x
	}
	return y
}

// --- v3 icons ---
