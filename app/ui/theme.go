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
type Palette struct {
	Bg          color.NRGBA // page background
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
}

func nrgba(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }

// paletteLight is the original v2 light set. Four text colors
// were deepened from the v2 drawing values so every pair
// passes WCAG AA (Hint #949CA8 -> #6A7280, Warn #C97C12 ->
// #9A6206, Success #12966C -> #0B7050, Danger #D03C3C ->
// #BE3232); hues are unchanged, only luminance moved.
var paletteLight = Palette{
	Bg:          nrgba(0xF6, 0xF7, 0xF9),
	Card:        nrgba(0xFF, 0xFF, 0xFF),
	Border:      nrgba(0xE4, 0xE7, 0xEC),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x23, 0x40, 0xB4),
	PrimaryLite: nrgba(0xE8, 0xEE, 0xFE),
	Text:        nrgba(0x1A, 0x1D, 0x21),
	Secondary:   nrgba(0x62, 0x6A, 0x78),
	Hint:        nrgba(0x6A, 0x72, 0x80),
	Success:     nrgba(0x0B, 0x70, 0x50),
	SuccessBg:   nrgba(0xDE, 0xF5, 0xEC),
	Warn:        nrgba(0x9A, 0x62, 0x06),
	WarnBg:      nrgba(0xFB, 0xF3, 0xE4),
	Danger:      nrgba(0xBE, 0x32, 0x32),
	DangerBg:    nrgba(0xFC, 0xE9, 0xE9),
	DangerFill:  nrgba(0xBE, 0x32, 0x32),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0xF9, 0xFA, 0xFB),
	PillIdle:    nrgba(0xED, 0xEF, 0xF2),
	Disabled:    nrgba(0xB6, 0xBD, 0xC9),
	Scrim:       color.NRGBA{A: 0x66},
}

// paletteNavy is the deep-blue tier sampled from the approved
// competitor reference (teardown notes): blue-black surfaces,
// never pure black, light-blue accent text on dark surfaces.
var paletteNavy = Palette{
	Bg:          nrgba(0x11, 0x15, 0x18),
	Card:        nrgba(0x19, 0x1D, 0x20),
	Border:      nrgba(0x26, 0x2B, 0x2F),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x8F, 0xA8, 0xFF),
	PrimaryLite: nrgba(0x1E, 0x2A, 0x4A),
	Text:        nrgba(0xF2, 0xF4, 0xF7),
	Secondary:   nrgba(0x9A, 0xA1, 0xA8),
	Hint:        nrgba(0x86, 0x8E, 0x99),
	Success:     nrgba(0x43, 0xD6, 0x9B),
	SuccessBg:   nrgba(0x12, 0x35, 0x28),
	Warn:        nrgba(0xE8, 0xA3, 0x3D),
	WarnBg:      nrgba(0x33, 0x27, 0x0E),
	Danger:      nrgba(0xFF, 0x9C, 0x9C),
	DangerBg:    nrgba(0x38, 0x1E, 0x1E),
	DangerFill:  nrgba(0xC2, 0x43, 0x43),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0x14, 0x18, 0x1B),
	PillIdle:    nrgba(0x20, 0x26, 0x2B),
	Disabled:    nrgba(0x5A, 0x62, 0x6B),
	Scrim:       color.NRGBA{A: 0x99},
}

// paletteInk is the ink-black tier: pure-black page, neutral
// grey surfaces, for OLED battery saving.
var paletteInk = Palette{
	Bg:          nrgba(0x00, 0x00, 0x00),
	Card:        nrgba(0x14, 0x14, 0x14),
	Border:      nrgba(0x26, 0x26, 0x26),
	Primary:     nrgba(0x2E, 0x54, 0xEB),
	PrimaryText: nrgba(0x8F, 0xA8, 0xFF),
	PrimaryLite: nrgba(0x1B, 0x24, 0x40),
	Text:        nrgba(0xF5, 0xF5, 0xF5),
	Secondary:   nrgba(0xA3, 0xA3, 0xA3),
	Hint:        nrgba(0x8F, 0x8F, 0x8F),
	Success:     nrgba(0x43, 0xD6, 0x9B),
	SuccessBg:   nrgba(0x0E, 0x2E, 0x22),
	Warn:        nrgba(0xE8, 0xA3, 0x3D),
	WarnBg:      nrgba(0x2E, 0x23, 0x0C),
	Danger:      nrgba(0xFF, 0x9C, 0x9C),
	DangerBg:    nrgba(0x33, 0x1B, 0x1B),
	DangerFill:  nrgba(0xC2, 0x43, 0x43),
	White:       nrgba(0xFF, 0xFF, 0xFF),
	InputBg:     nrgba(0x0A, 0x0A, 0x0A),
	PillIdle:    nrgba(0x1C, 0x1C, 0x1C),
	Disabled:    nrgba(0x59, 0x59, 0x59),
	Scrim:       color.NRGBA{A: 0xB3},
}

// pal is the active palette (see the Palette comment). It
// starts at light - the pre-v3 default - and the App switches
// it per frame from the persisted setting.
var pal = paletteLight

const (
	dpMargin     = 16 // page content margin
	dpCardGap    = 10 // vertical gap between cards
	dpCardRad    = 10 // card corner radius
	dpBtnRad     = 8  // button corner radius
	dpBtnH       = 48 // standard action button height (v3 token)
	dpChipH      = 40 // group filter chip height (v3 token, full-round)
	dpHeroH      = 56 // hero primary button height (first-screen one-tap connect)
	dpRowH       = 72 // two-line node row height (warning rows: 84)
	dpRadiusHero = 16 // hero button corner radius
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
					return layout.Inset{Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							children := []layout.FlexChild{
								layout.Flexed(1, layout.Spacer{}.Layout),
							}
							if ic != iconNone {
								children = append(children,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, ic, 19, fg)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(7)}.Layout),
								)
							}
							children = append(children,
								layout.Rigid(a.lbl1(15, font.Bold, fg, text).Layout),
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
func (a *App) iconTextButton(gtx layout.Context, btn *widget.Clickable, ic iconKind, text string, fg color.NRGBA) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(5), Right: unit.Dp(5),
			Top: unit.Dp(5), Bottom: unit.Dp(5),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return iconLayout(gtx, ic, 15, fg)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
				layout.Rigid(a.lbl1(12.5, font.Bold, fg, text).Layout),
			)
		})
	})
}

// textButton is a borderless colored label button (node row
// actions, revoke/import links).
func (a *App) textButton(gtx layout.Context, btn *widget.Clickable, text string, fg color.NRGBA) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(6), Right: unit.Dp(6),
			Top: unit.Dp(6), Bottom: unit.Dp(6),
		}.Layout(gtx, a.lbl(13.5, font.Bold, fg, text).Layout)
	})
}

// chip is a group filter pill: selected = light primary fill,
// unselected = white with border.
func (a *App) chip(gtx layout.Context, btn *widget.Clickable, text string, selected bool) layout.Dimensions {
	bg, fg := pal.Card, pal.Text
	var border color.NRGBA
	if selected {
		bg, fg = pal.PrimaryLite, pal.PrimaryText
	} else {
		border = pal.Border
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
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
	})
}

// radioRow is a settings language row: ring + dot when selected.
func (a *App) radioRow(gtx layout.Context, btn *widget.Clickable, text string, selected bool) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7)}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						d := gtx.Dp(unit.Dp(19))
						ring := pal.Hint
						if selected {
							ring = pal.Primary
						}
						paint.FillShape(gtx.Ops, ring, clip.Stroke{
							Path:  clip.Ellipse(image.Rect(0, 0, d, d)).Path(gtx.Ops),
							Width: float32(gtx.Dp(unit.Dp(2))),
						}.Op())
						if selected {
							dd := gtx.Dp(unit.Dp(9))
							off := (d - dd) / 2
							paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(off, off, off+dd, off+dd)).Op(gtx.Ops))
						}
						return layout.Dimensions{Size: image.Pt(d, d)}
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
					layout.Flexed(1, a.lbl(14, font.Normal, pal.Text, text).Layout),
				)
			})
	})
}

// radioDescRow is a settings option row in the reference
// style: radio ring + title + one line of plain-language
// description under it. Disabled rows (a choice the platform
// cannot honor) render dimmed with a reason line instead of
// the description, and are not clickable — a listed-but-honest
// absence, never a dead switch.
func (a *App) radioDescRow(gtx layout.Context, btn *widget.Clickable, title, desc, reason string, selected, enabled bool) layout.Dimensions {
	content := func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8)}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				titleCol, descCol := pal.Text, pal.Secondary
				if !enabled {
					titleCol, descCol = pal.Disabled, pal.Disabled
				}
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(2)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							d := gtx.Dp(unit.Dp(19))
							ring := pal.Hint
							if !enabled {
								ring = pal.Disabled
							} else if selected {
								ring = pal.Primary
							}
							paint.FillShape(gtx.Ops, ring, clip.Stroke{
								Path:  clip.Ellipse(image.Rect(0, 0, d, d)).Path(gtx.Ops),
								Width: float32(gtx.Dp(unit.Dp(2))),
							}.Op())
							if selected && enabled {
								dd := gtx.Dp(unit.Dp(9))
								off := (d - dd) / 2
								paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(off, off, off+dd, off+dd)).Op(gtx.Ops))
							}
							return layout.Dimensions{Size: image.Pt(d, d)}
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
	if !enabled {
		return content(gtx)
	}
	return btn.Layout(gtx, content)
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

// eyeMark draws the brand mark of Step 3 direction 1 (two
// eyelid arcs converging on a solid pupil = the node): an eye
// outline stroked in the primary color, a ring pupil and a
// solid center dot. Never a realistic eyeball (mockup README).
func eyeMark(gtx layout.Context) layout.Dimensions {
	w := gtx.Dp(unit.Dp(34))
	h := gtx.Dp(unit.Dp(24))
	fw, fh := float32(w), float32(h)
	var p clip.Path
	p.Begin(gtx.Ops)
	// Upper lid: left corner -> top arc -> right corner.
	p.MoveTo(f32.Point{X: fw * 0.03, Y: fh * 0.5})
	p.QuadTo(f32.Point{X: fw * 0.5, Y: -fh * 0.42}, f32.Point{X: fw * 0.97, Y: fh * 0.5})
	// Lower lid: right corner -> bottom arc -> left corner.
	p.QuadTo(f32.Point{X: fw * 0.5, Y: fh * 1.42}, f32.Point{X: fw * 0.03, Y: fh * 0.5})
	stroke := clip.Stroke{Path: p.End(), Width: float32(gtx.Dp(unit.Dp(2.2)))}
	paint.FillShape(gtx.Ops, pal.Primary, stroke.Op())
	// Pupil ring.
	rd := gtx.Dp(unit.Dp(11))
	off := image.Pt((w-rd)/2, (h-rd)/2)
	paint.FillShape(gtx.Ops, pal.Primary, clip.Stroke{
		Path:  clip.Ellipse(image.Rect(off.X, off.Y, off.X+rd, off.Y+rd)).Path(gtx.Ops),
		Width: float32(gtx.Dp(unit.Dp(2))),
	}.Op())
	// Pupil dot (the node everything converges on).
	dd := gtx.Dp(unit.Dp(4))
	off2 := image.Pt((w-dd)/2, (h-dd)/2)
	paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(off2.X, off2.Y, off2.X+dd, off2.Y+dd)).Op(gtx.Ops))
	return layout.Dimensions{Size: image.Pt(w, h)}
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

// optionGroup is one settings option rendered as a group: the
// radio, title and description share one column, the whole
// group is tinted when selected, and a disabled option's
// reason line sits INSIDE the group directly under its
// description (teardown settings pattern: a reason must never
// drift away from the option it belongs to).
func (a *App) optionGroup(gtx layout.Context, btn *widget.Clickable, selected, enabled bool, title, desc, reason string) layout.Dimensions {
	content := func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: unit.Dp(1)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return a.radio(gtx, selected, enabled)
					})
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					rows := []layout.FlexChild{
						layout.Rigid(a.lbl(15, font.Bold, ternary(enabled, pal.Text, pal.Disabled), title).Layout),
						layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
						layout.Rigid(a.lblWrap(13, 18, font.Normal, ternary(enabled, pal.Secondary, pal.Disabled), desc, 3).Layout),
					}
					if reason != "" {
						rows = append(rows,
							layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, iconWarn, 14, pal.Warn)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
									layout.Flexed(1, a.lblWrap(12.5, 17, font.Normal, pal.Warn, reason, 2).Layout),
								)
							}),
						)
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
				}),
			)
		})
	}
	clickable := func(gtx layout.Context) layout.Dimensions {
		if enabled {
			return material.Clickable(gtx, btn, content)
		}
		return content(gtx)
	}
	// Every group is a card (mockup 03): the selected one is
	// tinted, the rest sit on the card surface with a border.
	// The Expanded child takes the Stacked child's size, so
	// the fill covers exactly the group's bounds.
	bg := pal.Card
	if selected {
		bg = pal.PrimaryLite
	}
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			sz := gtx.Constraints.Min
			fillRRect(gtx, sz, 10, bg)
			strokeRRect(gtx, sz, 10, pal.Border)
			return layout.Dimensions{Size: sz}
		}),
		layout.Stacked(clickable),
	)
}

// radio draws the settings radio circle in the active palette
// (22dp ring, 11dp dot; same drawing idiom as radioDescRow).
func (a *App) radio(gtx layout.Context, selected, enabled bool) layout.Dimensions {
	d := gtx.Dp(unit.Dp(22))
	size := image.Pt(d, d)
	ring := pal.Hint
	if !enabled {
		ring = pal.Disabled
	} else if selected {
		ring = pal.Primary
	}
	paint.FillShape(gtx.Ops, ring, clip.Stroke{
		Path:  clip.Ellipse(image.Rect(0, 0, d, d)).Path(gtx.Ops),
		Width: float32(gtx.Dp(unit.Dp(2))),
	}.Op())
	if selected {
		dd := gtx.Dp(unit.Dp(11))
		off := (d - dd) / 2
		c := pal.Primary
		if !enabled {
			c = pal.Disabled
		}
		paint.FillShape(gtx.Ops, c, clip.Ellipse(image.Rect(off, off, off+dd, off+dd)).Op(gtx.Ops))
	}
	return layout.Dimensions{Size: size}
}

// swatch draws one background-tier swatch in the settings page:
// a 56x40 mini-UI (background, a card strip, an accent bar)
// rendered in the tier's own palette, with a 2dp outer ring in
// the primary color and a check badge when selected. The
// "system" tier passes split=true and shows light on the left
// half, navy on the right.
func (a *App) swatch(gtx layout.Context, p Palette, split bool, selected bool) layout.Dimensions {
	w := gtx.Dp(unit.Dp(56))
	h := gtx.Dp(unit.Dp(40))
	size := image.Pt(w, h)
	drawHalf := func(x0, x1 int, pp Palette) {
		stack := clip.Rect{Min: image.Pt(x0, 0), Max: image.Pt(x1, h)}.Push(gtx.Ops)
		paint.FillShape(gtx.Ops, pp.Bg, clip.Rect{Min: image.Pt(0, 0), Max: size}.Op())
		card := image.Rect(gtx.Dp(unit.Dp(6)), gtx.Dp(unit.Dp(7)), w-gtx.Dp(unit.Dp(6)), gtx.Dp(unit.Dp(20)))
		paint.FillShape(gtx.Ops, pp.Card, clip.RRect{Rect: card, NE: 3, NW: 3, SE: 3, SW: 3}.Op(gtx.Ops))
		bar := image.Rect(gtx.Dp(unit.Dp(6)), gtx.Dp(unit.Dp(26)), gtx.Dp(unit.Dp(26)), gtx.Dp(unit.Dp(33)))
		paint.FillShape(gtx.Ops, pp.Primary, clip.RRect{Rect: bar, NE: 3, NW: 3, SE: 3, SW: 3}.Op(gtx.Ops))
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
		pad := gtx.Dp(unit.Dp(3))
		st := op.Offset(image.Pt(-pad, -pad)).Push(gtx.Ops)
		strokeRRect(gtx, image.Pt(w+2*pad, h+2*pad), 12, pal.Primary)
		st.Pop()
		bd := gtx.Dp(unit.Dp(16))
		st2 := op.Offset(image.Pt(w-bd/2, -bd/2)).Push(gtx.Ops)
		paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(0, 0, bd, bd)).Op(gtx.Ops))
		iconLayout(gtx, iconCheck, 10, pal.White)
		st2.Pop()
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
