package ui

// Country resolution and flag icons for node rows (2026-11-14
// design ruling): every row leads with an icon image — the
// country flag when the node's country is actually known, the
// protocol tile otherwise. The country is only ever taken from
// data the node itself carries — a VPN Gate pool node's
// country field (its group / its [XX] name tag), or a flag
// emoji / country name the user put in their own node's name.
// Nothing is inferred from the server address and no country is
// ever invented: unknown means protocol tile.
//
// The name tables live in data/names.json (data, not UI copy:
// country names are lookup keys, never rendered as interface
// text). Flags are drawn procedurally with faithful base
// geometry (bands, crosses, discs, cantons, stars) for the
// countries in the recipe table; an ISO code without a recipe
// gets a neutral code tile — never a wrong flag.

import (
	_ "embed"
	"encoding/json"
	"image"
	"image/color"
	"sort"
	"strings"

	"gioui.org/f32"
	"gioui.org/op"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"

	"openproxy/app/service"
)

//go:embed data/names.json
var namesJSON []byte

var (
	countryByName map[string]string   // country name (EN/CN/local) -> ISO
	nameKeys      []string            // countryByName keys, longest first
	protocolShort map[string]string   // protocol -> tile text
	knownISO      map[string]bool     // ISO codes we may resolve to
)

func init() {
	var data struct {
		Countries map[string]string `json:"countries"`
		Protocols map[string]string `json:"protocols"`
		ISOCodes  []string          `json:"isoCodes"`
	}
	if err := json.Unmarshal(namesJSON, &data); err != nil {
		panic("ui: names.json: " + err.Error())
	}
	countryByName = data.Countries
	protocolShort = data.Protocols
	knownISO = map[string]bool{}
	for _, c := range data.ISOCodes {
		knownISO[c] = true
	}
	nameKeys = make([]string, 0, len(countryByName))
	for k := range countryByName {
		nameKeys = append(nameKeys, k)
	}
	sort.Slice(nameKeys, func(i, j int) bool { return len(nameKeys[i]) > len(nameKeys[j]) })
}

func f32Pt(x, y float32) f32.Point { return f32.Point{X: x, Y: y} }

// nodeCountryISO resolves the node's country code from its own
// data only (see the file comment). The second return value is
// false when no country is known.
func nodeCountryISO(view service.NodeView) (string, bool) {
	name := view.Record.Node.Name
	// 1. A flag emoji in the name: two regional indicators.
	if iso, ok := flagEmojiISO(name); ok {
		return iso, true
	}
	// 2. A bracketed [XX] tag (the VPN Gate name format, also
	// common in subscription node names).
	if iso, ok := bracketISO(name); ok {
		return iso, true
	}
	// 3. Pool nodes: the group IS the source's country field
	// (CountryLong, e.g. "Croatia (LOCAL Name: Hrvatska)").
	if view.VPNGate {
		if iso, ok := countryNameISO(view.Record.Node.Group); ok {
			return iso, true
		}
	}
	// 4. A country name written in the node name itself.
	if iso, ok := countryNameISO(name); ok {
		return iso, true
	}
	return "", false
}

// flagEmojiISO extracts the ISO code from the first regional
// indicator pair in s.
func flagEmojiISO(s string) (string, bool) {
	var first rune
	for _, r := range s {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if first == 0 {
				first = r
				continue
			}
			iso := string([]byte{
				byte('A' + (first - 0x1F1E6)),
				byte('A' + (r - 0x1F1E6)),
			})
			if knownISO[iso] {
				return iso, true
			}
			return "", false
		}
		first = 0
	}
	return "", false
}

// bracketISO extracts a validated [XX] tag from s.
func bracketISO(s string) (string, bool) {
	for i := 0; i+3 < len(s); i++ {
		if s[i] == '[' && s[i+3] == ']' {
			c := s[i+1 : i+3]
			if c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' && knownISO[c] {
				return c, true
			}
		}
	}
	return "", false
}

// countryNameISO matches the longest known country name inside
// s (the group form "Croatia (LOCAL Name: Hrvatska)" matches
// both "Croatia" and "Hrvatska"; the first key in length order
// that appears wins).
func countryNameISO(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	for _, k := range nameKeys {
		if strings.Contains(s, k) {
			return countryByName[k], true
		}
	}
	return "", false
}

// --- Flag tile -------------------------------------------------------

// flagIconLayout draws the row's leading icon: the flag for the
// resolved country, an ISO code tile for a known country
// without a drawn recipe, or the protocol tile when no country
// is known.
func (a *App) flagIconLayout(gtx layout.Context, view service.NodeView) layout.Dimensions {
	w := gtx.Dp(unit.Dp(46))
	h := gtx.Dp(unit.Dp(34))
	size := image.Pt(w, h)
	iso, ok := nodeCountryISO(view)
	if !ok {
		// Protocol tile.
		return layout.Stack{Alignment: layout.Center}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				fillRRect(gtx, size, 6, colPrimaryLite)
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				short := protocolShort[view.Record.Node.Protocol]
				if short == "" {
					short = strings.ToUpper(view.Record.Node.Protocol)
					if len(short) > 6 {
						short = short[:6]
					}
				}
				return a.lbl(10.5, font.Bold, colPrimaryDark, short).Layout(gtx)
			}),
		)
	}
	if !hasFlagRecipe(iso) {
		// Known country, no drawn recipe: neutral code tile.
		return layout.Stack{Alignment: layout.Center}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				fillRRect(gtx, size, 6, colPrimaryLite)
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return a.lbl(13, font.Bold, colPrimaryDark, iso).Layout(gtx)
			}),
		)
	}
	r := gtx.Dp(unit.Dp(6))
	rr := clip.RRect{
		Rect: image.Rect(0, 0, w, h),
		NE:   r, NW: r, SE: r, SW: r,
	}
	defer rr.Push(gtx.Ops).Pop()
	p := &flagPainter{gtx: gtx, w: float32(w), h: float32(h)}
	paintFlag(p, iso)
	// Hairline border over the flag so light flags (JP, PL)
	// keep a defined edge on the page background.
	strokeRRect(gtx, size, 6, colBorder)
	return layout.Dimensions{Size: size}
}

// flagPainter paints in tile-fraction coordinates: x and y in
// 0..1 across the tile, radii as fractions of the tile height.
type flagPainter struct {
	gtx layout.Context
	w   float32
	h   float32
}

func (p *flagPainter) rect(x, y, w, h float32, col color.NRGBA) {
	paint.FillShape(p.gtx.Ops, col, clip.Rect{
		Min: image.Pt(int(x*p.w), int(y*p.h)),
		Max: image.Pt(int((x+w)*p.w), int((y+h)*p.h)),
	}.Op())
}

func (p *flagPainter) disc(cx, cy, r float32, col color.NRGBA) {
	rp := r * p.h
	paint.FillShape(p.gtx.Ops, col, clip.Ellipse(image.Rect(
		int(cx*p.w-rp), int(cy*p.h-rp), int(cx*p.w+rp), int(cy*p.h+rp),
	)).Op(p.gtx.Ops))
}

// halfDisc paints the top or bottom half of a disc (KR).
func (p *flagPainter) halfDisc(cx, cy, r float32, col color.NRGBA, top bool) {
	y0 := int(cy * p.h)
	if top {
		defer clip.Rect{Min: image.Pt(0, 0), Max: image.Pt(int(p.w), y0)}.Push(p.gtx.Ops).Pop()
	} else {
		defer clip.Rect{Min: image.Pt(0, y0), Max: image.Pt(int(p.w), int(p.h))}.Push(p.gtx.Ops).Pop()
	}
	p.disc(cx, cy, r, col)
}

func (p *flagPainter) star(cx, cy, r float32, col color.NRGBA) {
	paint.FillShape(p.gtx.Ops, col, clip.Outline{Path: starPath(p.gtx.Ops, cx*p.w, cy*p.h, r*p.h)}.Op())
}

func starPath(ops *op.Ops, cx, cy, r float32) clip.PathSpec {
	var path clip.Path
	path.Begin(ops)
	for i := 0; i < 10; i++ {
		a := -1.5708 + float32(i)*0.6283
		rr := r
		if i%2 == 1 {
			rr = r * 0.42
		}
		x, y := cx+rr*cosf(a), cy+rr*sinf(a)
		if i == 0 {
			path.MoveTo(f32Pt(x, y))
		} else {
			path.LineTo(f32Pt(x, y))
		}
	}
	path.Close()
	return path.End()
}

// crescent paints a crescent: a disc in col masked by the field
// color offset toward +x.
func (p *flagPainter) crescent(cx, cy, r float32, col, field color.NRGBA) {
	p.disc(cx, cy, r, col)
	p.disc(cx+r*0.42, cy, r*0.88, field)
}

// hBands paints horizontal bands with the given relative
// heights and colors.
func (p *flagPainter) hBands(rel []float32, cols []color.NRGBA) {
	var total float32
	for _, v := range rel {
		total += v
	}
	y := float32(0)
	for i, v := range rel {
		hh := v / total
		p.rect(0, y, 1, hh+0.002, cols[i])
		y += hh
	}
}

// vBands paints vertical bands with the given relative widths.
func (p *flagPainter) vBands(rel []float32, cols []color.NRGBA) {
	var total float32
	for _, v := range rel {
		total += v
	}
	x := float32(0)
	for i, v := range rel {
		ww := v / total
		p.rect(x, 0, ww+0.002, 1, cols[i])
		x += ww
	}
}

// nordic paints a Nordic cross: background, then the cross
// (vertical arm at x=0.32 of the width, both arms 0.18 of the
// height thick); an optional inner cross color is drawn on top
// at 0.6 thickness.
func (p *flagPainter) nordic(bg, cross color.NRGBA, inner color.NRGBA) {
	p.rect(0, 0, 1, 1, bg)
	t := 0.18 * p.h / p.w // vertical arm thickness as x fraction
	p.rect(0.32-t/2, 0, t, 1, cross)
	p.rect(0, 0.5-0.09, 1, 0.18, cross)
	if inner.A != 0 {
		t2 := t * 0.55
		p.rect(0.32-t2/2, 0, t2, 1, inner)
		p.rect(0, 0.5-0.05, 1, 0.10, inner)
	}
}

// canton paints the top-left canton (width and height as tile
// fractions).
func (p *flagPainter) canton(w, h float32, col color.NRGBA) {
	p.rect(0, 0, w, h, col)
}

// triangle paints a left-pointing hoist triangle reaching x=w.
func (p *flagPainter) triangle(w float32, col color.NRGBA) {
	var path clip.Path
	path.Begin(p.gtx.Ops)
	path.MoveTo(f32Pt(0, 0))
	path.LineTo(f32Pt(w*p.w, p.h/2))
	path.LineTo(f32Pt(0, p.h))
	path.Close()
	paint.FillShape(p.gtx.Ops, col, clip.Outline{Path: path.End()}.Op())
}

// polygon fills an arbitrary polygon given in tile fractions.
func (p *flagPainter) polygon(pts [][2]float32, col color.NRGBA) {
	var path clip.Path
	path.Begin(p.gtx.Ops)
	for i, pt := range pts {
		if i == 0 {
			path.MoveTo(f32Pt(pt[0]*p.w, pt[1]*p.h))
		} else {
			path.LineTo(f32Pt(pt[0]*p.w, pt[1]*p.h))
		}
	}
	path.Close()
	paint.FillShape(p.gtx.Ops, col, clip.Outline{Path: path.End()}.Op())
}
