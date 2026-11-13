package ui

// Procedural flag recipes (companion to country.go). Each
// recipe paints the flag's faithful base geometry at tile size:
// band orders and colors, crosses, discs, cantons and simple
// emblems. Flags whose real design needs artwork beyond base
// geometry (coats of arms, calligraphy, complex crests) are
// deliberately absent — those countries get the ISO code tile
// instead of an approximation that would misstate the flag.

import "image/color"

func fc(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }

var (
	flWhite  = fc(0xFF, 0xFF, 0xFF)
	flBlack  = fc(0x1A, 0x1A, 0x1A)
	flRed    = fc(0xD2, 0x10, 0x2E)
	flBlue   = fc(0x00, 0x2A, 0x6B)
	flGold   = fc(0xFF, 0xD5, 0x00)
	flGreen  = fc(0x00, 0x7A, 0x3D)
	flSky    = fc(0x74, 0xAC, 0xDF)
	flOrange = fc(0xFF, 0x88, 0x3E)
)

func hasFlagRecipe(iso string) bool {
	switch iso {
	case "JP", "KR", "CN", "HK", "TW", "SG", "US", "GB", "CA",
		"DE", "BE", "FR", "IT", "NL", "RU", "AT", "CH", "ES", "PT",
		"SE", "DK", "NO", "FI", "IS", "PL", "ID", "TH", "VN", "IN",
		"PK", "TR", "AE", "IL", "EG", "NG", "BR", "MX", "AR", "AU",
		"NZ", "UA", "CZ", "HU", "RO", "BG", "HR", "GR", "KZ", "UZ",
		"MN", "PH", "MY", "KH", "LA", "MM", "BD", "CL", "CO", "PE",
		"UY", "RS", "SK", "IE", "LV", "LT", "EE", "MD", "GE", "AM",
		"AZ", "CR", "CU", "QA", "SA", "OM", "JO", "LB", "MA", "TN",
		"PY", "BO":
		return true
	}
	return false
}

func paintFlag(p *flagPainter, iso string) {
	switch iso {
	case "JP":
		p.rect(0, 0, 1, 1, flWhite)
		p.disc(0.5, 0.5, 0.30, fc(0xBC, 0x00, 0x2D))
	case "KR":
		p.rect(0, 0, 1, 1, flWhite)
		p.halfDisc(0.5, 0.5, 0.30, fc(0xCD, 0x2E, 0x3A), true)
		p.halfDisc(0.5, 0.5, 0.30, fc(0x00, 0x47, 0xA0), false)
	case "CN":
		p.rect(0, 0, 1, 1, fc(0xDE, 0x29, 0x10))
		p.star(0.27, 0.32, 0.17, fc(0xFF, 0xDE, 0x00))
		for _, d := range [][2]float32{{0.47, 0.14}, {0.52, 0.28}, {0.52, 0.44}, {0.47, 0.58}} {
			p.disc(d[0], d[1], 0.045, fc(0xFF, 0xDE, 0x00))
		}
	case "HK":
		p.rect(0, 0, 1, 1, fc(0xFF, 0x00, 0x00))
		// Bauhinia as five petals around a center.
		p.disc(0.5, 0.5, 0.10, flWhite)
		for i := 0; i < 5; i++ {
			a := float32(i) * 1.2566
			p.disc(0.5+0.15*cosf(a)/1.35, 0.5+0.15*sinf(a), 0.085, flWhite)
		}
	case "TW":
		p.rect(0, 0, 1, 1, fc(0xFE, 0x00, 0x00))
		p.canton(0.5, 0.5, fc(0x00, 0x00, 0x95))
		p.disc(0.25, 0.25, 0.12, flWhite)
	case "SG":
		p.hBands([]float32{1, 1}, []color.NRGBA{fc(0xEF, 0x33, 0x40), flWhite})
		p.crescent(0.20, 0.25, 0.115, flWhite, fc(0xEF, 0x33, 0x40))
		for _, d := range [][2]float32{{0.335, 0.16}, {0.36, 0.25}, {0.335, 0.34}, {0.29, 0.20}, {0.29, 0.30}} {
			p.disc(d[0], d[1], 0.018, flWhite)
		}
	case "US":
		p.hBands([]float32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]color.NRGBA{fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34), flWhite, fc(0xB2, 0x22, 0x34)})
		p.canton(0.42, 7.0/13.0, fc(0x3C, 0x3B, 0x6E))
		for r := 0; r < 4; r++ {
			for c := 0; c < 5; c++ {
				p.disc(0.05+float32(c)*0.085, 0.08+float32(r)*0.12, 0.020, flWhite)
			}
		}
	case "GB":
		p.rect(0, 0, 1, 1, fc(0x01, 0x21, 0x69))
		// White saltire (diagonals), then the cross of St George.
		p.polygon([][2]float32{{0, 0}, {0.14, 0}, {1, 1}, {0.86, 1}}, flWhite)
		p.polygon([][2]float32{{1, 0}, {0.86, 0}, {0, 1}, {0.14, 1}}, flWhite)
		t := 0.30 * p.h / p.w
		p.rect(0.5-t/2, 0, t, 1, flWhite)
		p.rect(0, 0.5-0.15, 1, 0.30, flWhite)
		t = 0.18 * p.h / p.w
		p.rect(0.5-t/2, 0, t, 1, fc(0xC8, 0x10, 0x2E))
		p.rect(0, 0.5-0.09, 1, 0.18, fc(0xC8, 0x10, 0x2E))
	case "CA":
		p.vBands([]float32{1, 2, 1}, []color.NRGBA{fc(0xFF, 0x00, 0x00), flWhite, fc(0xFF, 0x00, 0x00)})
		// Stylized maple leaf silhouette.
		p.polygon([][2]float32{
			{0.50, 0.14}, {0.545, 0.29}, {0.60, 0.20}, {0.615, 0.35}, {0.685, 0.30},
			{0.645, 0.45}, {0.725, 0.50}, {0.605, 0.565}, {0.62, 0.69}, {0.545, 0.61},
			{0.53, 0.80}, {0.47, 0.80}, {0.455, 0.61}, {0.38, 0.69}, {0.395, 0.565},
			{0.275, 0.50}, {0.355, 0.45}, {0.315, 0.30}, {0.385, 0.35}, {0.40, 0.20},
			{0.455, 0.29},
		}, fc(0xFF, 0x00, 0x00))
	case "DE":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flBlack, fc(0xDD, 0x00, 0x00), fc(0xFF, 0xCE, 0x00)})
	case "BE":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{flBlack, fc(0xFD, 0xDA, 0x24), fc(0xEF, 0x33, 0x40)})
	case "FR":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x55, 0xA4), flWhite, fc(0xEF, 0x41, 0x35)})
	case "IT":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x92, 0x46), flWhite, fc(0xCE, 0x2B, 0x37)})
	case "NL":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xAE, 0x1C, 0x28), flWhite, fc(0x21, 0x46, 0x8B)})
	case "RU":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flWhite, fc(0x00, 0x39, 0xA6), fc(0xD5, 0x2B, 0x1E)})
	case "AT":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xED, 0x29, 0x39), flWhite, fc(0xED, 0x29, 0x39)})
	case "CH":
		p.rect(0, 0, 1, 1, fc(0xFF, 0x00, 0x00))
		t := 0.20 * p.h / p.w
		p.rect(0.5-t/2, 0.5-0.26, t, 0.52, flWhite)
		p.rect(0.5-0.26*p.h/p.w, 0.5-0.10, 0.52*p.h/p.w, 0.20, flWhite)
	case "ES":
		p.hBands([]float32{1, 2, 1}, []color.NRGBA{fc(0xAA, 0x15, 0x1B), fc(0xF1, 0xBF, 0x00), fc(0xAA, 0x15, 0x1B)})
	case "PT":
		p.vBands([]float32{2, 3}, []color.NRGBA{fc(0x04, 0x6A, 0x38), fc(0xDA, 0x29, 0x1C)})
		p.disc(0.4, 0.5, 0.17, fc(0xFF, 0xDF, 0x00))
	case "SE":
		p.nordic(fc(0x00, 0x6A, 0xA7), fc(0xFE, 0xCC, 0x00), color.NRGBA{})
	case "DK":
		p.nordic(fc(0xC8, 0x10, 0x2E), flWhite, color.NRGBA{})
	case "NO":
		p.nordic(fc(0x00, 0x28, 0x5E), flWhite, fc(0xBA, 0x0C, 0x2F))
	case "FI":
		p.nordic(flWhite, fc(0x00, 0x2F, 0x6C), color.NRGBA{})
	case "IS":
		p.nordic(fc(0x02, 0x52, 0x9C), flWhite, fc(0xDC, 0x1E, 0x35))
	case "PL":
		p.hBands([]float32{1, 1}, []color.NRGBA{flWhite, fc(0xDC, 0x14, 0x3C)})
	case "ID":
		p.hBands([]float32{1, 1}, []color.NRGBA{fc(0xE7, 0x00, 0x11), flWhite})
	case "TH":
		p.hBands([]float32{1, 1, 2, 1, 1}, []color.NRGBA{fc(0xA5, 0x19, 0x31), flWhite, fc(0x2D, 0x2A, 0x4A), flWhite, fc(0xA5, 0x19, 0x31)})
	case "VN":
		p.rect(0, 0, 1, 1, fc(0xDA, 0x25, 0x1D))
		p.star(0.5, 0.5, 0.22, fc(0xFF, 0xDE, 0x00))
	case "IN":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xFF, 0x99, 0x32), flWhite, fc(0x13, 0x88, 0x08)})
		p.disc(0.5, 0.5, 0.11, fc(0x00, 0x00, 0x80))
	case "PK":
		p.rect(0, 0, 1, 1, fc(0x01, 0x41, 0x1C))
		p.rect(0, 0, 0.25, 1, flWhite)
		p.crescent(0.60, 0.44, 0.17, flWhite, fc(0x01, 0x41, 0x1C))
		p.star(0.735, 0.26, 0.07, flWhite)
	case "TR":
		p.rect(0, 0, 1, 1, fc(0xE3, 0x0A, 0x17))
		p.crescent(0.40, 0.5, 0.21, flWhite, fc(0xE3, 0x0A, 0x17))
		p.star(0.655, 0.5, 0.105, flWhite)
	case "AE":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x73, 0x2F), flWhite, flBlack})
		p.rect(0, 0, 0.28, 1, fc(0xFF, 0x00, 0x00))
	case "IL":
		p.rect(0, 0, 1, 1, flWhite)
		p.rect(0, 0.10, 1, 0.13, fc(0x00, 0x38, 0xB8))
		p.rect(0, 0.77, 1, 0.13, fc(0x00, 0x38, 0xB8))
		// Star of David as two triangles (outline only).
		p.polygon([][2]float32{{0.5, 0.33}, {0.60, 0.53}, {0.40, 0.53}}, fc(0x00, 0x38, 0xB8))
		p.polygon([][2]float32{{0.5, 0.60}, {0.40, 0.40}, {0.60, 0.40}}, flWhite)
	case "EG":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xCE, 0x11, 0x26), flWhite, flBlack})
		p.disc(0.5, 0.5, 0.10, fc(0xC0, 0x93, 0x00))
	case "NG":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x87, 0x51), flWhite, fc(0x00, 0x87, 0x51)})
	case "BR":
		p.rect(0, 0, 1, 1, fc(0x00, 0x9C, 0x3B))
		p.polygon([][2]float32{{0.5, 0.08}, {0.90, 0.5}, {0.5, 0.92}, {0.10, 0.5}}, fc(0xFF, 0xDF, 0x00))
		p.disc(0.5, 0.5, 0.155, fc(0x00, 0x27, 0x76))
	case "MX":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x68, 0x47), flWhite, fc(0xCE, 0x11, 0x26)})
		p.disc(0.5, 0.5, 0.09, fc(0xC0, 0x93, 0x00))
	case "AR":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flSky, flWhite, flSky})
		p.disc(0.5, 0.5, 0.11, fc(0xF6, 0xB4, 0x0E))
	case "AU":
		p.rect(0, 0, 1, 1, fc(0x00, 0x24, 0x7D))
		p.canton(0.5, 0.5, fc(0x01, 0x21, 0x69))
		t := 0.09 * p.h / p.w
		p.rect(0.25-t/2, 0, t, 0.5, flWhite)
		p.rect(0, 0.25-0.045, 0.5, 0.09, flWhite)
		t = 0.055 * p.h / p.w
		p.rect(0.25-t/2, 0, t, 0.5, fc(0xC8, 0x10, 0x2E))
		p.rect(0, 0.25-0.028, 0.5, 0.055, fc(0xC8, 0x10, 0x2E))
		p.star(0.25, 0.76, 0.075, flWhite)
		p.disc(0.78, 0.28, 0.025, flWhite)
		p.disc(0.70, 0.55, 0.025, flWhite)
		p.disc(0.82, 0.72, 0.025, flWhite)
	case "NZ":
		p.rect(0, 0, 1, 1, fc(0x00, 0x24, 0x7D))
		p.canton(0.5, 0.5, fc(0x01, 0x21, 0x69))
		t := 0.09 * p.h / p.w
		p.rect(0.25-t/2, 0, t, 0.5, flWhite)
		p.rect(0, 0.25-0.045, 0.5, 0.09, flWhite)
		t = 0.055 * p.h / p.w
		p.rect(0.25-t/2, 0, t, 0.5, fc(0xC8, 0x10, 0x2E))
		p.rect(0, 0.25-0.028, 0.5, 0.055, fc(0xC8, 0x10, 0x2E))
		for _, d := range [][2]float32{{0.74, 0.18}, {0.80, 0.38}, {0.72, 0.58}, {0.80, 0.78}} {
			p.disc(d[0], d[1], 0.028, fc(0xCC, 0x14, 0x2B))
		}
	case "UA":
		p.hBands([]float32{1, 1}, []color.NRGBA{fc(0x00, 0x5B, 0xBB), fc(0xFF, 0xD5, 0x00)})
	case "CZ":
		p.hBands([]float32{1, 1}, []color.NRGBA{flWhite, fc(0xD7, 0x14, 0x1A)})
		p.triangle(0.45, fc(0x11, 0x45, 0x7E))
	case "HU":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xCE, 0x29, 0x39), flWhite, fc(0x47, 0x70, 0x50)})
	case "RO":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x2B, 0x7F), fc(0xFC, 0xD1, 0x16), fc(0xCE, 0x11, 0x26)})
	case "BG":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flWhite, fc(0x00, 0x96, 0x6E), fc(0xD6, 0x26, 0x12)})
	case "HR":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xFF, 0x00, 0x00), flWhite, fc(0x17, 0x17, 0x96)})
	case "GR":
		p.rect(0, 0, 1, 1, flWhite)
		for i := 0; i < 5; i++ {
			p.rect(0, float32(i)*2.0/9.0, 1, 1.0/9.0+0.002, fc(0x0D, 0x5E, 0xAF))
		}
		p.canton(0.36, 5.0/9.0, fc(0x0D, 0x5E, 0xAF))
		t := 0.10 * p.h / p.w
		p.rect(0.18-t/2, 0, t, 5.0/9.0, flWhite)
		p.rect(0, 2.0/9.0-0.05, 0.36, 0.10, flWhite)
	case "KZ":
		p.rect(0, 0, 1, 1, fc(0x00, 0xAF, 0xCA))
		p.disc(0.5, 0.44, 0.17, fc(0xFE, 0xC6, 0x00))
		p.rect(0.30, 0.68, 0.40, 0.07, fc(0xFE, 0xC6, 0x00))
	case "UZ":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x99, 0xB5), flWhite, fc(0x1E, 0xB5, 0x3A)})
	case "MN":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xDA, 0x29, 0x1C), fc(0x00, 0x66, 0xB3), fc(0xDA, 0x29, 0x1C)})
		p.disc(0.165, 0.35, 0.07, fc(0xFF, 0xD5, 0x00))
	case "PH":
		p.hBands([]float32{1, 1}, []color.NRGBA{fc(0x00, 0x38, 0xA8), fc(0xCE, 0x11, 0x26)})
		p.triangle(0.38, flWhite)
		p.disc(0.13, 0.5, 0.075, fc(0xF8, 0xD0, 0x00))
	case "MY":
		p.rect(0, 0, 1, 1, flWhite)
		for i := 0; i < 7; i++ {
			p.rect(0, float32(i)*2.0/14.0, 1, 1.0/14.0+0.002, fc(0xCC, 0x00, 0x01))
		}
		p.canton(0.52, 0.5, fc(0x01, 0x00, 0x66))
		p.crescent(0.17, 0.25, 0.11, fc(0xFF, 0xCC, 0x00), fc(0x01, 0x00, 0x66))
		p.star(0.36, 0.25, 0.085, fc(0xFF, 0xCC, 0x00))
	case "KH":
		p.hBands([]float32{1, 2, 1}, []color.NRGBA{fc(0x03, 0x2E, 0xA1), fc(0xE0, 0x00, 0x25), fc(0x03, 0x2E, 0xA1)})
		p.rect(0.40, 0.40, 0.20, 0.20, flWhite)
	case "LA":
		p.hBands([]float32{1, 2, 1}, []color.NRGBA{fc(0xCE, 0x11, 0x26), fc(0x00, 0x28, 0x68), fc(0xCE, 0x11, 0x26)})
		p.disc(0.5, 0.5, 0.15, flWhite)
	case "MM":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xFE, 0xCB, 0x00), fc(0x34, 0xB2, 0x33), fc(0xEA, 0x28, 0x39)})
		p.star(0.5, 0.5, 0.17, flWhite)
	case "BD":
		p.rect(0, 0, 1, 1, fc(0x00, 0x6A, 0x4E))
		p.disc(0.46, 0.5, 0.21, fc(0xF4, 0x2A, 0x41))
	case "CL":
		p.hBands([]float32{1, 1}, []color.NRGBA{flWhite, fc(0xD5, 0x2B, 0x1E)})
		p.canton(0.4, 0.5, fc(0x00, 0x38, 0xA8))
		p.star(0.2, 0.25, 0.09, flWhite)
	case "CO":
		p.hBands([]float32{2, 1, 1}, []color.NRGBA{fc(0xFC, 0xD1, 0x16), fc(0x00, 0x38, 0x93), fc(0xCE, 0x11, 0x26)})
	case "PE":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xD9, 0x10, 0x23), flWhite, fc(0xD9, 0x10, 0x23)})
	case "UY":
		p.rect(0, 0, 1, 1, flWhite)
		for i := 0; i < 2; i++ {
			p.rect(0, 0.28+float32(i)*0.36, 1, 0.11, fc(0x00, 0x38, 0xA8))
		}
		p.rect(0, 0, 0.42, 0.5, flWhite)
		p.disc(0.21, 0.25, 0.11, fc(0xF8, 0xD0, 0x00))
	case "RS":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xC6, 0x36, 0x3C), fc(0x0C, 0x40, 0x76), flWhite})
	case "SK":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flWhite, fc(0x0B, 0x4E, 0xA2), fc(0xEE, 0x1C, 0x25)})
	case "IE":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x16, 0x9B, 0x62), flWhite, flOrange})
	case "LV":
		p.hBands([]float32{2, 1, 2}, []color.NRGBA{fc(0x9D, 0x22, 0x35), flWhite, fc(0x9D, 0x22, 0x35)})
	case "LT":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xFD, 0xB9, 0x13), fc(0x00, 0x6A, 0x44), fc(0xC1, 0x27, 0x2D)})
	case "EE":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x72, 0xCE), flBlack, flWhite})
	case "MD":
		p.vBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0x46, 0xAE), fc(0xFF, 0xD1, 0x00), fc(0xCC, 0x09, 0x2F)})
		p.disc(0.5, 0.5, 0.09, fc(0x8B, 0x5A, 0x2B))
	case "GE":
		p.rect(0, 0, 1, 1, flWhite)
		t := 0.13 * p.h / p.w
		p.rect(0.5-t/2, 0.06, t, 0.88, fc(0xFF, 0x00, 0x00))
		p.rect(0.06, 0.5-0.065, 0.88, 0.13, fc(0xFF, 0x00, 0x00))
		for _, d := range [][2]float32{{0.26, 0.26}, {0.74, 0.26}, {0.26, 0.74}, {0.74, 0.74}} {
			p.disc(d[0], d[1], 0.045, fc(0xFF, 0x00, 0x00))
		}
	case "AM":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xD9, 0x00, 0x12), fc(0x00, 0x33, 0xA0), fc(0xF2, 0xA8, 0x00)})
	case "AZ":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0x00, 0xB5, 0xE2), fc(0xEF, 0x33, 0x40), fc(0x50, 0x9E, 0x2F)})
		p.crescent(0.47, 0.5, 0.10, flWhite, fc(0xEF, 0x33, 0x40))
		p.star(0.60, 0.5, 0.05, flWhite)
	case "CR":
		p.hBands([]float32{1, 1, 2, 1, 1}, []color.NRGBA{fc(0x00, 0x2B, 0x7F), flWhite, fc(0xCE, 0x11, 0x26), flWhite, fc(0x00, 0x2B, 0x7F)})
	case "CU":
		p.hBands([]float32{1, 1, 1, 1, 1}, []color.NRGBA{fc(0x00, 0x2A, 0x8F), flWhite, fc(0x00, 0x2A, 0x8F), flWhite, fc(0x00, 0x2A, 0x8F)})
		p.triangle(0.42, fc(0xCF, 0x14, 0x2B))
		p.star(0.15, 0.5, 0.09, flWhite)
	case "QA":
		p.vBands([]float32{3, 7}, []color.NRGBA{flWhite, fc(0x8A, 0x15, 0x38)})
	case "SA":
		p.rect(0, 0, 1, 1, fc(0x16, 0x5C, 0x34))
		p.rect(0.22, 0.38, 0.56, 0.09, flWhite)
		p.rect(0.30, 0.62, 0.40, 0.05, flWhite)
	case "OM":
		p.vBands([]float32{2, 5}, []color.NRGBA{fc(0xEF, 0x33, 0x40), flWhite})
		p.rect(0.285, 0.33, 0.715, 0.34, fc(0xEF, 0x33, 0x40))
		p.rect(0.285, 0.67, 0.715, 0.33, fc(0x00, 0x96, 0x39))
	case "JO":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{flBlack, flWhite, fc(0x00, 0x7A, 0x3D)})
		p.triangle(0.42, fc(0xCE, 0x11, 0x26))
		p.star(0.14, 0.5, 0.07, flWhite)
	case "LB":
		p.hBands([]float32{1, 2, 1}, []color.NRGBA{fc(0xED, 0x1C, 0x24), flWhite, fc(0xED, 0x1C, 0x24)})
		p.disc(0.5, 0.5, 0.11, fc(0x00, 0xA6, 0x51))
	case "MA":
		p.rect(0, 0, 1, 1, fc(0xC1, 0x27, 0x2D))
		p.star(0.5, 0.5, 0.14, fc(0x00, 0x6A, 0x44))
	case "TN":
		p.rect(0, 0, 1, 1, fc(0xE7, 0x00, 0x13))
		p.disc(0.5, 0.5, 0.20, flWhite)
		p.crescent(0.5, 0.5, 0.15, fc(0xE7, 0x00, 0x13), flWhite)
		p.star(0.53, 0.5, 0.07, fc(0xE7, 0x00, 0x13))
	case "PY":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xD5, 0x2B, 0x1E), flWhite, fc(0x00, 0x38, 0xA8)})
		p.disc(0.5, 0.5, 0.09, fc(0xF8, 0xD0, 0x00))
	case "BO":
		p.hBands([]float32{1, 1, 1}, []color.NRGBA{fc(0xD5, 0x2B, 0x1E), fc(0xF8, 0xD0, 0x00), fc(0x00, 0x7A, 0x3D)})
	}
}
