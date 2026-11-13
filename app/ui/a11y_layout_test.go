package ui

// Step 18 accessibility baseline, font-scaling slice: the whole
// shell (all four tabs, all three shipped languages) must lay
// out without panicking and without exceeding the window
// constraints at system font scales 1.0 / 1.3 / 2.0, at the
// desktop minimum size and at a phone size. This is a headless
// layout exercise — it proves the layout engine completes and
// respects constraints; visual overflow (clipped or
// overlapping glyphs) can only be judged on a real device and
// stays on the Step 15 real-machine checklist
// (docs/step18-本地化与无障碍基线.md).

import (
	"image"
	"path/filepath"
	"testing"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/service"
)

func TestLayoutFontScaling(t *testing.T) {
	store, err := service.OpenStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	svc := service.New(store, nil)

	// Seed one weak-cipher node and select it so the nodes tab
	// renders the longest risk banner (risk.weak_encryption).
	rep := svc.ImportText("ss://YWVzLTI1Ni1jZmI6dGVzdHBhc3M@192.0.2.1:8388#weak-node")
	if rep == nil || rep.OK() != 1 {
		t.Fatalf("seed import: %+v", rep)
	}
	views := svc.Nodes(service.AllGroups)
	if len(views) != 1 {
		t.Fatalf("seeded nodes = %d, want 1", len(views))
	}
	if !views[0].Weak {
		t.Fatal("seeded node is not classified weak; risk banner path untested")
	}
	svc.SelectNode(views[0].Record.Node.ID)

	sizes := []image.Point{{X: 640, Y: 420}, {X: 420, Y: 760}, {X: 360, Y: 640}}
	scales := []float32{1.0, 1.3, 2.0}
	for _, lang := range locales.Supported {
		tr, err := i18n.New(locales.FS, locales.Supported, lang, locales.Fallback)
		if err != nil {
			t.Fatalf("i18n.New(%s): %v", lang, err)
		}
		th := material.NewTheme()
		th.Shaper = text.NewShaper(text.WithCollection(FontCollection()))
		a := New(svc, tr, th)
		for tab := 0; tab < 4; tab++ {
			a.tab = tab
			for _, scale := range scales {
				for _, size := range sizes {
					var ops op.Ops
					gtx := layout.Context{
						Ops: &ops,
						Metric: unit.Metric{
							PxPerDp: 1,
							PxPerSp: scale,
						},
						Constraints: layout.Constraints{Max: size},
					}
					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Errorf("lang=%s tab=%d scale=%.1f size=%v: layout panicked: %v",
									lang, tab, scale, size, r)
							}
						}()
						dims := a.Layout(gtx)
						if dims.Size.X > size.X || dims.Size.Y > size.Y {
							t.Errorf("lang=%s tab=%d scale=%.1f size=%v: layout returned %v, exceeds constraints",
								lang, tab, scale, size, dims.Size)
						}
					}()
				}
			}
		}
	}
}
