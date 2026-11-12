package ui

import (
	"context"
	"fmt"
	"os"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"openproxy/core/kernel"

	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/service"
)

func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }

// --- Nodes tab -------------------------------------------------------

func (a *App) layoutNodes(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.layoutGroupBar),
		layout.Rigid(a.layoutActions),
		layout.Rigid(a.layoutRiskBanners),
		layout.Flexed(1, a.layoutNodeList),
	)
}

func (a *App) layoutGroupBar(gtx layout.Context) layout.Dimensions {
	groups := a.svc.Groups()
	return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{
			layout.Rigid(material.Body2(a.th, a.T("group.label", nil)).Layout),
			layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
			layout.Rigid(material.RadioButton(a.th, &a.groupEnum, "all", a.T("group.all", nil)).Layout),
		}
		for _, g := range groups {
			g := g
			children = append(children,
				layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
				layout.Rigid(material.RadioButton(a.th, &a.groupEnum, "g:"+g, g).Layout),
			)
		}
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
	})
}

func (a *App) layoutActions(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		running := a.svc.Status().State == kernel.StateRunning
		children := []layout.FlexChild{}
		if running {
			children = append(children, layout.Rigid(material.Button(a.th, &a.disconnectBtn, a.T("conn.disconnect", nil)).Layout))
		} else {
			children = append(children, layout.Rigid(material.Button(a.th, &a.connectBtn, a.T("conn.connect", nil)).Layout))
		}
		children = append(children,
			layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
			layout.Rigid(material.Button(a.th, &a.autoBtn, a.T("conn.auto_select", nil)).Layout),
			layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
			layout.Rigid(material.Button(a.th, &a.testAllBtn, a.T("conn.test_all", nil)).Layout),
		)
		if a.isBusy() {
			children = append(children,
				layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
				layout.Rigid(material.Body2(a.th, a.T("conn.testing", nil)).Layout),
			)
		}
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
	})
}

// layoutRiskBanners shows the full risk-disclosure text for the
// selected node when it carries a risk classification (book 9.3:
// in-product risk disclosure duty; the strings are the packs'
// risk.* entries, hand-translated in every shipped language).
func (a *App) layoutRiskBanners(gtx layout.Context) layout.Dimensions {
	id := a.svc.SelectedNodeID()
	if id == "" {
		return layout.Dimensions{}
	}
	view, ok := a.svc.NodeByID(id)
	if !ok {
		return layout.Dimensions{}
	}
	var keys []string
	if view.Weak {
		keys = append(keys, "risk.weak_encryption")
	}
	if view.Insecure {
		keys = append(keys, "risk.insecure_skip_verify")
	}
	if len(keys) == 0 {
		return layout.Dimensions{}
	}
	return layout.Inset{Left: unit.Dp(14), Right: unit.Dp(14), Top: unit.Dp(8)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			children := make([]layout.FlexChild, 0, len(keys))
			for _, key := range keys {
				key := key
				children = append(children, layout.Rigid(material.Body2(a.th, a.T(key, nil)).Layout))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
}

func (a *App) layoutNodeList(gtx layout.Context) layout.Dimensions {
	views := a.svc.Nodes(a.currentGroup())
	if len(views) == 0 {
		return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(16)}.Layout(gtx,
			material.Body1(a.th, a.T("node.empty", nil)).Layout)
	}
	return material.List(a.th, &a.nodeList).Layout(gtx, len(views), func(gtx layout.Context, i int) layout.Dimensions {
		return a.layoutNodeRow(gtx, views[i])
	})
}

func (a *App) layoutNodeRow(gtx layout.Context, view service.NodeView) layout.Dimensions {
	n := view.Record.Node
	btns := a.rowButtons(n.ID)
	// Row-level click handling happens here (during layout).
	if btns.selectBtn.Clicked(gtx) {
		a.svc.SelectNode(n.ID)
	}
	if btns.testBtn.Clicked(gtx) {
		id := n.ID
		a.runAsync(func(ctx context.Context) error {
			_, err := a.svc.TestNode(ctx, id)
			return err
		})
	}
	if btns.delBtn.Clicked(gtx) {
		a.svc.DeleteNode(n.ID)
	}
	selected := a.svc.SelectedNodeID() == n.ID
	return layout.Inset{Left: unit.Dp(14), Right: unit.Dp(14), Top: unit.Dp(6), Bottom: unit.Dp(6)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return material.Clickable(gtx, &btns.selectBtn, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								name := n.Name
								if selected {
									name += " ✓"
								}
								return material.Body1(a.th, name).Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return material.Caption(a.th, nodeSubtitle(a, view)).Layout(gtx)
							}),
						)
					})
				}),
				layout.Rigid(material.Button(a.th, &btns.testBtn, a.T("node.test", nil)).Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
				layout.Rigid(material.Button(a.th, &btns.delBtn, a.T("node.delete", nil)).Layout),
			)
		})
}

// nodeSubtitle builds the second line of a node row from data and
// localized fragments only.
func nodeSubtitle(a *App, view service.NodeView) string {
	n := view.Record.Node
	s := n.Protocol + " · " + n.Server + ":" + fmt.Sprint(n.Port)
	lt := n.LastTest
	switch {
	case lt == nil:
		s += " · " + a.T("node.untested", nil)
	case !lt.OK:
		s += " · " + a.T("node.test_failed", nil)
	case lt.LatencyMs != nil:
		s += " · " + a.T("node.latency", map[string]string{"ms": fmt.Sprintf("%.0f", *lt.LatencyMs)})
	}
	if view.Weak {
		s += " · ⚠ " + a.T("node.weak_badge", nil)
	}
	if view.Insecure {
		s += " · ⚠ " + a.T("node.insecure_badge", nil)
	}
	return s
}

func (a *App) rowButtons(id string) *rowButtons {
	b, ok := a.rowBtns[id]
	if !ok {
		b = &rowButtons{}
		a.rowBtns[id] = b
	}
	return b
}

// --- Import tab ------------------------------------------------------

func (a *App) layoutImport(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(14), Right: unit.Dp(14), Top: unit.Dp(8)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(material.H6(a.th, a.T("import.title", nil)).Layout),
				layout.Rigid(material.Body2(a.th, a.T("import.links_label", nil)).Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(140))
					ed := material.Editor(a.th, &a.linksEd, a.T("import.links_hint", nil))
					return ed.Layout(gtx)
				}),
				layout.Rigid(material.Button(a.th, &a.importBtn, a.T("import.from_text", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(material.Body2(a.th, a.T("import.url_label", nil)).Layout),
				layout.Rigid(material.Editor(a.th, &a.urlEd, a.T("import.url_hint", nil)).Layout),
				layout.Rigid(material.Button(a.th, &a.urlBtn, a.T("import.from_url", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(material.Body2(a.th, a.T("import.from_file", nil)).Layout),
				layout.Rigid(material.Editor(a.th, &a.fileEd, a.T("import.file_path_hint", nil)).Layout),
				layout.Rigid(material.Button(a.th, &a.fileBtn, a.T("common.ok", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					result := a.lastImportResult()
					if result == "" {
						return layout.Dimensions{}
					}
					return material.Body1(a.th, result).Layout(gtx)
				}),
				layout.Rigid(material.Caption(a.th, a.T("warn.weak_auto_note", nil)).Layout),
			)
		})
}

// --- Logs tab --------------------------------------------------------

func (a *App) layoutLogs(gtx layout.Context) layout.Dimensions {
	lines := a.svc.Logs().Lines()
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(8)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(material.H6(a.th, a.T("log.title", nil)).Layout),
						layout.Flexed(1, layout.Spacer{}.Layout),
						layout.Rigid(material.Button(a.th, &a.clearLog, a.T("log.clear", nil)).Layout),
					)
				})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(lines) == 0 {
				return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(12)}.Layout(gtx,
					material.Body2(a.th, a.T("log.empty", nil)).Layout)
			}
			return material.List(a.th, &a.logList).Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(2), Bottom: unit.Dp(2)}.Layout(gtx,
					material.Caption(a.th, lines[i]).Layout)
			})
		}),
	)
}

// --- Settings tab ------------------------------------------------------

func (a *App) layoutSettings(gtx layout.Context) layout.Dimensions {
	caps := a.svc.Capabilities()
	state := func(ok bool) string {
		if ok {
			return a.T("cap.available", nil)
		}
		return a.T("cap.unavailable", nil)
	}
	return layout.Inset{Left: unit.Dp(14), Right: unit.Dp(14), Top: unit.Dp(8)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			children := []layout.FlexChild{
				layout.Rigid(material.H6(a.th, a.T("settings.title", nil)).Layout),
				layout.Rigid(material.Body1(a.th, a.T("settings.language", nil)).Layout),
			}
			for _, lang := range a.languages() {
				lang := lang
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// The language's own name comes from its pack.
					name := lang
					if p, err := packName(lang); err == nil {
						name = p
					}
					return material.RadioButton(a.th, &a.langEnum, lang, name).Layout(gtx)
				}))
			}
			children = append(children,
				layout.Rigid(material.Caption(a.th, a.T("settings.language_note", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(material.H6(a.th, a.T("cap.title", nil)).Layout),
				layout.Rigid(material.Body2(a.th, a.T("cap.kernel", map[string]string{
					"id": caps.KernelID, "version": caps.KernelVersion,
				})).Layout),
				layout.Rigid(material.Body2(a.th, a.T("cap.platform", map[string]string{
					"platform": caps.Platform.Platform,
				})).Layout),
				layout.Rigid(material.Body2(a.th, a.T("cap.tun", map[string]string{
					"state": state(caps.Platform.TUN),
				})).Layout),
				layout.Rigid(material.Body2(a.th, a.T("cap.system_proxy", map[string]string{
					"state": state(caps.Platform.SystemProxy),
				})).Layout),
				layout.Rigid(material.Body2(a.th, a.T("cap.kill_switch", map[string]string{
					"state": state(caps.Platform.KillSwitch),
				})).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(material.Body2(a.th, a.T("mode.capability_note", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(material.Body2(a.th, a.T("risk.node_trust", nil)).Layout),
			)
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
}

// packName loads a pack's self-name (lang.name) for the language
// radio list, so each language is labeled in its own script.
func packName(lang string) (string, error) {
	p, err := i18n.LoadPack(locales.FS, lang)
	if err != nil {
		return "", err
	}
	return p.Messages["lang.name"], nil
}

// Ensure the widget import is used even if widget sets change.
var _ = widget.Clickable{}
