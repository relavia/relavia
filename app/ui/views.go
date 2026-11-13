package ui

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"os"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
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
//
// Layout follows the v2 mockups (docs/ui-mockups/, 2026-11-14
// design rulings): a search box and a horizontally scrolling
// group-tab row on top; node rows in the reference form — flag
// (or protocol) icon, two text lines, a favorite star and the
// test/delete actions on a right rail. While connecting, the
// search/tab rows give way to the progress bar and (on TUN
// platforms) the consent banner; once connected, the connected
// node's card pins on top, followed by the traffic card (only
// where the engine exposes real counters) and the action row.
//
// Two layout rules from the real-device defects are structural
// here, not cosmetic: every text in a row is single-line with
// truncation (a width-starved label wrapping per-character is
// what exploded row heights and overlapped rows), and the
// group row lives in a bounded-height horizontal List so any
// number of long group names scrolls instead of squeezing.

func (a *App) layoutNodes(gtx layout.Context) layout.Dimensions {
	running := a.svc.Status().State == kernel.StateRunning
	connecting := a.isConnecting()
	children := []layout.FlexChild{}
	if connecting && !running {
		children = append(children, layout.Rigid(progressBarLayout))
		if a.svc.Mode() == kernel.ModeTUN {
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.layoutConsentBanner),
			)
		}
	} else {
		children = append(children,
			layout.Rigid(a.layoutSearchRow),
			layout.Rigid(a.layoutGroupTabs),
		)
	}
	if running {
		if id := a.connectedNodeID(); id != "" {
			if view, ok := a.svc.NodeByID(id); ok {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin)}.Layout(gtx,
							func(gtx layout.Context) layout.Dimensions {
								return a.layoutNodeRow(gtx, view, cardState{
									accent: colSuccess,
									pill:   a.T("status.connected", nil),
									pillBg: colSuccessBg, pillFg: colSuccess,
									pinned: true,
								})
							})
					}),
				)
			}
		}
		// Kick the async counter sample before the gate: the
		// gate needs a landed sample, and the sampler is the
		// only producer — calling it solely from inside the
		// card deadlocked the card into never appearing
		// (frame-probe finding, 2026-11-14).
		if a.svc.Capabilities().Features.TrafficStats {
			a.sampleTraffic()
		}
		if a.trafficAvailable() {
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				layout.Rigid(a.layoutTrafficCard),
			)
		}
	}
	children = append(children,
		layout.Rigid(a.layoutActions),
		layout.Rigid(a.layoutRiskBanners),
		layout.Flexed(1, a.layoutNodeList),
	)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// connectedNodeID identifies the node the running session is
// bound to: the engine-reported active node when there is one,
// otherwise the selected node (the only node the UI and shell
// connect paths ever start).
func (a *App) connectedNodeID() string {
	st := a.svc.Status()
	if st.State != kernel.StateRunning {
		return ""
	}
	if st.ActiveNodeID != "" {
		return st.ActiveNodeID
	}
	return a.svc.SelectedNodeID()
}

func (a *App) layoutConsentBanner(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return surface(gtx, colPrimary, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(a.lbl(14, font.Bold, colText, a.T("connect.consent_title", nil)).Layout),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl(12.5, font.Normal, colSecondary, a.T("connect.consent_body", nil)).Layout),
				)
			})
		})
}

func (a *App) layoutTrafficCard(gtx layout.Context) layout.Dimensions {
	// Refresh the counters for the next frame; the card shows
	// the last successful sample.
	a.sampleTraffic()
	stats := a.traffic()
	return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
				rows := []layout.FlexChild{
					layout.Rigid(a.lbl(12.5, font.Bold, colSecondary, a.T("traffic.session_title", nil)).Layout),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						half := func(gtx layout.Context, arrow, label string, bytes uint64) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(a.lbl(14, font.Normal, colSecondary, arrow+" "+label).Layout),
								layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
								layout.Rigid(a.lbl(15, font.Bold, colText, FormatBytes(bytes)).Layout),
							)
						}
						var up, down uint64
						if stats != nil {
							up, down = stats.UploadBytes, stats.DownloadBytes
						}
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return half(gtx, "↑", a.T("traffic.upload", nil), up)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return half(gtx, "↓", a.T("traffic.download", nil), down)
							}),
						)
					}),
				}
				if a.svc.Mode() == kernel.ModeTUN {
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(a.lbl(11.5, font.Normal, colHint, a.T("traffic.tun_note", nil)).Layout),
					)
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		})
}

// layoutSearchRow is the node search box (reference form: a
// rounded field with a search icon). It filters the list below
// by name / server / group, within the selected group tab.
func (a *App) layoutSearchRow(gtx layout.Context) layout.Dimensions {
	return layout.Inset{
		Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(10),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				fillRRect(gtx, size, dpBtnRad, colInputBg)
				strokeRRect(gtx, size, dpBtnRad, colBorder)
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(10), Right: unit.Dp(10), Top: unit.Dp(7), Bottom: unit.Dp(7)}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconSearch, 18, colHint)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								e := material.Editor(a.th, &a.searchEd, a.T("search.hint", nil))
								e.TextSize = unit.Sp(13.5)
								e.Color = colText
								e.HintColor = colHint
								e.SelectionColor = colPrimaryLite
								return e.Layout(gtx)
							}),
						)
					})
			}),
		)
	})
}

// layoutGroupTabs renders the group filter as a horizontally
// scrolling tab row of fixed height: any number of groups with
// any name length scrolls sideways instead of squeezing (the
// "Australia / Croatia (LOCAL Name: Hrvatska)" real-device
// explosion). Chips are single-line; a long name takes its
// natural width and scrolls off, it never wraps.
func (a *App) layoutGroupTabs(gtx layout.Context) layout.Dimensions {
	groups := a.svc.Groups()
	type tab struct{ value, label string }
	tabs := make([]tab, 0, len(groups)+1)
	tabs = append(tabs, tab{"all", a.T("group.all", nil)})
	for _, g := range groups {
		tabs = append(tabs, tab{"g:" + g, g})
	}
	return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(dpChipH + 4))
		gtx.Constraints.Min.Y = h
		gtx.Constraints.Max.Y = h
		return material.List(a.th, &a.groupList).Layout(gtx, len(tabs), func(gtx layout.Context, i int) layout.Dimensions {
			t := tabs[i]
			btn := a.groupButton(t.value)
			if btn.Clicked(gtx) {
				a.groupEnum.Value = t.value
				a.applyGroupSelection()
			}
			left := unit.Dp(0)
			if i == 0 {
				left = unit.Dp(dpMargin)
			}
			return layout.Inset{Left: left, Right: unit.Dp(6), Top: unit.Dp(2), Bottom: unit.Dp(2)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return a.chip(gtx, btn, t.label, a.groupEnum.Value == t.value)
				})
		})
	})
}

// filteredViews returns the node views for the current group
// tab, narrowed by the search box text when one is present.
func (a *App) filteredViews() []service.NodeView {
	views := a.svc.Nodes(a.currentGroup())
	q := strings.ToLower(strings.TrimSpace(a.searchEd.Text()))
	if q == "" {
		return views
	}
	out := views[:0]
	for _, v := range views {
		n := v.Record.Node
		if strings.Contains(strings.ToLower(n.Name), q) ||
			strings.Contains(strings.ToLower(n.Server), q) ||
			strings.Contains(strings.ToLower(n.Group), q) {
			out = append(out, v)
		}
	}
	return out
}

func (a *App) layoutActions(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(10)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			running := a.svc.Status().State == kernel.StateRunning
			disabled := a.isBusy() || a.isConnecting()
			children := []layout.FlexChild{}
			kind := btnOutline
			if disabled {
				kind = btnDisabled
			}
			switch {
			case running:
				k := btnDanger
				if disabled {
					k = btnDisabled
				}
				children = append(children, layout.Flexed(1.15, func(gtx layout.Context) layout.Dimensions {
					return a.bigButton(gtx, &a.disconnectBtn, iconPower, a.T("conn.disconnect", nil), k)
				}))
			case a.isConnecting():
				children = append(children, layout.Flexed(1.15, func(gtx layout.Context) layout.Dimensions {
					return a.bigButton(gtx, &a.connectBtn, iconPower, a.T("status.connecting", nil), btnDisabled)
				}))
			default:
				if _, unconnectable := a.selectedUnconnectable(); unconnectable {
					// The selected node's protocol family has
					// no connectable engine in this build (e.g.
					// OpenVPN pool nodes on Android, where the
					// process adapter cannot run): no connect
					// button, an honest reason instead. Import
					// and testing stay available.
					children = append(children, layout.Flexed(1.15, func(gtx layout.Context) layout.Dimensions {
						return a.lblMax(13, font.Normal, colWarn,
							a.T("node.openvpn_connect_unavailable", nil), 2).Layout(gtx)
					}))
				} else {
					k := btnPrimary
					if disabled {
						k = btnDisabled
					}
					children = append(children, layout.Flexed(1.15, func(gtx layout.Context) layout.Dimensions {
						return a.bigButton(gtx, &a.connectBtn, iconPower, a.T("conn.connect", nil), k)
					}))
				}
			}
			children = append(children,
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return a.bigButton(gtx, &a.autoBtn, iconTarget, a.T("conn.auto_select", nil), kind)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return a.bigButton(gtx, &a.testAllBtn, iconGauge, a.T("conn.test_all", nil), kind)
				}),
			)
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
	if view.VPNGate {
		// Book 7.3: pool nodes always carry their per-node
		// risk line while selected.
		keys = append(keys, "risk.vpngate.node_line")
	}
	if len(keys) == 0 {
		return layout.Dimensions{}
	}
	return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(dpCardGap)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			children := make([]layout.FlexChild, 0, len(keys)*2)
			for i, key := range keys {
				key := key
				if i > 0 {
					children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))
				}
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Stack{}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							size := gtx.Constraints.Min
							fillRRect(gtx, size, dpBtnRad, colWarnBg)
							return layout.Dimensions{Size: size}
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{
								Left: unit.Dp(12), Right: unit.Dp(12),
								Top: unit.Dp(9), Bottom: unit.Dp(9),
							}.Layout(gtx, a.lbl(12.5, font.Normal, colWarn, a.T(key, nil)).Layout)
						}),
					)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
}

// selectedUnconnectable returns the selected node view when a
// node is selected whose protocol family this build cannot
// connect (service.CanConnect is false for it).
func (a *App) selectedUnconnectable() (service.NodeView, bool) {
	id := a.svc.SelectedNodeID()
	if id == "" {
		return service.NodeView{}, false
	}
	view, ok := a.svc.NodeByID(id)
	if !ok {
		return service.NodeView{}, false
	}
	if a.svc.CanConnect(view.Record.Node.Protocol) {
		return service.NodeView{}, false
	}
	return view, true
}

// cardState carries the per-row presentation state: accent bar
// (pinned card), status pill, dimming and action visibility.
type cardState struct {
	accent      color.NRGBA // zero = no accent bar
	pill        string      // "" = no status pill
	pillBg      color.NRGBA
	pillFg      color.NRGBA
	dim         bool // another node is being connected
	hideActions bool // this row's own node is being connected
	pinned      bool // render as a surface card (connected node)
}

func (a *App) layoutNodeList(gtx layout.Context) layout.Dimensions {
	views := a.filteredViews()
	running := a.svc.Status().State == kernel.StateRunning
	connID := a.connectedNodeID()
	if running && connID != "" {
		rest := views[:0]
		for _, v := range views {
			if v.Record.Node.ID != connID {
				rest = append(rest, v)
			}
		}
		views = rest
	}
	if len(views) == 0 {
		if running {
			return layout.Dimensions{}
		}
		key := "node.empty"
		if strings.TrimSpace(a.searchEd.Text()) != "" {
			key = "search.empty"
		}
		return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(16)}.Layout(gtx,
			a.lbl(14, font.Normal, colSecondary, a.T(key, nil)).Layout)
	}
	connecting := a.isConnecting()
	selectedID := a.svc.SelectedNodeID()
	return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return material.List(a.th, &a.nodeList).Layout(gtx, len(views), func(gtx layout.Context, i int) layout.Dimensions {
			view := views[i]
			var st cardState
			switch {
			case connecting && view.Record.Node.ID == selectedID:
				st = cardState{
					accent: colPrimary,
					pill:   a.T("node.connecting_badge", nil),
					pillBg: colPrimaryLite, pillFg: colPrimaryDark,
					hideActions: true,
				}
			case connecting:
				st = cardState{dim: true}
			case view.Record.Node.ID == selectedID:
				st = cardState{
					accent: colPrimary,
					pill:   a.T("node.selected_badge", nil),
					pillBg: colPrimaryLite, pillFg: colPrimaryDark,
				}
			}
			return a.layoutNodeRow(gtx, view, st)
		})
	})
}

// layoutNodeRow renders one node in the v2 reference form:
// [flag icon] name + status pill / address · latency, with a
// right rail of favorite star and the test / delete actions.
// Every text is single-line truncating, so the row height is a
// pure function of the rail (star + two mini actions) — rows
// can never overlap or inflate regardless of name or address
// length. The pinned variant wraps the same content in the
// surface card with an accent bar.
func (a *App) layoutNodeRow(gtx layout.Context, view service.NodeView, st cardState) layout.Dimensions {
	n := view.Record.Node
	btns := a.rowButtons(n.ID)
	// Row-level click handling happens here (during layout).
	if btns.selectBtn.Clicked(gtx) {
		a.svc.SelectNode(n.ID)
	}
	if btns.testBtn.Clicked(gtx) {
		id := n.ID
		a.runAsync("test-node", func(ctx context.Context) error {
			_, err := a.svc.TestNode(ctx, id)
			return err
		})
	}
	if btns.delBtn.Clicked(gtx) {
		a.svc.DeleteNode(n.ID)
	}
	if btns.favBtn.Clicked(gtx) {
		a.svc.SetNodeFavorite(n.ID, !view.Favorite)
	}
	nameColor := colText
	if st.dim {
		nameColor = colSecondary
	}
	content := func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
			// Flag / protocol icon.
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(3)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return a.flagIconLayout(gtx, view)
				})
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(11)}.Layout),
			// Two text lines.
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				rows := []layout.FlexChild{
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return btns.selectBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							children := []layout.FlexChild{
								layout.Flexed(1, a.lbl1(15, font.Bold, nameColor, n.Name).Layout),
							}
							if st.pill != "" {
								children = append(children,
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return a.pill(gtx, st.pill, st.pillBg, st.pillFg, 20)
									}),
								)
							}
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
						})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl1(12.5, font.Normal, colSecondary, nodeAddressLine(a, view)).Layout),
				}
				if view.Weak {
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
						layout.Rigid(a.lbl1(12, font.Bold, colWarn,
							"⚠ "+a.T("node.weak_badge", nil)+" · "+a.T("node.weak_demote", nil)).Layout),
					)
				}
				if view.Insecure {
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
						layout.Rigid(a.lbl1(12, font.Bold, colWarn,
							"⚠ "+a.T("node.insecure_badge", nil)).Layout),
					)
				}
				if view.VPNGate {
					line := a.T("source.vpngate.badge", nil)
					switch view.Admission {
					case service.AdmissionHandshakeVerified:
						line += " · " + a.T("source.vpngate.level_handshake", nil)
					case service.AdmissionTCPConnect:
						line += " · " + a.T("source.vpngate.level_tcp", nil)
					default:
						line += " · " + a.T("source.vpngate.level_none", nil)
					}
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
						layout.Rigid(a.lbl1(12, font.Bold, colWarn, line).Layout),
					)
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
			// Right rail: favorite star, then test / delete.
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// NOTE: no Flexed child anywhere in this rail — a
				// Flexed inside a Rigid is measured against the
				// row's full width and would inflate the rail to
				// the whole row, squeezing the text column to
				// zero width (frame-probe finding, 2026-11-14).
				children := []layout.FlexChild{
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return btns.favBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(2), Bottom: unit.Dp(2)}.Layout(gtx,
								func(gtx layout.Context) layout.Dimensions {
									return starIcon(gtx, view.Favorite, 24)
								})
						})
					}),
				}
				if !st.hideActions {
					actColor, delColor := colPrimary, colDanger
					if st.dim {
						actColor, delColor = colHint, colHint
					}
					children = append(children,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.iconTextButton(gtx, &btns.testBtn, iconPulse, a.T("node.test", nil), actColor)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.iconTextButton(gtx, &btns.delBtn, iconTrash, a.T("common.delete", nil), delColor)
						}),
					)
				}
				return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx, children...)
			}),
		)
	}
	if st.pinned {
		return surface(gtx, st.accent, content)
	}
	// Flat list row: selection tint + hairline separator.
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			if st.accent.A != 0 {
				paint.FillShape(gtx.Ops, colPrimaryLite, clip.Rect{Max: size}.Op())
			}
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
				Top: unit.Dp(9), Bottom: unit.Dp(9),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(content),
					layout.Rigid(layout.Spacer{Height: unit.Dp(9)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						h := gtx.Dp(unit.Dp(1))
						w := gtx.Constraints.Max.X
						paint.FillShape(gtx.Ops, colBorder, clip.Rect{Max: image.Pt(w, h)}.Op())
						return layout.Dimensions{Size: image.Pt(w, h)}
					}),
				)
			})
		}),
	)
}

// nodeAddressLine builds the address + latency fragment of a
// node row's second line from data and localized fragments
// only.
func nodeAddressLine(a *App, view service.NodeView) string {
	n := view.Record.Node
	s := n.Server + ":" + fmt.Sprint(n.Port)
	lt := n.LastTest
	switch {
	case lt == nil:
		s += " · " + a.T("node.untested", nil)
	case !lt.OK:
		s += " · " + a.T("node.test_failed", nil)
	case lt.LatencyMs != nil:
		s += " · " + a.T("node.latency", map[string]string{"ms": fmt.Sprintf("%.0f", *lt.LatencyMs)})
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

func (a *App) sectionTitle(text string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return a.lbl(17, font.Bold, colText, text).Layout(gtx)
	}
}

func (a *App) cardTitle(text string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return a.lbl(14, font.Bold, colText, text).Layout(gtx)
	}
}

func (a *App) layoutImport(gtx layout.Context) layout.Dimensions {
	return material.List(a.th, &a.importList).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
			Top: unit.Dp(12), Bottom: unit.Dp(12),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			children := []layout.FlexChild{
				layout.Rigid(a.sectionTitle(a.T("import.title", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.layoutImportTextCard),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				layout.Rigid(a.layoutImportURLCard),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(a.lbl(11.5, font.Normal, colHint, a.T("warn.weak_auto_note", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(a.layoutSources),
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	})
}

func (a *App) layoutImportTextCard(gtx layout.Context) layout.Dimensions {
	return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{
			layout.Rigid(a.cardTitle(a.T("import.links_label", nil))),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.editorBox(gtx, &a.linksEd, a.T("import.links_hint", nil), 84)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				kind := btnPrimary
				if a.isBusy() {
					kind = btnDisabled
				}
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return a.bigButton(gtx, &a.importBtn, iconFileText, a.T("import.from_text", nil), kind)
					}),
				)
			}),
		}
		if note := a.lastImportNote(); note != "" {
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lblMax(12.5, font.Normal, colWarn, note, 3).Layout),
			)
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

func (a *App) layoutImportURLCard(gtx layout.Context) layout.Dimensions {
	return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{
			layout.Rigid(a.cardTitle(a.T("import.url_label", nil))),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.editorBox(gtx, &a.urlEd, a.T("import.url_hint", nil), 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				kind := btnOutline
				if a.isBusy() {
					kind = btnDisabled
				}
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return a.bigButton(gtx, &a.urlBtn, iconLink, a.T("import.from_url", nil), kind)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.iconTextButton(gtx, &a.fileBtn, iconFolder, a.T("import.from_file", nil), colPrimary)
					}),
				)
			}),
		}
		if a.showFilePath {
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.editorBox(gtx, &a.fileEd, a.T("import.file_path_hint", nil), 0)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, layout.Spacer{}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.iconTextButton(gtx, &a.fileGoBtn, iconCheck, a.T("common.ok", nil), colPrimary)
						}),
					)
				}),
			)
		}
		if result := a.lastImportResult(); result != "" {
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl(13, font.Normal, colSuccess, "✓ "+result).Layout),
			)
			if failText := a.lastImportFailText(); failText != "" {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lblMax(12.5, font.Normal, colWarn, failText, 2).Layout),
				)
			}
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

// --- Sources section (Import tab) -------------------------------------

// layoutSources lists the built-in node sources. VPN Gate is
// the first (book 7): a source plugin with a hard risk gate —
// this view only presents state and forwards the user's
// confirm/enable/refresh/revoke actions to the service; the
// consent state machine itself lives in the plugin and is not
// re-implemented here.
func (a *App) layoutSources(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.sectionTitle(a.T("source.title", nil))),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(a.layoutVPNGateSource),
	)
}

func (a *App) layoutVPNGateSource(gtx layout.Context) layout.Dimensions {
	st := a.svc.VPNGateStatus()
	// Click handling during layout, like the node rows.
	if a.vgRiskBtn.Clicked(gtx) {
		a.showVPNGateRisk = true
	}
	if a.vgEnableBtn.Clicked(gtx) {
		a.runAsync("vpngate-enable", func(ctx context.Context) error { return a.svc.EnableVPNGate() })
	}
	if a.vgRefreshBtn.Clicked(gtx) {
		a.runAsync("vpngate-refresh", func(ctx context.Context) error {
			_, err := a.svc.RefreshVPNGate(ctx, true)
			return err
		})
	}
	if a.vgRevokeBtn.Clicked(gtx) {
		a.runAsync("vpngate-revoke", func(ctx context.Context) error { return a.svc.DisableVPNGate() })
	}
	return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				row := []layout.FlexChild{
					layout.Rigid(a.lbl(14.5, font.Bold, colText, a.T("source.vpngate.name", nil)).Layout),
				}
				if st.Attached && st.Enabled {
					row = append(row,
						layout.Flexed(1, layout.Spacer{}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.pill(gtx, a.T("source.vpngate.enabled", nil), colSuccessBg, colSuccess, 22)
						}),
					)
				}
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, row...)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(a.lbl(12.5, font.Normal, colSecondary, a.T("source.vpngate.desc", nil)).Layout),
		}
		switch {
		case !st.Attached:
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl(12.5, font.Normal, colSecondary, a.T("source.vpngate.unavailable", nil)).Layout))
		case st.ConsentState != service.VPNGateConsentAcknowledged:
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl(13, font.Normal, colText, a.T("source.vpngate.consent_required", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return a.bigButton(gtx, &a.vgRiskBtn, iconShield, a.T("source.vpngate.view_risk", nil), btnOutline)
						}),
						layout.Flexed(1, layout.Spacer{}.Layout),
					)
				}),
			)
		case !st.Enabled:
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return a.bigButton(gtx, &a.vgEnableBtn, iconCheck, a.T("source.vpngate.enable", nil), btnPrimary)
						}),
						layout.Flexed(1, layout.Spacer{}.Layout),
					)
				}),
			)
		default:
			if st.NodeCount == 0 {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(a.lbl(13, font.Normal, colText, a.T("source.vpngate.status_never", nil)).Layout))
			} else {
				t := st.LastRefresh.Local()
				ts := fmt.Sprintf("%04d-%02d-%02d %02d:%02d",
					t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute())
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(a.lbl(13, font.Normal, colText, a.T("source.vpngate.status", map[string]string{
						"count": fmt.Sprint(st.NodeCount), "time": ts,
					})).Layout))
			}
			if st.Stale {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl(12, font.Normal, colWarn, a.T("source.vpngate.stale", nil)).Layout))
			}
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					kind := btnPrimary
					if a.isBusy() {
						kind = btnDisabled
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return a.bigButton(gtx, &a.vgRefreshBtn, iconRefresh, a.T("source.vpngate.refresh", nil), kind)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.iconTextButton(gtx, &a.vgRevokeBtn, iconShield, a.T("risk.vpngate.revoke", nil), colDanger)
						}),
					)
				}),
			)
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

// layoutVPNGateRisk is the book 7.3 risk gate page: the full
// disclosure text (the packs' risk.vpngate.body, hand-
// translated in every shipped language) with confirm/decline.
// Confirming is the only path that records the plugin's
// consent acknowledgement; the service then enables the source
// and runs the first refresh.
func (a *App) layoutVPNGateRisk(gtx layout.Context) layout.Dimensions {
	if a.vgDeclineBtn.Clicked(gtx) {
		a.showVPNGateRisk = false
	}
	if a.vgConfirmBtn.Clicked(gtx) {
		a.showVPNGateRisk = false
		a.runAsync("vpngate-confirm", func(ctx context.Context) error {
			if err := a.svc.AcknowledgeVPNGateRisk(); err != nil {
				return err
			}
			if err := a.svc.EnableVPNGate(); err != nil {
				return err
			}
			_, err := a.svc.RefreshVPNGate(ctx, true)
			return err
		})
	}
	return material.List(a.th, &a.riskList).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
			Top: unit.Dp(12), Bottom: unit.Dp(12),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(a.sectionTitle(a.T("risk.vpngate.title", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.lbl(13.5, font.Normal, colText, a.T("risk.vpngate.body", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return a.bigButton(gtx, &a.vgConfirmBtn, iconCheck, a.T("risk.vpngate.confirm", nil), btnPrimary)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return a.bigButton(gtx, &a.vgDeclineBtn, iconClose, a.T("risk.vpngate.decline", nil), btnOutline)
						}),
					)
				}),
			)
		})
	})
}

// --- Logs tab --------------------------------------------------------

func (a *App) layoutLogs(gtx layout.Context) layout.Dimensions {
	lines := a.svc.Logs().Lines()
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(12),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(a.sectionTitle(a.T("log.title", nil))),
					layout.Flexed(1, layout.Spacer{}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.iconTextButton(gtx, &a.clearLog, iconTrash, a.T("log.clear", nil), colPrimary)
					}),
				)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(lines) == 0 {
				return layout.Inset{Left: unit.Dp(dpMargin), Top: unit.Dp(12)}.Layout(gtx,
					a.lbl(13, font.Normal, colSecondary, a.T("log.empty", nil)).Layout)
			}
			return material.List(a.th, &a.logList).Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
				return layout.Inset{
					Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
					Top: unit.Dp(2), Bottom: unit.Dp(2),
				}.Layout(gtx, a.lbl(12, font.Normal, colSecondary, lines[i]).Layout)
			})
		}),
	)
}

// --- Settings tab ------------------------------------------------------

func (a *App) layoutSettings(gtx layout.Context) layout.Dimensions {
	caps := a.svc.Capabilities()
	return material.List(a.th, &a.settingsList).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
			Top: unit.Dp(12), Bottom: unit.Dp(12),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			children := []layout.FlexChild{
				layout.Rigid(a.sectionTitle(a.T("settings.title", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				// Language card.
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
						rows := []layout.FlexChild{
							layout.Rigid(a.cardTitle(a.T("settings.language", nil))),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						}
						for _, lang := range a.languages() {
							lang := lang
							btn := a.langButton(lang)
							if btn.Clicked(gtx) {
								a.applyLanguage(lang)
							}
							rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								// The language's own name comes
								// from its pack.
								name := lang
								if p, err := packName(lang); err == nil {
									name = p
								}
								return a.radioRow(gtx, btn, name, a.langEnum.Value == lang)
							}))
						}
						rows = append(rows,
							layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
							layout.Rigid(a.lbl(11.5, font.Normal, colHint, a.T("settings.language_note", nil)).Layout),
						)
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				// Connection preferences (2026-11-14 ruling):
				// real choices wired into the service — the
				// protocol preference feeds AutoSelect's
				// ranking, the run mode is persisted and handed
				// to the engine at connect time.
				layout.Rigid(a.layoutPrefCard),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				layout.Rigid(a.layoutModeCard),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				// Capability card (honest, live-detected states).
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
						row := func(labelKey, value string, pillState *bool) layout.FlexChild {
							return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(a.lbl(14, font.Normal, colText, a.T(labelKey, nil)).Layout),
									layout.Flexed(1, layout.Spacer{}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if pillState != nil {
											if *pillState {
												return a.pill(gtx, a.T("cap.available", nil), colSuccessBg, colSuccess, 22)
											}
											return a.pill(gtx, a.T("cap.unavailable", nil), colPillIdle, colSecondary, 22)
										}
										return a.lbl(14, font.Normal, colSecondary, value).Layout(gtx)
									}),
								)
							})
						}
						boolPtr := func(b bool) *bool { return &b }
						rows := []layout.FlexChild{
							layout.Rigid(a.cardTitle(a.T("cap.title", nil))),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							row("cap.kernel_label", caps.KernelID+" "+caps.KernelVersion, nil),
							layout.Rigid(layout.Spacer{Height: unit.Dp(11)}.Layout),
							row("cap.platform_label", caps.Platform.Platform, nil),
							layout.Rigid(layout.Spacer{Height: unit.Dp(11)}.Layout),
							row("cap.tun_label", "", boolPtr(caps.Platform.TUN)),
							layout.Rigid(layout.Spacer{Height: unit.Dp(11)}.Layout),
							row("cap.system_proxy_label", "", boolPtr(caps.Platform.SystemProxy)),
							layout.Rigid(layout.Spacer{Height: unit.Dp(11)}.Layout),
							row("cap.kill_switch_label", "", boolPtr(caps.Platform.KillSwitch)),
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.lbl(11.5, font.Normal, colHint, a.T("mode.capability_note", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				// Trust note card.
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
						return a.lbl(13, font.Normal, colSecondary, a.T("risk.node_trust", nil)).Layout(gtx)
					})
				}),
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	})
}

// layoutPrefCard is the protocol-preference section: three
// radio options with plain-language descriptions. The choice
// is persisted by the service and changes AutoSelect's ranking
// (see service.AutoSelectWithPreference); when the current
// group holds no node of the preferred class, a note says the
// selection fell back to latency.
func (a *App) layoutPrefCard(gtx layout.Context) layout.Dimensions {
	return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
		pref := a.svc.ProtocolPref()
		opts := []struct{ value, titleKey, descKey string }{
			{service.ProtocolPrefAuto, "pref.auto", "pref.auto_desc"},
			{service.ProtocolPrefSpeed, "pref.speed", "pref.speed_desc"},
			{service.ProtocolPrefCompat, "pref.compat", "pref.compat_desc"},
		}
		rows := []layout.FlexChild{
			layout.Rigid(a.cardTitle(a.T("pref.title", nil))),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(a.lbl(13, font.Bold, colSecondary, a.T("pref.proto_label", nil)).Layout),
			layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
		}
		for _, o := range opts {
			o := o
			btn := a.prefButton(o.value)
			if btn.Clicked(gtx) {
				a.svc.SetProtocolPref(o.value)
			}
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.radioDescRow(gtx, btn, a.T(o.titleKey, nil), a.T(o.descKey, nil), "",
					pref == o.value, true)
			}))
		}
		if pref != service.ProtocolPrefAuto && !a.groupHasPreferredClass(pref) {
			rows = append(rows,
				layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
				layout.Rigid(a.lblMax(12, font.Normal, colWarn, a.T("pref.fallback_note", nil), 2).Layout),
			)
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

// groupHasPreferredClass reports whether the current group
// holds at least one node of the preference's protocol class.
func (a *App) groupHasPreferredClass(pref string) bool {
	want := service.ClassFast
	if pref == service.ProtocolPrefCompat {
		want = service.ClassTraditional
	}
	for _, v := range a.svc.Nodes(a.currentGroup()) {
		if service.ProtocolClassOf(v.Record.Node.Protocol) == want {
			return true
		}
	}
	return false
}

// layoutModeCard is the run-mode section: the modes this
// platform can actually run are selectable (persisted via
// svc.SetMode and handed to the engine at connect time); the
// rest are listed disabled with the plain reason, per the
// ruling — listed, honest, never dead switches.
func (a *App) layoutModeCard(gtx layout.Context) layout.Dimensions {
	return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
		current := a.svc.Mode()
		descFor := func(m kernel.RunMode) string {
			switch m {
			case kernel.ModeTUN:
				return a.T("mode.tun_desc", nil)
			case kernel.ModeSystemProxy:
				return a.T("mode.system_proxy_desc", nil)
			default:
				return a.T("mode.manual_desc", nil)
			}
		}
		nameFor := func(m kernel.RunMode) string {
			switch m {
			case kernel.ModeTUN:
				return a.T("mode.tun", nil)
			case kernel.ModeSystemProxy:
				return a.T("mode.system_proxy", nil)
			default:
				return a.T("mode.manual", nil)
			}
		}
		rows := []layout.FlexChild{
			layout.Rigid(a.cardTitle(a.T("mode.label", nil))),
			layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
		}
		for _, opt := range a.svc.RunModeOptions() {
			opt := opt
			btn := a.modeButton(string(opt.Mode))
			if opt.Available && btn.Clicked(gtx) {
				a.svc.SetMode(opt.Mode)
			}
			reason := ""
			if !opt.Available {
				reason = a.T("mode.reason_platform", nil)
			}
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.radioDescRow(gtx, btn, nameFor(opt.Mode), descFor(opt.Mode), reason,
					current == opt.Mode, opt.Available)
			}))
		}
		rows = append(rows,
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(a.lbl(11.5, font.Normal, colHint, a.T("pref.mode_note", nil)).Layout),
		)
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
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
