package ui

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"os"
	"sort"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/service"
)

func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }

// --- Nodes tab -------------------------------------------------------
//
// Layout follows the approved v3 mockups (docs/ui-mockups/,
// 2026-11-14 design rulings): the first screen is a hero card
// whose content follows the real service state (new user /
// returning / connected), a "picked for you" shortlist built
// only from real measured handshakes, then the full node list
// with two-line rows. Structural rules carried over from the
// v2 real-device defects: every row text is single-line with
// truncation, and the group row lives in a bounded-height
// horizontal List so long group names scroll instead of
// squeezing.

// layoutNodes is the first screen AND the node browser in
// one scrolling stream (hero, context cards, picked section,
// all-nodes header, search, group tabs, rows, guide entry).
// Everything lives in a single list: the previous fixed
// header + flexed inner list squeezed the rows to zero height
// on short windows (700dp frames, desktop minimum size),
// leaving the nodes unreachable.
func (a *App) layoutNodes(gtx layout.Context) layout.Dimensions {
	items := []layout.Widget{}
	add := func(w layout.Widget) { items = append(items, w) }
	add(func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(12),
		}.Layout(gtx, a.layoutHero)
	})
	kind, _ := a.heroKind()
	if a.isConnecting() && a.svc.Mode() == kernel.ModeTUN {
		add(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(10)}.Layout(gtx, a.layoutConsentBanner)
		})
	}
	if kind == heroConnected {
		// Kick the async counter sample before the gate (the
		// sampler is the only producer; calling it solely from
		// inside the card deadlocked it in v2).
		if a.svc.Capabilities().Features.TrafficStats {
			a.sampleTraffic()
		}
		if a.trafficAvailable() {
			add(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(dpCardGap)}.Layout(gtx, a.layoutTrafficCard)
			})
		}
	}
	add(a.layoutRiskBanners)
	searching := strings.TrimSpace(a.searchEd.Text()) != ""
	if searching {
		n := len(a.filteredViews())
		add(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(12)}.Layout(gtx,
				a.lbl(13, font.Normal, pal.Secondary, a.T("search.count", map[string]string{"n": fmt.Sprint(n)})).Layout)
		})
	} else if picked := a.layoutPickedSection(); picked != nil {
		add(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(16)}.Layout(gtx, picked)
		})
	}
	if len(a.svc.Nodes(a.currentGroup())) > 0 {
		add(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(a.lbl(15, font.Bold, pal.Text, a.T("hero.all_title", nil)).Layout),
					layout.Flexed(1, layout.Spacer{}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Clickable(gtx, &a.checkAllBtn, func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min = image.Pt(gtx.Dp(unit.Dp(40)), gtx.Dp(unit.Dp(40)))
							return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconGauge, 21, pal.PrimaryText)
							})
						})
					}),
				)
			})
		})
	}
	add(a.layoutSearchRow)
	add(a.layoutGroupTabs)
	rows := a.visibleRowViews()
	if len(rows) == 0 {
		if a.svc.Status().State != kernel.StateRunning {
			key := "node.empty"
			if searching {
				key = "search.empty"
			}
			add(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(16)}.Layout(gtx,
					a.lbl(14, font.Normal, pal.Secondary, a.T(key, nil)).Layout)
			})
		}
	} else {
		for i := range rows {
			i := i
			add(func(gtx layout.Context) layout.Dimensions {
				dims := a.layoutNodeRow(gtx, rows[i])
				if i == len(rows)-1 {
					return dims
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return dims }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.dividerInset(gtx, 68)
					}),
				)
			})
		}
	}
	add(func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
			Top: unit.Dp(10), Bottom: unit.Dp(12),
		}.Layout(gtx, a.layoutGuideRow)
	})
	return material.List(a.th, &a.nodeList).Layout(gtx, len(items), func(gtx layout.Context, i int) layout.Dimensions {
		return items[i](gtx)
	})
}

// visibleRowViews is the node list's row set: the current
// group/search filter with the connected node removed (it
// pins inside the hero instead).
func (a *App) visibleRowViews() []service.NodeView {
	views := a.filteredViews()
	if a.svc.Status().State != kernel.StateRunning {
		return views
	}
	connID := a.connectedNodeID()
	if connID == "" {
		return views
	}
	rest := views[:0]
	for _, v := range views {
		if v.Record.Node.ID != connID {
			rest = append(rest, v)
		}
	}
	return rest
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
			return surface(gtx, pal.Primary, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(a.lbl(14, font.Bold, pal.Text, a.T("connect.consent_title", nil)).Layout),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl(12.5, font.Normal, pal.Secondary, a.T("connect.consent_body", nil)).Layout),
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
					layout.Rigid(a.lbl(12.5, font.Bold, pal.Secondary, a.T("traffic.session_title", nil)).Layout),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						half := func(gtx layout.Context, arrow, label string, bytes uint64) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(a.lbl(14, font.Normal, pal.Secondary, arrow+" "+label).Layout),
								layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
								layout.Rigid(a.lbl(15, font.Bold, pal.Text, FormatBytes(bytes)).Layout),
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
						layout.Rigid(a.lbl(11.5, font.Normal, pal.Hint, a.T("traffic.tun_note", nil)).Layout),
					)
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		})
}

// layoutSearchRow is the v3 node search box: 48dp field with a
// search icon and a clear button while text is present. It
// filters the list below by name / server / group, within the
// selected group tab.
func (a *App) layoutSearchRow(gtx layout.Context) layout.Dimensions {
	hasText := a.searchEd.Text() != ""
	return layout.Inset{
		Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(10),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(48))
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				fillRRect(gtx, size, 12, pal.InputBg)
				strokeRRect(gtx, size, 12, pal.Border)
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(12), Right: unit.Dp(8)}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconSearch, 18, pal.Hint)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								e := material.Editor(a.th, &a.searchEd, a.T("search.hint", nil))
								e.TextSize = unit.Sp(13.5)
								e.Color = pal.Text
								e.HintColor = pal.Hint
								e.SelectionColor = pal.PrimaryLite
								return e.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if !hasText {
									return layout.Dimensions{}
								}
								return material.Clickable(gtx, &a.searchClearBtn, func(gtx layout.Context) layout.Dimensions {
									gtx.Constraints.Min = image.Pt(gtx.Dp(unit.Dp(32)), gtx.Dp(unit.Dp(32)))
									return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, iconClose, 16, pal.Hint)
									})
								})
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

// --- First-screen hero ---------------------------------------------------

type heroKind int

const (
	heroConnected heroKind = iota
	heroProgress
	heroFailed
	heroReconnect
	heroFastest
	heroNew
)

// heroKind classifies the first screen from real service state
// only (teardown first-screen priority: connected > last
// success > pool consented > new user). The view is the hero's
// node where one applies.
func (a *App) heroKind() (heroKind, *service.NodeView) {
	st := a.svc.Status()
	if st.State == kernel.StateRunning {
		if id := a.connectedNodeID(); id != "" {
			if v, ok := a.svc.NodeByID(id); ok {
				return heroConnected, &v
			}
		}
		return heroConnected, nil
	}
	if stage, _, failed := a.heroProgress(); stage != stageNone {
		return heroProgress, nil
	} else if failed {
		return heroFailed, nil
	}
	if a.isConnecting() {
		return heroProgress, nil
	}
	if id := a.svc.LastConnectedNodeID(); id != "" {
		if v, ok := a.svc.NodeByID(id); ok {
			return heroReconnect, &v
		}
	}
	vg := a.svc.VPNGateStatus()
	if vg.Attached && vg.ConsentState == service.VPNGateConsentAcknowledged {
		return heroFastest, nil
	}
	return heroNew, nil
}

func (a *App) layoutHero(gtx layout.Context) layout.Dimensions {
	kind, view := a.heroKind()
	switch kind {
	case heroConnected:
		return a.layoutHeroConnected(gtx, view)
	case heroProgress:
		return a.layoutHeroProgress(gtx)
	case heroFailed:
		return a.layoutHeroFailed(gtx)
	case heroReconnect:
		return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(a.lbl(20, font.Bold, pal.Text, a.T("hero.idle_title", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(a.lbl1(13, font.Normal, pal.Secondary, nodeSubLine(a, *view)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.heroButton(gtx, &a.heroBtn, iconPower, a.T("hero.connect_last", nil), btnPrimary)
				}),
			)
		})
	case heroFastest:
		return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(a.lbl(20, font.Bold, pal.Text, a.T("hero.idle_title", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.heroButton(gtx, &a.heroBtn, iconPower, a.T("hero.connect_fastest", nil), btnPrimary)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(a.layoutRiskLine),
			)
		})
	default: // heroNew
		return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(a.lbl(20, font.Bold, pal.Text, a.T("hero.new_title", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lblWrap(13.5, 19.5, font.Normal, pal.Secondary, a.T("hero.new_desc", nil), 3).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.heroButton(gtx, &a.heroBtn, iconPower, a.T("hero.connect_free", nil), btnPrimary)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(a.layoutRiskLine),
			)
		})
	}
}

func (a *App) layoutHeroConnected(gtx layout.Context, view *service.NodeView) layout.Dimensions {
	return surface(gtx, pal.Success, func(gtx layout.Context) layout.Dimensions {
		rows := []layout.FlexChild{
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						d := gtx.Dp(unit.Dp(10))
						paint.FillShape(gtx.Ops, pal.Success, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
						return layout.Dimensions{Size: image.Pt(d, d)}
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(7)}.Layout),
					layout.Rigid(a.lbl(15, font.Bold, pal.Success, a.T("status.connected", nil)).Layout),
				)
			}),
		}
		if view != nil {
			line := nodeSubLine(a, *view)
			if a.autoPicked() {
				line = a.T("hero.auto_picked", map[string]string{"name": view.Record.Node.Name})
				if lt := view.Record.Node.LastTest; lt != nil && lt.OK && lt.LatencyMs != nil {
					line += " · " + a.T("node.latency", map[string]string{"ms": fmt.Sprintf("%.0f", *lt.LatencyMs)})
				}
			}
			rows = append(rows,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl1(20, font.Bold, pal.Text, view.Record.Node.Name).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
				layout.Rigid(a.lbl1(13, font.Normal, pal.Secondary, line).Layout),
			)
		}
		rows = append(rows,
			layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.bigButton(gtx, &a.disconnectBtn, iconPower, a.T("conn.disconnect", nil), btnDangerOutline)
			}),
		)
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

func (a *App) layoutHeroProgress(gtx layout.Context) layout.Dimensions {
	stage, _, _ := a.heroProgress()
	text := a.T("status.connecting", nil)
	switch stage {
	case stageRefresh:
		text = a.T("hero.working_refresh", nil)
	case stageCheck:
		text = a.T("hero.working_check", nil)
	case stageConnect:
		// The chain reports the candidate it is attempting;
		// without one (a plain manual connect) the generic
		// trying-nodes line stands.
		if name := a.tryingNameText(); name != "" {
			text = a.T("hero.working_connect", map[string]string{"name": name})
		} else {
			text = a.T("hero.working_trying", nil)
		}
	}
	return surface(gtx, pal.Primary, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return iconLayout(gtx, iconPulse, 26, pal.Primary)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
					layout.Flexed(1, a.lblWrap(16, 22, font.Bold, pal.Text, text, 2).Layout),
				)
			}),
			// The chain must be stoppable from the state it
			// creates (2026-11-14 fix batch): a cancel button
			// right on the progress card, wired to the same
			// stop-everything action as Disconnect.
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.bigButton(gtx, &a.heroCancelBtn, iconClose, a.T("common.cancel", nil), btnOutline)
			}),
		)
	})
}

func (a *App) layoutHeroFailed(gtx layout.Context) layout.Dimensions {
	_, herr, _ := a.heroProgress()
	reason := a.T("err.generic", nil)
	if herr != nil {
		reason = a.T(ErrorKey(herr), nil)
	}
	return surface(gtx, pal.Danger, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return iconLayout(gtx, iconWarn, 20, pal.Danger)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(a.lbl(17, font.Bold, pal.Danger, a.T("hero.failed_title", nil)).Layout),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(a.lblMax(13, font.Normal, pal.Text, reason, 2).Layout),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return a.bigButton(gtx, &a.heroRetryBtn, iconRefresh, a.T("hero.retry_another", nil), btnPrimary)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return a.bigButton(gtx, &a.heroReasonBtn, iconList, a.T("hero.view_reason", nil), btnOutline)
					}),
				)
			}),
		)
	})
}

// layoutRiskLine is the hero's one-line pool risk summary with
// its full-notice entry: file icon, the short line, and the
// "view the risk notice" link opening the sheet.
func (a *App) layoutRiskLine(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return iconLayout(gtx, iconFileText, 13, pal.Hint)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
		layout.Flexed(1, a.lbl1(11.5, font.Normal, pal.Hint, a.T("hero.risk_line", nil)).Layout),
		layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.textButton(gtx, &a.riskLinkBtn, a.T("risk.view_link", nil), pal.PrimaryText)
		}),
	)
}

// --- "Picked for you" ----------------------------------------------------

// pickedViews builds the shortlist strictly from real measured
// data (teardown: only nodes with a successful latency-bearing
// handshake on record may appear; nothing is estimated or
// invented). Order: the last successfully connected node, then
// favorites by latency, then the fastest — at most three.
func (a *App) pickedViews() []service.NodeView {
	views := a.svc.Nodes(a.currentGroup())
	var tested []service.NodeView
	for _, v := range views {
		if lt := v.Record.Node.LastTest; lt != nil && lt.OK && lt.LatencyMs != nil {
			tested = append(tested, v)
		}
	}
	if len(tested) == 0 {
		return nil
	}
	byLatency := append([]service.NodeView{}, tested...)
	sort.SliceStable(byLatency, func(i, j int) bool {
		return *byLatency[i].Record.Node.LastTest.LatencyMs < *byLatency[j].Record.Node.LastTest.LatencyMs
	})
	var out []service.NodeView
	seen := map[string]bool{}
	if connID := a.connectedNodeID(); connID != "" {
		seen[connID] = true // the connected node pins in the hero
	}
	add := func(v service.NodeView) {
		if !seen[v.Record.Node.ID] && len(out) < 3 {
			seen[v.Record.Node.ID] = true
			out = append(out, v)
		}
	}
	if id := a.svc.LastConnectedNodeID(); id != "" {
		for _, v := range tested {
			if v.Record.Node.ID == id {
				add(v)
			}
		}
	}
	for _, v := range byLatency {
		if v.Favorite {
			add(v)
		}
	}
	for _, v := range byLatency {
		add(v)
	}
	return out
}

// layoutPickedSection renders the shortlist card, or nil when
// no node has real measured data yet.
func (a *App) layoutPickedSection() layout.Widget {
	picked := a.pickedViews()
	if len(picked) == 0 {
		return nil
	}
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(a.lbl(15, font.Bold, pal.Text, a.T("hero.picked_title", nil)).Layout),
					layout.Flexed(1, layout.Spacer{}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.textButton(gtx, &a.viewAllBtn, a.T("hero.view_all", nil), pal.PrimaryText)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
					rows := []layout.FlexChild{}
					for i, v := range picked {
						i, v := i, v
						if i > 0 {
							rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return a.dividerInset(gtx, 46)
							}))
						}
						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if a.pickedBtns[i].Clicked(gtx) {
								id := v.Record.Node.ID
								a.runAsync("connect", func(ctx context.Context) error {
									return a.svc.Connect(ctx, id)
								})
							}
							return material.Clickable(gtx, &a.pickedBtns[i], func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(64))
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return a.flagIconSized(gtx, v, 36, 25)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										sub := a.T("node.latency", map[string]string{"ms": fmt.Sprintf("%.0f", *v.Record.Node.LastTest.LatencyMs)}) +
											" · " + a.protoDisplayName(v.Record.Node.Protocol)
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(a.lbl1(15, font.Bold, pal.Text, v.Record.Node.Name).Layout),
											layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
											layout.Rigid(a.lbl1(12, font.Normal, pal.Secondary, sub).Layout),
										)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, iconArrowCircle, 30, pal.Primary)
									}),
								)
							})
						}))
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
				})
			}),
		)
	}
}

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
							fillRRect(gtx, size, dpBtnRad, pal.WarnBg)
							return layout.Dimensions{Size: size}
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{
								Left: unit.Dp(12), Right: unit.Dp(12),
								Top: unit.Dp(9), Bottom: unit.Dp(9),
							}.Layout(gtx, a.lbl(12.5, font.Normal, pal.Warn, a.T(key, nil)).Layout)
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

// layoutNodeRow renders one node in the v3 two-line form:
// 40x28 flag (or protocol tile), name line (name + pool
// badge, favorite star aligned to it), and the {server} ·
// {protocol} · {latency} sub-line. Rows are 72dp, 84dp with a
// warning line.
//
// Interaction (user ruling, 2026-11-14): tapping the row
// itself — anywhere on the flag/text body — selects the node
// AND expands its action strip (connect / check latency /
// delete) directly under the row; tapping again collapses
// it, and expanding another row collapses this one. The
// previous design hid the actions behind a "…" overflow
// button, which the user could not find on the real device;
// the "…" button is gone. The star stays its own tap target
// at the end of the name line.
func (a *App) layoutNodeRow(gtx layout.Context, view service.NodeView) layout.Dimensions {
	n := view.Record.Node
	btns := a.rowButtons(n.ID)
	if btns.selectBtn.Clicked(gtx) {
		a.svc.SelectNode(n.ID)
		if a.expandedRowID == n.ID {
			a.expandedRowID = ""
		} else {
			a.expandedRowID = n.ID
		}
	}
	if btns.favBtn.Clicked(gtx) {
		a.svc.SetNodeFavorite(n.ID, !view.Favorite)
	}
	if btns.connBtn.Clicked(gtx) {
		id := n.ID
		a.runAsync("connect", func(ctx context.Context) error { return a.svc.Connect(ctx, id) })
	}
	if btns.testBtn.Clicked(gtx) {
		// "Check latency" is the FAST reachability check
		// (2026-11-14 fix batch): a full handshake per tap
		// is what made checking pool nodes unusable. It runs
		// through runRowCheck, NOT the busy-gated runAsync
		// (2026-11-14 timing audit §8): while a sweep or a
		// connect chain held the gate, these taps were
		// dropped silently and the row looked dead. The
		// result (latency / no response) lands on the row's
		// sub-line either way.
		a.runRowCheck(n.ID)
	}
	if btns.delBtn.Clicked(gtx) {
		a.svc.DeleteNode(n.ID)
	}
	selected := n.ID == a.svc.SelectedNodeID()
	warn := view.Weak || view.Insecure
	expanded := a.expandedRowID == n.ID
	connectingThis := a.isConnecting() && n.ID == a.svc.SelectedNodeID()
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			if selected {
				paint.FillShape(gtx.Ops, pal.PrimaryLite, clip.Rect{Max: size}.Op())
				bar := gtx.Dp(unit.Dp(3))
				paint.FillShape(gtx.Ops, pal.Primary, clip.Rect{Max: image.Pt(bar, size.Y)}.Op())
			}
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			minH := unit.Dp(dpRowH)
			if warn {
				minH = unit.Dp(84)
			}
			gtx.Constraints.Min.Y = gtx.Dp(minH)
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Left: unit.Dp(dpMargin), Right: unit.Dp(8),
						Top: unit.Dp(10), Bottom: unit.Dp(10),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							// The row body (flag + text) is
							// one big tap target: tapping it
							// selects the node and expands /
							// collapses its action strip.
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return btns.selectBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Inset{Top: unit.Dp(1)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return a.flagIconLayout(gtx, view)
											})
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
										layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
											rows := []layout.FlexChild{
												// Name line: name +
												// pool badge.
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
														layout.Flexed(1, a.lbl1(15, font.Bold, pal.Text, n.Name).Layout),
														layout.Rigid(func(gtx layout.Context) layout.Dimensions {
															if !view.VPNGate {
																return layout.Dimensions{}
															}
															return layout.Inset{Left: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
																return a.pill(gtx, a.T("source.vpngate.badge", nil), pal.PrimaryLite, pal.PrimaryText, 18)
															})
														}),
													)
												}),
												layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
												layout.Rigid(a.lbl1(12.5, font.Normal, pal.Secondary, nodeSubLine(a, view)).Layout),
											}
											if warn {
												text := ""
												if view.Weak {
													text = "⚠ " + a.T("node.weak_badge", nil) + " · " + a.T("node.weak_demote", nil)
												} else {
													text = "⚠ " + a.T("node.insecure_badge", nil)
												}
												rows = append(rows,
													layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
													layout.Rigid(a.lbl1(12, font.Bold, pal.Warn, text).Layout),
												)
											}
											if connectingThis {
												rows = append(rows,
													layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
													layout.Rigid(a.lbl1(12, font.Bold, pal.PrimaryText, a.T("node.connecting_badge", nil)).Layout),
												)
											}
											return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
										}),
									)
								})
							}),
							// The star is the row's only other
							// tap target, sitting on the name
							// line at the row's end.
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return btns.favBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Left: unit.Dp(6), Right: unit.Dp(2), Bottom: unit.Dp(3)}.Layout(gtx,
										func(gtx layout.Context) layout.Dimensions {
											return starIcon(gtx, view.Favorite, 21)
										})
								})
							}),
						)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if !expanded {
						return layout.Dimensions{}
					}
					return layout.Inset{Left: unit.Dp(68), Right: unit.Dp(dpMargin), Bottom: unit.Dp(10)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return a.iconTextButton(gtx, &btns.connBtn, iconPower, a.T("conn.connect", nil), pal.PrimaryText)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return a.iconTextButton(gtx, &btns.testBtn, iconGauge, a.T("node.test", nil), pal.PrimaryText)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return a.iconTextButton(gtx, &btns.delBtn, iconTrash, a.T("common.delete", nil), pal.Danger)
								}),
							)
						})
				}),
			)
		}),
	)
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
//
// v3 form (approved mockup 02): a recommendation card for the
// public pool first (the zero-effort path), the guide entry,
// then three method rows that expand on tap — exactly one is
// ever open. The sources section (the pool's management card)
// stays at the bottom.

func (a *App) sectionTitle(text string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return a.lbl(17, font.Bold, pal.Text, text).Layout(gtx)
	}
}

func (a *App) cardTitle(text string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return a.lbl(14, font.Bold, pal.Text, text).Layout(gtx)
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
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			}
			if rec := a.layoutPoolRecommend(); rec != nil {
				children = append(children,
					layout.Rigid(rec),
					layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				)
			}
			children = append(children,
				layout.Rigid(a.layoutGuideRow),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.layoutMethodRows),
			)
			if result := a.lastImportResult(); result != "" {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
					layout.Rigid(a.lbl(13, font.Normal, pal.Success, "✓ "+result).Layout),
				)
				if failText := a.lastImportFailText(); failText != "" {
					children = append(children,
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(a.lblMax(12.5, font.Normal, pal.Warn, failText, 2).Layout),
					)
				}
			}
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				layout.Rigid(a.layoutSources),
			)
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	})
}

// layoutPoolRecommend is the import page's recommendation
// card: when the pool is attached but not yet enabled, offer
// the one-tap path (risk first). It returns nil when there is
// nothing to recommend (pool already enabled, or not attached
// — the sources section below reports that state).
func (a *App) layoutPoolRecommend() layout.Widget {
	st := a.svc.VPNGateStatus()
	if !st.Attached || st.Enabled {
		return nil
	}
	consented := st.ConsentState == service.VPNGateConsentAcknowledged
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Min
				fillRRect(gtx, size, dpCardRad, pal.PrimaryLite)
				return layout.Dimensions{Size: size}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{
					Left: unit.Dp(14), Right: unit.Dp(14),
					Top: unit.Dp(14), Bottom: unit.Dp(14),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return iconLayout(gtx, iconShield, 20, pal.PrimaryText)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
								layout.Rigid(a.lbl(15.5, font.Bold, pal.Text, a.T("import.rec_title", nil)).Layout),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(a.lblWrap(13, 18.5, font.Normal, pal.Secondary, a.T("import.rec_desc", nil), 2).Layout),
						layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if !consented {
								return a.bigButton(gtx, &a.recBtn, iconShield, a.T("import.rec_button", nil), btnOutline)
							}
							kind := btnPrimary
							if a.isBusy() {
								kind = btnDisabled
							}
							return a.bigButton(gtx, &a.vgEnableBtn, iconCheck, a.T("source.vpngate.enable", nil), kind)
						}),
					)
				})
			}),
		)
	}
}

// importMethod describes one import method row.
type importMethod struct {
	icon     iconKind
	titleKey string
	descKey  string
}

// layoutMethodRows renders the three import methods as 88dp
// rows; tapping a header expands that method's body and
// collapses the others (a.expandedMethod: 0 = none, 1..3 =
// links / subscription / file).
func (a *App) layoutMethodRows(gtx layout.Context) layout.Dimensions {
	methods := []importMethod{
		{iconLink, "import.method_link", "import.method_link_desc"},
		{iconRss, "import.method_url", "import.method_url_desc"},
		{iconFolder, "import.method_file", "import.method_file_desc"},
	}
	rows := []layout.FlexChild{}
	for i, m := range methods {
		i, m := i, m
		if i > 0 {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.dividerInset(gtx, 64)
			}))
		}
		open := a.expandedMethod == i+1
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if a.methodBtns[i].Clicked(gtx) {
						if open {
							a.expandedMethod = 0
						} else {
							a.expandedMethod = i + 1
						}
					}
					return material.Clickable(gtx, &a.methodBtns[i], func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(88))
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								size := image.Pt(gtx.Dp(unit.Dp(40)), gtx.Dp(unit.Dp(40)))
								return layout.Stack{Alignment: layout.Center}.Layout(gtx,
									layout.Expanded(func(gtx layout.Context) layout.Dimensions {
										fillRRect(gtx, size, 10, pal.PrimaryLite)
										return layout.Dimensions{Size: size}
									}),
									layout.Stacked(func(gtx layout.Context) layout.Dimensions {
										return iconLayout(gtx, m.icon, 21, pal.PrimaryText)
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(a.lbl(15.5, font.Bold, pal.Text, a.T(m.titleKey, nil)).Layout),
									layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
									layout.Rigid(a.lblWrap(12.5, 17, font.Normal, pal.Secondary, a.T(m.descKey, nil), 2).Layout),
								)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconChevron, 20, pal.Hint)
							}),
						)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if !open {
						return layout.Dimensions{}
					}
					return layout.Inset{Bottom: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						switch i {
						case 0:
							return a.layoutMethodLinks(gtx)
						case 1:
							return a.layoutMethodURL(gtx)
						default:
							return a.layoutMethodFile(gtx)
						}
					})
				}),
			)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

// dividerInset draws a hairline starting leftDp from the
// content edge (aligned to a row's text column).
func (a *App) dividerInset(gtx layout.Context, leftDp int) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(float32(leftDp))}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(1))
		w := gtx.Constraints.Max.X
		paint.FillShape(gtx.Ops, pal.Border, clip.Rect{Max: image.Pt(w, h)}.Op())
		return layout.Dimensions{Size: image.Pt(w, h)}
	})
}

// layoutMethodLinks is the expanded "paste node links" body.
func (a *App) layoutMethodLinks(gtx layout.Context) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.editorBox(gtx, &a.linksEd, a.T("import.links_hint", nil), 84)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			kind := btnPrimary
			if a.isBusy() {
				kind = btnDisabled
			}
			return a.bigButton(gtx, &a.importBtn, iconFileText, a.T("import.from_text", nil), kind)
		}),
	}
	if note := a.lastImportNote(); note != "" {
		children = append(children,
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Stack{}.Layout(gtx,
					layout.Expanded(func(gtx layout.Context) layout.Dimensions {
						size := gtx.Constraints.Min
						fillRRect(gtx, size, dpBtnRad, pal.WarnBg)
						return layout.Dimensions{Size: size}
					}),
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{
							Left: unit.Dp(12), Right: unit.Dp(12),
							Top: unit.Dp(10), Bottom: unit.Dp(10),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(a.lblWrap(13, 18.5, font.Normal, pal.Text, note, 3).Layout),
								layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return a.textButton(gtx, &a.detourBtn, a.T("import.detour_go", nil), pal.PrimaryText)
										}),
										layout.Flexed(1, layout.Spacer{}.Layout),
									)
								}),
							)
						})
					}),
				)
			}),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// layoutMethodURL is the expanded "subscription URL" body.
func (a *App) layoutMethodURL(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.editorBox(gtx, &a.urlEd, a.T("import.url_hint", nil), 0)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			kind := btnPrimary
			if a.isBusy() {
				kind = btnDisabled
			}
			return a.bigButton(gtx, &a.urlBtn, iconLink, a.T("import.from_url", nil), kind)
		}),
	)
}

// layoutMethodFile is the expanded "import from a file" body:
// the native picker button, plus the path field it reveals.
func (a *App) layoutMethodFile(gtx layout.Context) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.iconTextButton(gtx, &a.fileBtn, iconFolder, a.T("import.from_file", nil), pal.PrimaryText)
				}),
				layout.Flexed(1, layout.Spacer{}.Layout),
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
						return a.iconTextButton(gtx, &a.fileGoBtn, iconCheck, a.T("common.ok", nil), pal.PrimaryText)
					}),
				)
			}),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
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
		if st.ConsentState == service.VPNGateConsentAcknowledged {
			a.openRiskSheet(sheetInfo)
		} else {
			a.openRiskSheet(sheetGateEnable)
		}
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
					layout.Rigid(a.lbl(14.5, font.Bold, pal.Text, a.T("source.vpngate.name", nil)).Layout),
				}
				if st.Attached && st.Enabled {
					row = append(row,
						layout.Flexed(1, layout.Spacer{}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.pill(gtx, a.T("source.vpngate.enabled", nil), pal.SuccessBg, pal.Success, 22)
						}),
					)
				}
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, row...)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(a.lbl(12.5, font.Normal, pal.Secondary, a.T("source.vpngate.desc", nil)).Layout),
		}
		switch {
		case !st.Attached:
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl(12.5, font.Normal, pal.Secondary, a.T("source.vpngate.unavailable", nil)).Layout))
		case st.ConsentState != service.VPNGateConsentAcknowledged:
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lbl(13, font.Normal, pal.Text, a.T("source.vpngate.consent_required", nil)).Layout),
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
			// Consented but not enabled: the import page's
			// recommendation card above carries the enable
			// action; this card stays the status/management
			// surface and does not duplicate the button.
			// Nothing to add: name + description above, the
			// enable action on the recommendation card.
		default:
			if st.NodeCount == 0 {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(a.lbl(13, font.Normal, pal.Text, a.T("source.vpngate.status_never", nil)).Layout))
			} else {
				t := st.LastRefresh.Local()
				ts := fmt.Sprintf("%04d-%02d-%02d %02d:%02d",
					t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute())
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(a.lbl(13, font.Normal, pal.Text, a.T("source.vpngate.status", map[string]string{
						"count": fmt.Sprint(st.NodeCount), "time": ts,
					})).Layout))
			}
			if st.Stale {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl(12, font.Normal, pal.Warn, a.T("source.vpngate.stale", nil)).Layout))
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
							return a.iconTextButton(gtx, &a.vgRevokeBtn, iconShield, a.T("risk.vpngate.revoke", nil), pal.Danger)
						}),
					)
				}),
			)
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

// --- VPN Gate risk bottom sheet (v3) -----------------------------------
//
// The book 7.3 risk gate is a bottom sheet over the current
// page, never a page jump (2026-11-14 design ruling). Three
// modes: gate-connect (agreeing acknowledges the risk and
// continues the first-screen one-tap connect chain),
// gate-enable (agreeing acknowledges, enables the source and
// refreshes), and info (already acknowledged; read-only). The
// three summary points are plain-language compressions of the
// legal text; the full text — risk.vpngate.body, hand-
// translated in every shipped language — is one tap away
// inside the same sheet and is never altered by this UI.

const (
	sheetGateConnect = iota
	sheetGateEnable
	sheetInfo
)

type riskSheetState struct {
	mode int
	full bool
}

// openRiskSheet presents the risk sheet in the given mode.
func (a *App) openRiskSheet(mode int) {
	a.sheet = &riskSheetState{mode: mode}
}

// layoutRiskSheet renders the sheet over the whole window:
// scrim + bottom panel. The middle (points / full text)
// scrolls; the agree and decline actions stay pinned at the
// panel's bottom edge.
func (a *App) layoutRiskSheet(gtx layout.Context) layout.Dimensions {
	sh := a.sheet
	if sh == nil {
		return layout.Dimensions{}
	}
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			return material.Clickable(gtx, &a.sheetScrimBtn, func(gtx layout.Context) layout.Dimensions {
				paint.FillShape(gtx.Ops, pal.Scrim, clip.Rect{Max: size}.Op())
				return layout.Dimensions{Size: size}
			})
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Flexed(1, layout.Spacer{}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					maxY := gtx.Constraints.Max.Y * 88 / 100
					gtx.Constraints.Max.Y = maxY
					return layout.Stack{}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							size := gtx.Constraints.Min
							fillTopRRect(gtx, size, 20, pal.Card)
							return layout.Dimensions{Size: size}
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{
								Left: unit.Dp(20), Right: unit.Dp(20),
								Top: unit.Dp(10), Bottom: unit.Dp(24),
							}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return a.layoutRiskSheetContent(gtx, sh)
							})
						}),
					)
				}),
			)
		}),
	)
}

func (a *App) layoutRiskSheetContent(gtx layout.Context, sh *riskSheetState) layout.Dimensions {
	children := []layout.FlexChild{
		// Drag pill.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				size := image.Pt(gtx.Dp(unit.Dp(36)), gtx.Dp(unit.Dp(4)))
				fillRRect(gtx, size, 2, pal.PillIdle)
				return layout.Dimensions{Size: size}
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		// Title: shield in a warning circle + text.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					size := image.Pt(gtx.Dp(unit.Dp(40)), gtx.Dp(unit.Dp(40)))
					return layout.Stack{Alignment: layout.Center}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							paint.FillShape(gtx.Ops, pal.WarnBg, clip.Ellipse(image.Rect(0, 0, size.X, size.Y)).Op(gtx.Ops))
							return layout.Dimensions{Size: size}
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return iconLayout(gtx, iconShield, 21, pal.Warn)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Flexed(1, a.lblWrap(17, 23, font.Bold, pal.Text, a.T("risk.sheet.title", nil), 2).Layout),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		// Scrollable middle: the three points, then either the
		// "read the full notice" entry or the full legal text.
		// Height-capped (not flexed) so the panel hugs its
		// content instead of stretching to the 88% ceiling.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if cap := gtx.Dp(unit.Dp(300)); gtx.Constraints.Max.Y > cap {
				gtx.Constraints.Max.Y = cap
			}
			items := []string{"risk.sheet.point1", "risk.sheet.point2", "risk.sheet.point3"}
			count := len(items)
			if sh.full {
				count++
			} else {
				count++ // the view-full row
			}
			return material.List(a.th, &a.sheetList).Layout(gtx, count, func(gtx layout.Context, i int) layout.Dimensions {
				if i < len(items) {
					return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: unit.Dp(7)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									d := gtx.Dp(unit.Dp(7))
									paint.FillShape(gtx.Ops, pal.Secondary, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
									return layout.Dimensions{Size: image.Pt(d, d)}
								})
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
							layout.Flexed(1, a.lblWrap(13.5, 19, font.Normal, pal.Text, a.T(items[i], nil), 4).Layout),
						)
					})
				}
				if !sh.full {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return a.textButton(gtx, &a.sheetFullBtn, a.T("risk.view_full", nil), pal.PrimaryText)
						}),
					)
				}
				return a.lblWrap(12.5, 18, font.Normal, pal.Secondary, a.T("risk.vpngate.body", nil), 0).Layout(gtx)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
	}
	if sh.mode != sheetInfo {
		label := a.T("risk.sheet.agree_enable", nil)
		if sh.mode == sheetGateConnect {
			label = a.T("risk.sheet.agree", nil)
		}
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.heroButton(gtx, &a.sheetAgreeBtn, iconCheck, label, btnPrimary)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.bigButton(gtx, &a.sheetCloseBtn, iconClose, a.T("risk.sheet.decline", nil), btnOutline)
			}),
		)
	} else {
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.bigButton(gtx, &a.sheetCloseBtn, iconCheck, a.T("risk.sheet.close", nil), btnPrimary)
			}),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// --- Shared small pieces -------------------------------------------------

// layoutGuideRow is the "illustrated guide" entry shown on the
// nodes, import and settings pages: book icon, one line, and a
// chevron. Tapping opens the website guide in the platform
// browser (see openGuide); a failure leaves a plain-language
// hint with the address under the row.
func (a *App) layoutGuideRow(gtx layout.Context) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return material.Clickable(gtx, &a.guideBtn, func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							size := image.Pt(gtx.Dp(unit.Dp(40)), gtx.Dp(unit.Dp(40)))
							return layout.Stack{Alignment: layout.Center}.Layout(gtx,
								layout.Expanded(func(gtx layout.Context) layout.Dimensions {
									paint.FillShape(gtx.Ops, pal.PrimaryLite, clip.Ellipse(image.Rect(0, 0, size.X, size.Y)).Op(gtx.Ops))
									return layout.Dimensions{Size: size}
								}),
								layout.Stacked(func(gtx layout.Context) layout.Dimensions {
									return iconLayout(gtx, iconBook, 21, pal.PrimaryText)
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
						layout.Flexed(1, a.lbl(14.5, font.Normal, pal.Text, a.T("help.guide", nil)).Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return iconLayout(gtx, iconChevron, 20, pal.Hint)
						}),
					)
				})
			})
		}),
	}
	if hint := a.helpHintText(); hint != "" {
		children = append(children,
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(a.lblMax(12, font.Normal, pal.Warn, hint, 3).Layout),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// protoDisplayName resolves a protocol id to its display name
// from the packs; an unknown id renders as the id itself (it is
// node data, never interface copy).
func (a *App) protoDisplayName(protocol string) string {
	key := "proto." + protocol
	if s := a.T(key, nil); s != key && s != "!"+key+"!" {
		return s
	}
	return protocol
}

// nodeSubLine builds a node row's second line from data and
// localized fragments only: {server} · {protocol} · {latency
// or check state}. Two measurement kinds can stand in the
// last slot and the fresher one wins: the persisted handshake
// record (LastTest) and this session's fast reachability
// check (view.Reach — a latency when it responded, "no
// response" when it did not). Neither is ever dressed up as
// the other: the fast check's number is a connect latency
// under the "check latency" action that produced it, and the
// handshake number only ever comes from a real handshake.
func nodeSubLine(a *App, view service.NodeView) string {
	n := view.Record.Node
	s := n.Server + " · " + a.protoDisplayName(n.Protocol)
	lt := n.LastTest
	if r := view.Reach; r != nil && r.Checked && reachIsFresher(r, lt) {
		if r.Reachable {
			return s + " · " + a.T("node.latency", map[string]string{"ms": fmt.Sprintf("%.0f", r.LatencyMs)})
		}
		return s + " · " + a.T("node.no_response", nil)
	}
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

// reachIsFresher reports whether a fast-check result postdates
// the persisted handshake record (an unparseable or absent
// record time counts as older).
func reachIsFresher(r *service.ReachResult, lt *specnode.LastTest) bool {
	if lt == nil {
		return true
	}
	t, err := time.Parse(time.RFC3339, lt.At)
	if err != nil {
		return true
	}
	return r.At.After(t)
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
						return a.iconTextButton(gtx, &a.clearLog, iconTrash, a.T("log.clear", nil), pal.Primary)
					}),
				)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(lines) == 0 {
				return layout.Inset{Left: unit.Dp(dpMargin), Top: unit.Dp(12)}.Layout(gtx,
					a.lbl(13, font.Normal, pal.Secondary, a.T("log.empty", nil)).Layout)
			}
			return material.List(a.th, &a.logList).Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
				return layout.Inset{
					Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
					Top: unit.Dp(2), Bottom: unit.Dp(2),
				}.Layout(gtx, a.lbl(12, font.Normal, pal.Secondary, lines[i]).Layout)
			})
		}),
	)
}

// --- Settings tab ------------------------------------------------------

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
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				// Background tiers (v3): four complete token
				// sets, applied immediately and persisted.
				layout.Rigid(a.cardTitle(a.T("theme.title", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(a.layoutThemeRow),
			}
			if a.svc.Theme() == service.ThemeSystem && a.systemUnreadable() {
				children = append(children,
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(a.lblMax(12, font.Normal, pal.Hint, a.T("theme.system_fallback", nil), 2).Layout),
				)
			}
			children = append(children,
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				// Language: compact radio rows with dividers,
				// no card (v3 settings pattern).
				layout.Rigid(a.cardTitle(a.T("settings.language", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					langs := a.languages()
					rows := []layout.FlexChild{}
					for i, lang := range langs {
						lang := lang
						if i > 0 {
							rows = append(rows, layout.Rigid(a.divider44))
						}
						btn := a.langButton(lang)
						if btn.Clicked(gtx) {
							a.applyLanguage(lang)
						}
						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							name := lang
							if p, err := packName(lang); err == nil {
								name = p
							}
							return a.langRow(gtx, btn, name, a.langEnum.Value == lang)
						}))
					}
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(a.lbl(11.5, font.Normal, pal.Hint, a.T("settings.language_note", nil)).Layout),
					)
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				// Protocol preference: option groups (v3).
				layout.Rigid(a.cardTitle(a.T("pref.title", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(a.layoutPrefGroups),
				// Run mode: option groups (v3).
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				layout.Rigid(a.cardTitle(a.T("mode.label", nil))),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(a.layoutModeGroups),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(a.lblMax(12, font.Normal, pal.Hint, a.T("mode.effect", nil), 2).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				// Capability card (honest, live-detected states).
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
						row := func(labelKey, value string, pillState *bool) layout.FlexChild {
							return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(a.lbl(14, font.Normal, pal.Text, a.T(labelKey, nil)).Layout),
									layout.Flexed(1, layout.Spacer{}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if pillState != nil {
											if *pillState {
												return a.pill(gtx, a.T("cap.available", nil), pal.SuccessBg, pal.Success, 22)
											}
											return a.pill(gtx, a.T("cap.unavailable", nil), pal.PillIdle, pal.Secondary, 22)
										}
										return a.lbl(14, font.Normal, pal.Secondary, value).Layout(gtx)
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
				layout.Rigid(a.lbl(11.5, font.Normal, pal.Hint, a.T("mode.capability_note", nil)).Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(dpCardGap)}.Layout),
				// Trust note card.
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return surface(gtx, color.NRGBA{}, func(gtx layout.Context) layout.Dimensions {
						return a.lbl(13, font.Normal, pal.Secondary, a.T("risk.node_trust", nil)).Layout(gtx)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(a.layoutGuideRow),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, a.lbl(11.5, font.Normal, pal.Hint, a.T("app.footer_note", nil)).Layout)
				}),
			)
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	})
}

// langRow is one compact language option row (64dp guide):
// radio + name, whole row clickable.
func (a *App) langRow(gtx layout.Context, btn *widget.Clickable, name string, selected bool) layout.Dimensions {
	return material.Clickable(gtx, btn, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(52))
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.radio(gtx, selected, true)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Rigid(a.lbl(15, font.Normal, pal.Text, name).Layout),
		)
	})
}

// divider44 is a hairline indented to the option groups' text
// column (44dp from the content edge: 12 group padding + 22
// radio + 10 gap).
func (a *App) divider44(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(44)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(1))
		w := gtx.Constraints.Max.X
		paint.FillShape(gtx.Ops, pal.Border, clip.Rect{Max: image.Pt(w, h)}.Op())
		return layout.Dimensions{Size: image.Pt(w, h)}
	})
}

// layoutThemeRow renders the four background swatches with
// their names; a tap applies and persists the tier at once.
func (a *App) layoutThemeRow(gtx layout.Context) layout.Dimensions {
	cur := a.svc.Theme()
	tiers := []struct {
		value   string
		nameKey string
		p       Palette
		split   bool
	}{
		{service.ThemeLight, "theme.light", paletteLight, false},
		{service.ThemeNavy, "theme.navy", paletteNavy, false},
		{service.ThemeInk, "theme.ink", paletteInk, false},
		{service.ThemeSystem, "theme.system", paletteLight, true},
	}
	children := make([]layout.FlexChild, 0, len(tiers)*2)
	for i, t := range tiers {
		t := t
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout))
		}
		if a.themeBtns[i].Clicked(gtx) {
			a.svc.SetTheme(t.value)
		}
		children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return material.Clickable(gtx, &a.themeBtns[i], func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return a.swatch(gtx, t.p, t.split, cur == t.value)
						})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(a.lbl(12.5, font.Normal, pal.Secondary, a.T(t.nameKey, nil)).Layout),
				)
			})
		}))
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
}

// layoutPrefGroups renders the protocol-preference options as
// v3 option groups, followed by the post-hoc fallback line
// (only after an auto-select actually fell back) and the
// weak-encryption note.
func (a *App) layoutPrefGroups(gtx layout.Context) layout.Dimensions {
	pref := a.svc.ProtocolPref()
	opts := []struct{ value, titleKey, descKey string }{
		{service.ProtocolPrefAuto, "pref.auto", "pref.auto_desc"},
		{service.ProtocolPrefSpeed, "pref.speed", "pref.speed_desc"},
		{service.ProtocolPrefCompat, "pref.compat", "pref.compat_desc"},
	}
	rows := []layout.FlexChild{}
	for i, o := range opts {
		o := o
		if i > 0 {
			rows = append(rows, layout.Rigid(a.divider44))
		}
		btn := a.prefButton(o.value)
		if btn.Clicked(gtx) {
			a.svc.SetProtocolPref(o.value)
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.optionGroup(gtx, btn, pref == o.value, true,
				a.T(o.titleKey, nil), a.T(o.descKey, nil), "")
		}))
	}
	if name, fellBack, ok := a.svc.LastAutoSelect(); ok && fellBack {
		rows = append(rows,
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return iconLayout(gtx, iconWarn, 14, pal.Warn)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
					layout.Flexed(1, a.lblWrap(12.5, 17, font.Normal, pal.Warn,
						a.T("pref.fallback_note", map[string]string{"node": name}), 2).Layout),
				)
			}),
		)
	}
	rows = append(rows,
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(a.lblMax(12, font.Normal, pal.Hint, a.T("pref.weak", nil), 2).Layout),
	)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

// layoutModeGroups renders the run-mode options as v3 option
// groups; an unavailable mode stays listed, disabled, with its
// real reason inside the group.
func (a *App) layoutModeGroups(gtx layout.Context) layout.Dimensions {
	mode := a.svc.Mode()
	rows := []layout.FlexChild{}
	for i, opt := range a.svc.RunModeOptions() {
		opt := opt
		if i > 0 {
			rows = append(rows, layout.Rigid(a.divider44))
		}
		var titleKey, descKey string
		switch opt.Mode {
		case kernel.ModeTUN:
			titleKey, descKey = "mode.tun", "mode.tun_desc"
		case kernel.ModeSystemProxy:
			titleKey, descKey = "mode.system_proxy", "mode.system_proxy_desc"
		default:
			titleKey, descKey = "mode.manual", "mode.manual_desc"
		}
		reason := ""
		if !opt.Available {
			if opt.Reason == service.ModeReasonVersion {
				reason = a.T("mode.reason_version", nil)
			} else {
				reason = a.T("mode.reason_platform", nil)
			}
		}
		btn := a.modeButton(string(opt.Mode))
		if opt.Available && btn.Clicked(gtx) {
			a.svc.SetMode(opt.Mode)
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.optionGroup(gtx, btn, mode == opt.Mode, opt.Available,
				a.T(titleKey, nil), a.T(descKey, nil), reason)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

func packName(lang string) (string, error) {
	p, err := i18n.LoadPack(locales.FS, lang)
	if err != nil {
		return "", err
	}
	return p.Messages["lang.name"], nil
}

// Ensure the widget import is used even if widget sets change.
var _ = widget.Clickable{}
