package vpngate

// Risk-disclosure wiring (book 7.3, hard requirement).
//
// Placement ruling (recorded in docs/step14-VPNGate来源插件.md):
// the consent STATE MACHINE lives in this plugin package
// (consent.go) because the gate guards plugin activation; the
// display STRINGS live in the app i18n packs (app/locales) as
// risk.vpngate.* keys alongside the Step 9 risk.* family, so the
// app's trilingual completeness checks (tools/i18ncheck, i18n
// package tests) cover them and no Step 9 interface changes.
//
// The zh-Hans text of RiskBodyKey reproduces the fixed sentence
// of book 7.3 verbatim and extends it with the remaining points
// of VPN Gate's official anti-abuse policy (packet logs kept two
// weeks or more, disclosure to police/courts on legal demand,
// nodes running on volunteers' personal computers, reachability
// tool rather than privacy tool). All three shipped languages
// are human translations; risk strings must never ship
// machine-translated (book 8.1 / Step 9 discipline).
const (
	// RiskTextVersion identifies the exact risk wording the user
	// acknowledged. It mirrors manifest.riskText.version. Any
	// wording change must bump it, which invalidates earlier
	// acknowledgements (see consent.go).
	RiskTextVersion = "vpngate-risk-v1"

	RiskTitleKey    = "risk.vpngate.title"
	RiskBodyKey     = "risk.vpngate.body"
	RiskNodeLineKey = "risk.vpngate.node_line"
	RiskConfirmKey  = "risk.vpngate.confirm"
	RiskDeclineKey  = "risk.vpngate.decline"
	RiskRevokeKey   = "risk.vpngate.revoke"
)

// RiskKeys lists every i18n key of the consent gate, in display
// order. The app renders the intercept page from these keys;
// RiskNodeLineKey is the one-line notice permanently shown in
// node details (book 7.3).
func RiskKeys() []string {
	return []string{
		RiskTitleKey, RiskBodyKey, RiskNodeLineKey,
		RiskConfirmKey, RiskDeclineKey, RiskRevokeKey,
	}
}
