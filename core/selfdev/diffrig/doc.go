// Package diffrig is the differential test rig of the
// self-development route (docs/自研协议路线-01-shadowsocks.md
// section 4): the self-developed Shadowsocks engine is run
// against two independent reference servers - shadowsocks-rust
// (server A) and a sing-box inbound (server B) - with the
// sing-box outbound as the control client, comparing four
// layers: result, plaintext, structure (fixed-salt wire bytes
// against the frozen vectors) and error classification.
//
// The rig lives in tests: this package ships no production
// code. Server A is located via the RELAVIA_SSSERVER
// environment variable or PATH and tests skip loudly without
// it; CI installs shadowsocks-rust v1.25.0 (the version the
// spec's section 6 verification was cross-checked against).
package diffrig
