package openvpn

import (
	"fmt"
	"strings"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Configuration generation for the openvpn child process.
//
// Two node shapes (unified model, package specnode):
//
//   - Full-text mode (credential.configContent): the .ovpn body is
//     passed through VERBATIM except for a controlled rewrite of
//     directives that would fight the adapter for control of the
//     process (its own management endpoint, daemonising, log/status
//     redirection, privilege drop, and any hook that executes
//     external code). The adapter then appends its management
//     block. This is the VPN Gate shape: those configs carry
//     inline <ca>/<cert>/<key> material and must not be re-rendered.
//
//   - Structured mode (credential fields): the config is assembled
//     field by field with inline PEM blocks.
//
// In both modes the generated file lives in a private per-session
// directory (0700, file 0600): it contains key material and is
// deleted when the session ends.

// stripDirectives are config directives removed (or rewritten) in
// full-text mode. Rationale per group:
//
//   - management*: the adapter owns the management endpoint; a
//     config-provided one would detach the process from supervision.
//   - daemon/syslog/log/log-append/status/writepid: the adapter
//     captures the child's stdout/stderr itself; daemonising would
//     orphan the process and defeat lifecycle supervision.
//   - user/group/chroot/setenv…: privilege drop or environment
//     control would break the adapter's control channel and is a
//     config-smuggling vector.
//   - plugin and every *-script hook (up/down/route-up/…): these
//     execute arbitrary external code; a node document must never
//     gain code execution through a config body (the same ruling
//     the VPN Gate plugin records for itself in Step 14).
//   - service/win-sys/tap-sleep/show-* (Windows service control):
//     the process is a child of the adapter, never a service.
var stripDirectives = map[string]bool{
	"management": true, "management-log-cache": true,
	"management-forget-disconnect": true, "management-query-passwords": true,
	"management-hold": true, "management-signal": true,
	"management-client-auth": true, "management-client-group": true,
	"management-client-pf": true, "management-client-user": true,
	"daemon": true, "daemonlog": true, "syslog": true,
	"log": true, "log-append": true, "status": true, "writepid": true,
	"chroot": true, "user": true, "group": true, "setenv": true,
	"setenv-safe": true, "plugin": true,
	"script-security": true, "up": true, "down": true,
	"route-up": true, "route-pre-down": true, "ipchange": true,
	"tls-verify": true, "auth-user-pass-verify": true,
	"auth-gen-token": true, "client-connect": true,
	"client-disconnect": true, "learn-address": true,
	"service": true, "win-sys": true, "tap-sleep": true,
	"show-net-up": true, "show-adapters": true,
}

// buildOptions parameterises one generated configuration.
type buildOptions struct {
	// mgmtLines is the adapter management block (endpoint lines),
	// produced by the platform endpoint code.
	mgmtLines []string
	// devOverride replaces any dev directive when non-empty.
	// Diagnostics/testing only (e.g. the CI rig's null device);
	// production passes "".
	devOverride string
	// extra directives appended after the management block
	// (adapter-controlled, e.g. test rigs).
	extra []string
}

type builtConfig struct {
	text string
	// rewritten names the directives dropped or rewritten in
	// full-text mode, for diagnostics (never secret values).
	rewritten []string
	// proto is the effective transport protocol of the session
	// ("udp" or "tcp"), best-effort from the config.
	proto string
	// usesAuth is true when the session may ask for a
	// username/password over the management interface.
	usesAuth bool
	// authRequired is true when the profile itself demands
	// username/password authentication (an auth-user-pass
	// directive survived rendering), whether or not the node
	// carries credentials. Full-text mode only: structured
	// mode emits auth-user-pass solely when a username is
	// present, so there authRequired == usesAuth. Consumers
	// without a management interface (OpenVPN 3) need this
	// to refuse credential-less auth profiles up front.
	authRequired bool
}

func firstToken(line string) string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return ""
	}
	return strings.ToLower(f[0])
}

// buildConfig renders the session configuration for a spec node.
func buildConfig(n *specnode.Node, bo buildOptions) (*builtConfig, error) {
	if n == nil || n.OpenVPN == nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "BuildConfig",
			"node carries no OpenVPN credential", nil)
	}
	var bc *builtConfig
	var err error
	if n.OpenVPN.ConfigContent != "" {
		bc, err = buildPassthrough(n, bo)
	} else {
		bc, err = buildStructured(n, bo)
	}
	if err != nil {
		return nil, err
	}
	// The adapter management block always comes last: OpenVPN
	// honours the last occurrence of most directives, and the
	// block must win over anything the body tried to set.
	var b strings.Builder
	b.WriteString(bc.text)
	if !strings.HasSuffix(bc.text, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("# --- relavia openvpn adapter: managed block ---\n")
	for _, l := range bo.mgmtLines {
		b.WriteString(l + "\n")
	}
	b.WriteString("management-query-passwords\n")
	if bc.usesAuth {
		b.WriteString("auth-nocache\n")
	}
	for _, l := range bo.extra {
		b.WriteString(l + "\n")
	}
	bc.text = b.String()
	return bc, nil
}

func buildPassthrough(n *specnode.Node, bo buildOptions) (*builtConfig, error) {
	content := strings.ReplaceAll(n.OpenVPN.ConfigContent, "\r\n", "\n")
	bc := &builtConfig{proto: "udp"}
	var out []string
	hasVerb := false
	hasAuthUserPass := false
	sawRemote := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out = append(out, line)
			continue
		}
		tok := firstToken(trimmed)
		switch {
		case stripDirectives[tok]:
			bc.rewritten = append(bc.rewritten, tok)
			continue
		case tok == "auth-user-pass" && len(strings.Fields(trimmed)) > 1:
			// A file argument would point at a file the adapter
			// does not control; the credentials travel over the
			// management interface instead.
			out = append(out, "auth-user-pass")
			hasAuthUserPass = true
			bc.rewritten = append(bc.rewritten, "auth-user-pass(file->management)")
			continue
		case tok == "auth-user-pass":
			hasAuthUserPass = true
		case tok == "verb":
			hasVerb = true
		case tok == "proto":
			f := strings.Fields(trimmed)
			if len(f) >= 2 {
				p := strings.ToLower(f[1])
				if strings.HasPrefix(p, "tcp") {
					bc.proto = "tcp"
				} else {
					bc.proto = "udp"
				}
			}
		case tok == "remote":
			sawRemote = true
		case tok == "dev" && bo.devOverride != "":
			out = append(out, "dev "+bo.devOverride)
			bc.rewritten = append(bc.rewritten, "dev(override)")
			continue
		}
		out = append(out, line)
	}
	if !sawRemote {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "BuildConfig",
			"openvpn config body has no remote directive; the node cannot be connected", nil)
	}
	// Node-level credentials on a body without an auth directive:
	// enable the management password query so they can be used.
	if n.OpenVPN.Username != "" && !hasAuthUserPass {
		out = append(out, "auth-user-pass")
		hasAuthUserPass = true
		bc.rewritten = append(bc.rewritten, "auth-user-pass(added)")
	}
	if !hasVerb {
		out = append(out, "verb 3")
	}
	bc.authRequired = hasAuthUserPass
	bc.usesAuth = hasAuthUserPass && n.OpenVPN.Username != ""
	bc.text = strings.Join(out, "\n") + "\n"
	return bc, nil
}

func buildStructured(n *specnode.Node, bo buildOptions) (*builtConfig, error) {
	c := n.OpenVPN
	if c.CACert == "" {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "BuildConfig",
			"openvpn structured mode requires a CA certificate (caCert); without one the TLS handshake cannot be verified", nil)
	}
	bc := &builtConfig{}
	proto := strings.ToLower(c.Proto)
	ovpnProto := proto
	switch {
	case strings.HasPrefix(proto, "tcp"):
		ovpnProto = "tcp-client"
		// Preserve the address-family suffix (tcp4/tcp6-client
		// is not valid syntax; the family goes on the proto as
		// tcp-client + proto v4/v6 handled by openvpn as
		// "tcp4-client"/"tcp6-client").
		if proto == "tcp4" || proto == "tcp6" {
			ovpnProto = proto + "-client"
		}
		bc.proto = "tcp"
	default:
		bc.proto = "udp"
	}
	dev := "tun"
	if bo.devOverride != "" {
		dev = bo.devOverride
	}
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev " + dev + "\n")
	b.WriteString("proto " + ovpnProto + "\n")
	fmt.Fprintf(&b, "remote %s %d\n", n.Server, n.Port)
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("nobind\n")
	if c.DataCiphers != "" {
		b.WriteString("data-ciphers " + c.DataCiphers + "\n")
	}
	if c.Cipher != "" {
		b.WriteString("cipher " + c.Cipher + "\n")
	}
	if c.AuthDigest != "" {
		b.WriteString("auth " + c.AuthDigest + "\n")
	}
	writeInline := func(tag, pem string) {
		if pem == "" {
			return
		}
		b.WriteString("<" + tag + ">\n")
		b.WriteString(strings.TrimSpace(pem) + "\n")
		b.WriteString("</" + tag + ">\n")
	}
	writeInline("ca", c.CACert)
	writeInline("cert", c.ClientCert)
	writeInline("key", c.ClientKey)
	if c.TLSAuthKey != "" {
		dir := 1
		if c.KeyDirection != nil {
			dir = *c.KeyDirection
		}
		fmt.Fprintf(&b, "key-direction %d\n", dir)
		writeInline("tls-auth", c.TLSAuthKey)
	}
	if c.TLSCryptKey != "" {
		writeInline("tls-crypt", c.TLSCryptKey)
	}
	if c.RedirectGateway {
		b.WriteString("redirect-gateway def1\n")
	}
	if c.BlockOutsideDNS {
		b.WriteString("block-outside-dns\n")
	}
	if c.Username != "" {
		b.WriteString("auth-user-pass\n")
		bc.usesAuth = true
	}
	b.WriteString("verb 3\n")
	bc.text = b.String()
	return bc, nil
}

// redactor masks credential material out of log lines before they
// reach the application's log view or any diagnostic surface. The
// generated config text itself is never logged; this guards the
// child's own output (openvpn echoes usernames in some paths) and
// adapter-generated lines.
type redactor struct {
	secrets []string
}

func newRedactor(n *specnode.Node) *redactor {
	r := &redactor{}
	if n != nil && n.OpenVPN != nil {
		for _, s := range []string{n.OpenVPN.Password, n.OpenVPN.Username} {
			if len(s) >= 2 {
				r.secrets = append(r.secrets, s)
			}
		}
	}
	return r
}

func (r *redactor) line(s string) string {
	if r == nil {
		return s
	}
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}
