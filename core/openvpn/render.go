package openvpn

import (
	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// WrapClassified attaches one of this package's stable
// failure classification codes (CodeAuthFailed, ...) to a
// kernel error, producing an error CodeOf can recover the
// code from. It exists for sibling consumers that reproduce
// this adapter's failure semantics over a different transport
// (the Android OpenVPN 3 bridge classifying native core
// events), so the whole product speaks one taxonomy.
func WrapClassified(code string, kerr *kernel.Error) error {
	if kerr == nil {
		return nil
	}
	return &classifiedError{code: code, kerr: kerr}
}

// RenderedProfile is an OpenVPN profile rendered for an
// in-process OpenVPN 3 session (Android, docs/openvpn3安卓
// 接线.md). It is produced by the same builders the desktop
// process adapter uses, so the safety posture is shared: hook
// and control directives are stripped in full-text mode, and
// structured mode is assembled field by field. The difference
// is what is NOT here: the process adapter's management block
// (management endpoint lines, management-query-passwords,
// auth-nocache) is a child-process control artifact and is
// never appended — OpenVPN 3 takes credentials through its
// ProvideCreds API instead.
type RenderedProfile struct {
	// Text is the complete profile body to hand to the
	// OpenVPN 3 core (Config.content).
	Text string
	// Proto is the effective transport ("udp" or "tcp"),
	// best-effort from the profile.
	Proto string
	// UsesAuth reports that the profile may ask for a
	// username/password (auth-user-pass present).
	UsesAuth bool
	// Username / Password are the node-level credentials,
	// to be supplied via ProvideCreds when UsesAuth is set.
	// Empty when the node carries none.
	Username string
	Password string
	// Rewritten names the directives dropped or rewritten
	// while rendering (diagnostics only, never values).
	Rewritten []string
}

// RenderProfile renders the session profile for an OpenVPN 3
// consumer. It fails with KindInvalidConfig on the same
// conditions buildConfig rejects (no OpenVPN credential, no
// remote in full-text mode, missing CA in structured mode).
// A node whose profile needs credentials it does not carry
// fails with a classified auth_credentials_missing error,
// matching the desktop adapter's startup classification, so
// the bridge never starts a session that can only fail at
// AUTH_FAILED time.
func RenderProfile(n *specnode.Node) (*RenderedProfile, error) {
	if n == nil || n.OpenVPN == nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "RenderProfile",
			"node carries no OpenVPN credential", nil)
	}
	var bc *builtConfig
	var err error
	if n.OpenVPN.ConfigContent != "" {
		bc, err = buildPassthrough(n, buildOptions{})
	} else {
		bc, err = buildStructured(n, buildOptions{})
	}
	if err != nil {
		return nil, err
	}
	rp := &RenderedProfile{
		Text:      bc.text,
		Proto:     bc.proto,
		UsesAuth:  bc.authRequired || bc.usesAuth,
		Username:  n.OpenVPN.Username,
		Password:  n.OpenVPN.Password,
		Rewritten: bc.rewritten,
	}
	if bc.authRequired && rp.Username == "" {
		return nil, &classifiedError{
			code: CodeAuthNoCredentials,
			kerr: kernel.NewError(kernel.KindInvalidConfig, "RenderProfile",
				"profile requires username/password authentication but the node carries no credentials", nil),
		}
	}
	return rp, nil
}
