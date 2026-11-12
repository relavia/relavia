package kernel

import "fmt"

// KnownProtocol reports whether p is a protocol named in proposal
// book 4.1 (first or second tier). Unknown protocols are a structural
// error (KindInvalidConfig); known-but-not-in-an-adapter's-matrix is
// KindUnsupported instead.
func KnownProtocol(p Protocol) bool {
	switch p {
	case ProtocolShadowsocks, ProtocolTrojan, ProtocolVMess,
		ProtocolVLESS, ProtocolHysteria2, ProtocolTUIC,
		ProtocolWireGuard, ProtocolOpenVPN, ProtocolSOCKS5,
		ProtocolHTTP, ProtocolSoftEther, ProtocolL2TP,
		ProtocolSSTP, ProtocolAnyTLS:
		return true
	}
	return false
}

// ValidateNode performs STRUCTURAL validation of a node: required
// fields present and in range. It does not check adapter support;
// adapters layer the Capabilities check on top (see
// ValidateAgainst). Returns *Error with Kind KindInvalidConfig.
//
// NOTE (Step 5 placeholder): these field rules mirror the minimal
// placeholder model in config.go and must be re-derived from the
// Step 5 spec/ JSON Schema when it lands.
func ValidateNode(n *Node) error {
	if n == nil {
		return NewError(KindInvalidConfig, "ValidateConfig", "node is nil", nil)
	}
	if n.Server == "" {
		return NewError(KindInvalidConfig, "ValidateConfig",
			"node.server is empty", nil)
	}
	if n.Port < 1 || n.Port > 65535 {
		return NewError(KindInvalidConfig, "ValidateConfig",
			fmt.Sprintf("node.port %d out of range 1..65535", n.Port), nil)
	}
	if n.Protocol == "" {
		return NewError(KindInvalidConfig, "ValidateConfig",
			"node.protocol is empty", nil)
	}
	if !KnownProtocol(n.Protocol) {
		return NewError(KindInvalidConfig, "ValidateConfig",
			fmt.Sprintf("node.protocol %q is not a known protocol", n.Protocol), nil)
	}
	if n.Transport.Type == "" {
		return NewError(KindInvalidConfig, "ValidateConfig",
			"node.transport.type is empty", nil)
	}
	// Reality without a public key can never handshake; catch it
	// structurally instead of at dial time.
	if n.Security.Type == SecurityReality && n.Security.PublicKey == "" {
		return NewError(KindInvalidConfig, "ValidateConfig",
			"reality security requires security.publicKey", nil)
	}
	return nil
}

// ValidateAgainst validates a full Config for a specific adapter:
// structural validation, then the Capabilities support check.
// Adapter ValidateConfig implementations should call this so all
// adapters share identical validation semantics.
func ValidateAgainst(cfg *Config, caps Capabilities) error {
	if cfg == nil {
		return NewError(KindInvalidConfig, "ValidateConfig", "config is nil", nil)
	}
	if err := ValidateNode(cfg.Node); err != nil {
		return err
	}
	if !caps.SupportsNode(cfg.Node) {
		return NewError(KindUnsupported, "ValidateConfig",
			fmt.Sprintf("combination %s/%s/%s not supported by kernel %q",
				cfg.Node.Protocol, cfg.Node.Transport.Type,
				cfg.Node.Security.Type, caps.KernelID), nil)
	}
	return nil
}
