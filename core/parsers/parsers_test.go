package parsers

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	uuidA = "20000000-0000-4000-8000-0000000000a1"
	uuidB = "20000000-0000-4000-8000-0000000000b2"
	uuidC = "20000000-0000-4000-8000-0000000000c3"

	wgPriv = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	wgPub  = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	wgPsk  = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="
)

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func credOf(t *testing.T, n *Node) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(n.Credential, &m); err != nil {
		t.Fatalf("credential not JSON: %v", err)
	}
	return m
}

func hasWarn(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

func mustNode(t *testing.T, r LinkResult) *Node {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("unexpected parse error: %v", r.Err)
	}
	if r.Node == nil {
		t.Fatal("nil node without error")
	}
	return r.Node
}

// ---------------------------------------------------------------------------
// 正例：分享链接（每格式至少 2 条，含参数变体）
// ---------------------------------------------------------------------------

type linkCase struct {
	name      string
	raw       string
	protocol  string
	server    string
	port      int
	nodeName  string
	warnCodes []string
	check     func(t *testing.T, n *Node)
}

func linkCases() []linkCase {
	return []linkCase{
		{
			name: "ss SIP002 AEAD", protocol: "shadowsocks", server: "ss1.example.com", port: 8388, nodeName: "SS-SIP002",
			raw: "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@ss1.example.com:8388#SS-SIP002",
			check: func(t *testing.T, n *Node) {
				c := credOf(t, n)
				if c["method"] != "aes-256-gcm" || c["password"] != "password123" {
					t.Errorf("cred = %v", c)
				}
			},
		},
		{
			name: "ss SIP002 plain userinfo + plugin", protocol: "shadowsocks", server: "ss2.example.com", port: 8389, nodeName: "SS-Plugin",
			raw: "ss://chacha20-ietf-poly1305:plainpass@ss2.example.com:8389/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#SS-Plugin",
			check: func(t *testing.T, n *Node) {
				c := credOf(t, n)
				if c["plugin"] != "v2ray-plugin" || c["pluginOpts"] != "mode=websocket;host=cdn.example.com" {
					t.Errorf("plugin = %v", c)
				}
			},
		},
		{
			name: "ss legacy whole-base64 weak", protocol: "shadowsocks", server: "ss3.example.com", port: 8390, nodeName: "SS-Legacy",
			raw:       "ss://YWVzLTI1Ni1jZmI6bGVnYWN5cGFzc0BzczMuZXhhbXBsZS5jb206ODM5MA==#SS-Legacy",
			warnCodes: []string{WarnWeakEncryption, WarnDeprecatedFormat},
			check: func(t *testing.T, n *Node) {
				if credOf(t, n)["method"] != "aes-256-cfb" {
					t.Errorf("method = %v", credOf(t, n))
				}
			},
		},
		{
			name: "vless reality vision", protocol: "vless", server: "vl.example.com", port: 443, nodeName: "VLESS-Reality",
			raw: "vless://" + uuidA + "@vl.example.com:443?encryption=none&security=reality&pbk=REALITYKEY43CHARSAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123abcd&spx=%2F&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp&headerType=none#VLESS-Reality",
			check: func(t *testing.T, n *Node) {
				c := credOf(t, n)
				if c["flow"] != "xtls-rprx-vision" {
					t.Errorf("flow = %v", c)
				}
				if n.Security == nil || n.Security.Type != "reality" || n.Security.PublicKey == "" || n.Security.ShortID != "0123abcd" {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
		{
			name: "vless ws tls", protocol: "vless", server: "vl2.example.com", port: 443, nodeName: "VLESS-WS",
			raw: "vless://" + uuidB + "@vl2.example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com&sni=vl2.example.com&alpn=h2%2Chttp%2F1.1#VLESS-WS",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.Type != "ws" || n.Transport.Path != "/ws" || n.Transport.Host != "cdn.example.com" {
					t.Errorf("transport = %+v", n.Transport)
				}
				if n.Security == nil || n.Security.Type != "tls" || len(n.Security.ALPN) != 2 {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
		{
			name: "vmess base64 ws tls", protocol: "vmess", server: "vm.example.com", port: 443, nodeName: "VMess-WS-TLS",
			raw: "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtV1MtVExTIiwiYWRkIjoidm0uZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIyMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDMiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiY2RuLmV4YW1wbGUuY29tIiwicGF0aCI6Ii92bXdzIiwidGxzIjoidGxzIiwic25pIjoidm0uZXhhbXBsZS5jb20iLCJhbHBuIjoiaDIsaHR0cC8xLjEiLCJmcCI6ImNocm9tZSJ9",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.Type != "ws" || n.Transport.Path != "/vmws" {
					t.Errorf("transport = %+v", n.Transport)
				}
				if n.Security == nil || n.Security.Type != "tls" {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
		{
			name: "vmess base64 grpc", protocol: "vmess", server: "vm2.example.com", port: 8443, nodeName: "VMess-gRPC",
			raw: "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtZ1JQQyIsImFkZCI6InZtMi5leGFtcGxlLmNvbSIsInBvcnQiOjg0NDMsImlkIjoiMjAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDEzIiwiYWlkIjowLCJzY3kiOiJhZXMtMTI4LWdjbSIsIm5ldCI6ImdycGMiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoidm0tZ3JwYy1zZXJ2aWNlIiwidGxzIjoidGxzIiwic25pIjoidm0yLmV4YW1wbGUuY29tIn0=",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.Type != "grpc" || n.Transport.ServiceName != "vm-grpc-service" {
					t.Errorf("transport = %+v", n.Transport)
				}
				if credOf(t, n)["cipher"] != "aes-128-gcm" {
					t.Errorf("cipher = %v", credOf(t, n))
				}
			},
		},
		{
			name: "vmess query form", protocol: "vmess", server: "vm3.example.com", port: 443, nodeName: "VMess-Query",
			raw: "vmess://" + uuidC + "@vm3.example.com:443?type=ws&security=tls&path=%2Fp&host=h.example.com&sni=vm3.example.com#VMess-Query",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.Type != "ws" {
					t.Errorf("transport = %+v", n.Transport)
				}
			},
		},
		{
			name: "trojan ws", protocol: "trojan", server: "tj.example.com", port: 443, nodeName: "Trojan-WS",
			raw: "trojan://tjpass@tj.example.com:443?type=ws&path=%2Ft&host=cdn.example.com&sni=tj.example.com&fp=chrome#Trojan-WS",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.Type != "ws" {
					t.Errorf("transport = %+v", n.Transport)
				}
				if n.Security == nil || n.Security.Type != "tls" || n.Security.Fingerprint != "chrome" {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
		{
			name: "trojan default port", protocol: "trojan", server: "tj2.example.com", port: 443, nodeName: "Trojan-Plain",
			raw: "trojan://tjpass@tj2.example.com?sni=tj2.example.com#Trojan-Plain",
			check: func(t *testing.T, n *Node) {
				if n.Transport != nil {
					t.Errorf("transport should be nil, got %+v", n.Transport)
				}
			},
		},
		{
			name: "hysteria2 basic", protocol: "hysteria2", server: "hy.example.com", port: 443, nodeName: "HY2",
			raw: "hysteria2://auth123@hy.example.com:443?sni=hy.example.com&alpn=h3#HY2",
			check: func(t *testing.T, n *Node) {
				if credOf(t, n)["auth"] != "auth123" {
					t.Errorf("auth = %v", credOf(t, n))
				}
			},
		},
		{
			name: "hy2 obfs mport insecure", protocol: "hysteria2", server: "hy2.example.com", port: 8443, nodeName: "HY2-Obfs",
			raw:       "hy2://user:pass@hy2.example.com:8443?obfs=salamander&obfs-password=obfspw&mport=20000-30000&insecure=1#HY2-Obfs",
			warnCodes: []string{WarnInsecureSkipVerify},
			check: func(t *testing.T, n *Node) {
				c := credOf(t, n)
				if c["auth"] != "user:pass" || c["obfsPassword"] != "obfspw" {
					t.Errorf("cred = %v", c)
				}
				if len(n.ExtraPorts) != 1 || n.ExtraPorts[0] != "20000-30000" {
					t.Errorf("extraPorts = %v", n.ExtraPorts)
				}
			},
		},
		{
			name: "tuic bbr", protocol: "tuic", server: "tuic.example.com", port: 443, nodeName: "TUIC",
			raw: "tuic://" + uuidA + ":tupass@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example.com&alpn=h3#TUIC",
			check: func(t *testing.T, n *Node) {
				if n.Transport == nil || n.Transport.CongestionControl != "bbr" || n.Transport.UDPRelayMode != "native" {
					t.Errorf("transport = %+v", n.Transport)
				}
			},
		},
		{
			name: "tuic disable sni insecure", protocol: "tuic", server: "tuic2.example.com", port: 10443, nodeName: "TUIC2",
			raw:       "tuic://" + uuidB + ":tupass@tuic2.example.com:10443?disable_sni=1&allow_insecure=1#TUIC2",
			warnCodes: []string{WarnInsecureSkipVerify},
			check: func(t *testing.T, n *Node) {
				if n.Security == nil || n.Security.ServerName != "" {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
		{
			name: "wireguard link", protocol: "wireguard", server: "wg.example.com", port: 51820, nodeName: "WG-Link",
			raw: "wg://" + wgPriv + "@wg.example.com:51820?publickey=" + wgPub + "&presharedkey=" + wgPsk + "&address=10.0.0.2%2F32&dns=1.1.1.1&allowedips=0.0.0.0%2F0%2C%3A%3A%2F0&keepalive=25&mtu=1280#WG-Link",
			check: func(t *testing.T, n *Node) {
				c := credOf(t, n)
				if c["privateKey"] != wgPriv || c["peerPublicKey"] != wgPub {
					t.Errorf("keys = %v", c)
				}
				addrs, _ := c["addresses"].([]any)
				if len(addrs) != 1 || addrs[0] != "10.0.0.2/32" {
					t.Errorf("addresses = %v", c["addresses"])
				}
			},
		},
		{
			name: "wireguard link default allowedips", protocol: "wireguard", server: "wg2.example.com", port: 51820, nodeName: "WG-Link2",
			raw:       "wireguard://" + wgPriv + "@wg2.example.com?publickey=" + wgPub + "&address=10.0.0.3%2F32#WG-Link2",
			warnCodes: []string{WarnDefaultedField},
			check: func(t *testing.T, n *Node) {
				if n.Port != 51820 {
					t.Errorf("port = %d", n.Port)
				}
			},
		},
		{
			name: "socks5 auth", protocol: "socks5", server: "so.example.com", port: 1080, nodeName: "SOCKS5",
			raw: "socks5://user:sopass@so.example.com:1080#SOCKS5",
			check: func(t *testing.T, n *Node) {
				if credOf(t, n)["username"] != "user" {
					t.Errorf("cred = %v", credOf(t, n))
				}
			},
		},
		{
			name: "socks5 no auth", protocol: "socks5", server: "so2.example.com", port: 1081, nodeName: "SOCKS5-NoAuth",
			raw: "socks5://so2.example.com:1081#SOCKS5-NoAuth",
			check: func(t *testing.T, n *Node) {
				if len(credOf(t, n)) != 0 {
					t.Errorf("cred should be empty, got %v", credOf(t, n))
				}
			},
		},
		{
			name: "http proxy", protocol: "http", server: "hp.example.com", port: 8080, nodeName: "HTTP",
			raw: "http://user:hppass@hp.example.com:8080#HTTP",
			check: func(t *testing.T, n *Node) {
				if n.Security != nil {
					t.Errorf("security should be nil for plain http, got %+v", n.Security)
				}
			},
		},
		{
			name: "https proxy", protocol: "http", server: "hp2.example.com", port: 8443, nodeName: "HTTPS",
			raw: "https://user:hppass@hp2.example.com:8443#HTTPS",
			check: func(t *testing.T, n *Node) {
				if n.Security == nil || n.Security.Type != "tls" {
					t.Errorf("security = %+v", n.Security)
				}
			},
		},
	}
}

func TestParseLinkPositives(t *testing.T) {
	for _, tc := range linkCases() {
		t.Run(tc.name, func(t *testing.T) {
			r := ParseLink(tc.raw, Options{})
			n := mustNode(t, r)
			if n.Protocol != tc.protocol || n.Server != tc.server || n.Port != tc.port || n.Name != tc.nodeName {
				t.Errorf("got %s %s:%d %q, want %s %s:%d %q", n.Protocol, n.Server, n.Port, n.Name, tc.protocol, tc.server, tc.port, tc.nodeName)
			}
			if n.SchemaVersion != "1.0" || n.Source.Kind != "manual" || n.Source.Authorization != "user-provided" {
				t.Errorf("bad common fields: %+v", n)
			}
			for _, code := range tc.warnCodes {
				if !hasWarn(r.Warnings, code) {
					t.Errorf("missing warning %s, got %v", code, r.Warnings)
				}
			}
			if tc.check != nil {
				tc.check(t, n)
			}
			// id 确定性：同一链接重复解析 id 不变。
			r2 := ParseLink(tc.raw, Options{})
			if mustNode(t, r2).ID != n.ID {
				t.Error("non-deterministic node id")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 反例：异常样本必须结构化报错且不 panic
// ---------------------------------------------------------------------------

func TestParseLinkNegatives(t *testing.T) {
	cases := []struct {
		name, raw, code string
	}{
		{"empty", "", ErrEmptyInput},
		{"blank", "   ", ErrEmptyInput},
		{"unknown scheme", "ssr://abcdef", ErrUnknownScheme},
		{"no scheme", "just-a-string", ErrUnknownScheme},
		{"vless bad uuid", "vless://not-a-uuid@h.example.com:443", ErrBadUUID},
		{"vless port too big", "vless://" + uuidA + "@h.example.com:99999", ErrBadPort},
		{"vless reality missing pbk", "vless://" + uuidA + "@h.example.com:443?security=reality", ErrMissingField},
		{"vless bad flow", "vless://" + uuidA + "@h.example.com:443?flow=xtls-rprx-direct", ErrUnsupportedValue},
		{"ss bad base64", "ss://!!!not-base64!!!", ErrBadBase64},
		{"ss port zero", "ss://YWVzLTI1Ni1nY206cGFzcw@h.example.com:0", ErrBadPort},
		{"ss unknown method", "ss://dW5rbm93bi1jaXBoZXI6cHc@h.example.com:8388", ErrUnsupportedValue},
		{"vmess bad json", "vmess://e25vdCBhIGpzb24=", ErrBadJSON},
		{"vmess missing id", "vmess://eyJhZGQiOiAieC5leGFtcGxlLmNvbSIsICJwb3J0IjogNDQzfQ==", ErrBadUUID},
		{"vmess truncated b64", "vmess://eyJ2Ijoi", ErrBadJSON},
		{"trojan empty password", "trojan://@h.example.com:443", ErrMissingField},
		{"tuic missing password", "tuic://" + uuidA + "@h.example.com:443", ErrMissingField},
		{"tuic bad congestion", "tuic://" + uuidA + ":pw@h.example.com:443?congestion_control=turbo", ErrUnsupportedValue},
		{"hy2 obfs without password", "hysteria2://auth@h.example.com:443?obfs=salamander", ErrMissingField},
		{"hy2 bad mport", "hysteria2://auth@h.example.com:443?mport=99999-100000", ErrBadPort},
		{"wg bad private key", "wg://shortkey@h.example.com:51820?publickey=" + wgPub + "&address=10.0.0.2%2F32", ErrBadKeyFormat},
		{"wg missing address", "wg://" + wgPriv + "@h.example.com:51820?publickey=" + wgPub, ErrMissingField},
		{"socks5 user without password", "socks5://useronly@h.example.com:1080", ErrMissingField},
		{"oversized link", "ss://" + strings.Repeat("A", 70000), ErrInputTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ParseLink(tc.raw, Options{})
			if r.Err == nil {
				t.Fatalf("expected error %s, got node %+v", tc.code, r.Node)
			}
			if r.Err.Code != tc.code {
				t.Errorf("error code = %s (%v), want %s", r.Err.Code, r.Err, tc.code)
			}
			if r.Node != nil {
				t.Error("node must be nil on error")
			}
		})
	}
}

// 任意截断/变异输入不得 panic。
func TestNoPanicOnGarbage(t *testing.T) {
	seeds := []string{
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@ss1.example.com:8388#X",
		"vless://" + uuidA + "@vl.example.com:443?security=reality&pbk=K&flow=xtls-rprx-vision#X",
		"vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtV1MtVExTIiwiYWRkIjoidm0uZXhhbXBsZS5jb20ifQ==",
		"wg://" + wgPriv + "@wg.example.com:51820?publickey=" + wgPub + "&address=10.0.0.2%2F32",
	}
	parse := func(s string) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic on %q: %v", s, rec)
			}
		}()
		_ = ParseLink(s, Options{})
		_ = ParseSubscription([]byte(s), SubscriptionOptions{})
	}
	for _, s := range seeds {
		for i := 0; i <= len(s); i += 7 {
			parse(s[:i])
		}
		parse(s)
		for _, cut := range []string{"://", "@", "?", "#", "%", "%zz", "\x00", "🎉"} {
			parse(strings.Replace(s, "://", cut, 1))
		}
	}
	parse(strings.Repeat("🎉", 5000))
	_ = ParseWireGuardConf("[Interface]\nPrivateKey = x\n[Peer]\n", Options{})
	_ = ParseOpenVPNConf("garbage without markers", Options{})
	_ = ParseVPNGateCSV("a,b,c\n1,2,3", Options{})
}

// ---------------------------------------------------------------------------
// 批量与订阅
// ---------------------------------------------------------------------------

func TestParseLinkListMixed(t *testing.T) {
	text := "# comment line\n" +
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@ss1.example.com:8388#OK1\n" +
		"\n" +
		"this is not a link\n" +
		"vless://" + uuidB + "@vl2.example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com#OK2\n"
	out := ParseLinkList(text, Options{})
	if len(out.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(out.Items))
	}
	if out.OK() != 2 {
		t.Errorf("ok = %d, want 2", out.OK())
	}
	bad := out.Items[1]
	if bad.Err == nil || bad.Err.Code != ErrUnknownScheme || bad.Err.Index != 1 {
		t.Errorf("bad item = %+v", bad)
	}
	if out.Items[0].Node == nil || out.Items[2].Node == nil {
		t.Error("good items must carry nodes")
	}
}

func TestParseSubscriptionV2RayBase64(t *testing.T) {
	list := "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@ss1.example.com:8388#A\n" +
		"trojan://tjpass@tj.example.com:443# B\n" +
		"hysteria2://auth123@hy.example.com:443#C"
	out := ParseSubscription([]byte(b64s(list)), SubscriptionOptions{
		Options: Options{},
		URL:     "https://subs.example.com/token123",
		Name:    "测试订阅",
	})
	if out.Format != "v2ray-base64" {
		t.Errorf("format = %s", out.Format)
	}
	if out.OK() != 3 {
		t.Fatalf("ok = %d, items = %+v", out.OK(), out.Items)
	}
	if out.Group == nil || len(out.Group.NodeIDs) != 3 || out.Group.Name != "测试订阅" {
		t.Errorf("group = %+v", out.Group)
	}
	if out.Subscription == nil || out.Subscription.Format != "v2ray-base64" || out.Subscription.GroupName != "测试订阅" {
		t.Errorf("subscription = %+v", out.Subscription)
	}
	if out.SourceRecord == nil || out.SourceRecord.Kind != "subscription" || out.SourceRecord.Authorization.Status != "B" {
		t.Errorf("source = %+v", out.SourceRecord)
	}
	for _, it := range out.Items {
		if it.Node.Group != "测试订阅" || it.Node.Source.Kind != "subscription" {
			t.Errorf("node source/group = %+v", it.Node)
		}
	}
}

func TestParseSubscriptionPlainList(t *testing.T) {
	out := ParseSubscription([]byte("socks5://so.example.com:1080#S\n"), SubscriptionOptions{})
	if out.Format != "link-list" || out.OK() != 1 {
		t.Errorf("format=%s ok=%d", out.Format, out.OK())
	}
	if out.Subscription != nil {
		t.Error("subscription record must be nil without URL")
	}
}

const singBoxSample = `{
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["a"]},
    {"type": "direct", "tag": "direct"},
    {"type": "shadowsocks", "tag": "SB-SS", "server": "sb-ss.example.com", "server_port": 8388,
     "method": "aes-256-gcm", "password": "sbpass", "network": "tcp,udp"},
    {"type": "vless", "tag": "SB-VLESS", "server": "sb-vl.example.com", "server_port": 443,
     "uuid": "` + uuidA + `", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.example.com",
             "reality": {"enabled": true, "public_key": "SBREALITYKEY", "short_id": "ab12"},
             "utls": {"enabled": true, "fingerprint": "chrome"}}},
    {"type": "vmess", "tag": "SB-VMess", "server": "sb-vm.example.com", "server_port": 443,
     "uuid": "` + uuidB + `", "security": "auto", "alter_id": 0,
     "transport": {"type": "ws", "path": "/sbws", "headers": {"Host": "cdn.example.com"}},
     "tls": {"enabled": true, "server_name": "sb-vm.example.com"}},
    {"type": "trojan", "tag": "SB-Trojan", "server": "sb-tj.example.com", "server_port": 443,
     "password": "sbtjpass", "tls": {"enabled": true, "server_name": "sb-tj.example.com", "insecure": true}},
    {"type": "hysteria2", "tag": "SB-HY2", "server": "sb-hy.example.com", "server_port": 443,
     "password": "sbhyauth", "obfs": {"type": "salamander", "password": "sbobfs"},
     "server_ports": ["20000-30000"], "tls": {"enabled": true, "server_name": "sb-hy.example.com"}},
    {"type": "tuic", "tag": "SB-TUIC", "server": "sb-tu.example.com", "server_port": 443,
     "uuid": "` + uuidC + `", "password": "sbtupass", "congestion_control": "bbr", "udp_relay_mode": "native",
     "tls": {"enabled": true, "server_name": "sb-tu.example.com", "alpn": ["h3"]}},
    {"type": "socks", "tag": "SB-Socks", "server": "sb-so.example.com", "server_port": 1080, "version": "5",
     "username": "u", "password": "p"},
    {"type": "http", "tag": "SB-HTTP", "server": "sb-hp.example.com", "server_port": 8080,
     "username": "u", "password": "p", "tls": {"enabled": true, "server_name": "sb-hp.example.com"}},
    {"type": "shadowsocks", "tag": "SB-Broken", "server": "sb-bad.example.com", "server_port": 8388,
     "method": "aes-256-gcm"}
  ]
}`

func TestParseSingBoxJSON(t *testing.T) {
	out := ParseSubscription([]byte(singBoxSample), SubscriptionOptions{Name: "SB订阅"})
	if out.Format != "sing-box-json" {
		t.Fatalf("format = %s", out.Format)
	}
	// 9 个节点型出站中 8 个成功、SB-Broken 缺 password 失败；selector/direct 跳过。
	if len(out.Items) != 9 || out.OK() != 8 {
		t.Fatalf("items=%d ok=%d", len(out.Items), out.OK())
	}
	byName := map[string]ItemResult{}
	for _, it := range out.Items {
		if it.Node != nil {
			byName[it.Node.Name] = it
		}
	}
	vl := byName["SB-VLESS"]
	if vl.Node == nil || vl.Node.Security == nil || vl.Node.Security.Type != "reality" || vl.Node.Security.PublicKey != "SBREALITYKEY" {
		t.Errorf("SB-VLESS = %+v", vl)
	}
	hy := byName["SB-HY2"]
	if hy.Node == nil || len(hy.Node.ExtraPorts) != 1 {
		t.Errorf("SB-HY2 = %+v", hy)
	}
	tj := byName["SB-Trojan"]
	if !hasWarn(tj.Warnings, WarnInsecureSkipVerify) {
		t.Errorf("SB-Trojan should carry insecure warning, got %v", tj.Warnings)
	}
	var broken *ItemResult
	for i := range out.Items {
		if out.Items[i].Err != nil {
			broken = &out.Items[i]
		}
	}
	if broken == nil || broken.Err.Code != ErrMissingField {
		t.Errorf("broken item = %+v", broken)
	}
	if len(out.Warnings) < 2 {
		t.Errorf("expected skip warnings for selector/direct, got %v", out.Warnings)
	}
}

func TestParseSingBoxBrokenJSON(t *testing.T) {
	out := ParseSubscription([]byte("{"), SubscriptionOptions{})
	if len(out.Items) != 1 || out.Items[0].Err == nil || out.Items[0].Err.Code != ErrBadJSON {
		t.Errorf("out = %+v", out.Items)
	}
}

const clashSample = `
mixed-port: 7890
proxies:
  - name: "CL-SS"
    type: ss
    server: cl-ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: clpass
    plugin: obfs
    plugin-opts:
      mode: http
      host: bing.example.com
    udp: true
  - name: "CL-VMess"
    type: vmess
    server: cl-vm.example.com
    port: 443
    uuid: ` + uuidB + `
    alterId: 0
    cipher: auto
    tls: true
    servername: cl-vm.example.com
    network: ws
    ws-opts:
      path: /clws
      headers:
        Host: cdn.example.com
  - name: "CL-VLESS"
    type: vless
    server: cl-vl.example.com
    port: 443
    uuid: ` + uuidA + `
    flow: xtls-rprx-vision
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: CLREALITYKEY
      short-id: cd34
    network: tcp
  - name: "CL-Trojan"
    type: trojan
    server: cl-tj.example.com
    port: 443
    password: cltjpass
    sni: cl-tj.example.com
    network: ws
    ws-opts:
      path: /cltj
  - name: "CL-HY2"
    type: hysteria2
    server: cl-hy.example.com
    port: 443
    password: clhyauth
    obfs: salamander
    obfs-password: clobfs
    ports: "20000-30000"
    sni: cl-hy.example.com
  - name: "CL-TUIC"
    type: tuic
    server: cl-tu.example.com
    port: 443
    uuid: ` + uuidC + `
    password: cltupass
    congestion-controller: bbr
    udp-relay-mode: native
    sni: cl-tu.example.com
    alpn: [h3]
  - name: "CL-WG"
    type: wireguard
    server: cl-wg.example.com
    port: 51820
    ip: 10.0.0.2
    private-key: ` + wgPriv + `
    public-key: ` + wgPub + `
    allowed-ips: ["0.0.0.0/0"]
    dns: [1.1.1.1]
    keepalive: 25
    udp: true
  - name: "CL-Socks"
    type: socks5
    server: cl-so.example.com
    port: 1080
    username: u
    password: p
  - name: "CL-HTTP"
    type: http
    server: cl-hp.example.com
    port: 8080
    username: u
    password: p
    tls: true
    sni: cl-hp.example.com
  - name: "CL-SSR"
    type: ssr
    server: cl-ssr.example.com
    port: 8388
    cipher: aes-256-cfb
    password: x
    protocol: origin
`

func TestParseClashYAML(t *testing.T) {
	out := ParseSubscription([]byte(clashSample), SubscriptionOptions{Name: "Clash订阅"})
	if out.Format != "clash-yaml" {
		t.Fatalf("format = %s", out.Format)
	}
	if len(out.Items) != 10 || out.OK() != 9 {
		t.Fatalf("items=%d ok=%d", len(out.Items), out.OK())
	}
	byName := map[string]*Node{}
	var ssrErr *ParseError
	for _, it := range out.Items {
		if it.Node != nil {
			byName[it.Node.Name] = it.Node
		}
		if it.Err != nil {
			ssrErr = it.Err
		}
	}
	if ssrErr == nil || ssrErr.Code != ErrUnsupportedProto {
		t.Errorf("ssr err = %v", ssrErr)
	}
	ss := byName["CL-SS"]
	if ss == nil {
		t.Fatal("CL-SS missing")
	}
	c := credOf(t, ss)
	if c["plugin"] != "obfs" || c["pluginOpts"] != "obfs=http;obfs-host=bing.example.com" {
		t.Errorf("CL-SS plugin = %v", c)
	}
	vl := byName["CL-VLESS"]
	if vl == nil || vl.Security == nil || vl.Security.Type != "reality" || vl.Security.PublicKey != "CLREALITYKEY" {
		t.Errorf("CL-VLESS = %+v", vl)
	}
	wg := byName["CL-WG"]
	if wg == nil || wg.Protocol != "wireguard" {
		t.Errorf("CL-WG = %+v", wg)
	}
	hp := byName["CL-HTTP"]
	if hp == nil || hp.Security == nil || hp.Security.Type != "tls" {
		t.Errorf("CL-HTTP = %+v", hp)
	}
}

func TestParseClashBrokenYAML(t *testing.T) {
	out := ParseSubscription([]byte("proxies: [unclosed"), SubscriptionOptions{})
	if len(out.Items) != 1 || out.Items[0].Err == nil {
		t.Errorf("out = %+v", out.Items)
	}
}

// ---------------------------------------------------------------------------
// 配置文件格式
// ---------------------------------------------------------------------------

const wgConfSample = `[Interface]
PrivateKey = ` + wgPriv + `
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = ` + wgPub + `
PresharedKey = ` + wgPsk + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wgconf.example.com:51820
PersistentKeepalive = 25
`

func TestParseWireGuardConf(t *testing.T) {
	out := ParseWireGuardConf(wgConfSample, Options{})
	if out.OK() != 1 {
		t.Fatalf("ok = %d, items = %+v", out.OK(), out.Items)
	}
	n := out.Items[0].Node
	if n.Server != "wgconf.example.com" || n.Port != 51820 {
		t.Errorf("endpoint = %s:%d", n.Server, n.Port)
	}
	c := credOf(t, n)
	if addrs, _ := c["addresses"].([]any); len(addrs) != 2 {
		t.Errorf("addresses = %v", c["addresses"])
	}
	if n.Source.Kind != "file" {
		t.Errorf("source = %+v", n.Source)
	}
}

func TestParseWireGuardConfMultiPeerAndMissing(t *testing.T) {
	multi := wgConfSample + `
[Peer]
PublicKey = ` + wgPub + `
AllowedIPs = 10.0.0.0/8
Endpoint = wgconf2.example.com:51821
`
	out := ParseWireGuardConf(multi, Options{})
	if out.OK() != 2 {
		t.Errorf("multi peer ok = %d", out.OK())
	}
	bad := ParseWireGuardConf("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = "+wgPub+"\n", Options{})
	if bad.OK() != 0 {
		t.Errorf("missing privatekey should fail, ok = %d", bad.OK())
	}
	noEp := ParseWireGuardConf("[Interface]\nPrivateKey = "+wgPriv+"\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = "+wgPub+"\nAllowedIPs = 0.0.0.0/0\n", Options{})
	if noEp.OK() != 0 || len(noEp.Items) != 1 || noEp.Items[0].Err == nil || noEp.Items[0].Err.Code != ErrMissingField {
		t.Errorf("missing endpoint = %+v", noEp.Items)
	}
}

const ovpnSample = `client
dev tun
proto udp
remote ovpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
auth-user-pass
verb 3
<ca>
-----BEGIN CERTIFICATE-----
FAKE-CERT-FOR-TEST
-----END CERTIFICATE-----
</ca>
`

func TestParseOpenVPNConf(t *testing.T) {
	r := ParseOpenVPNConf(ovpnSample, Options{Name: "测试.ovpn"})
	n := mustNode(t, r)
	if n.Protocol != "openvpn" || n.Server != "ovpn.example.com" || n.Port != 1194 {
		t.Errorf("node = %+v", n)
	}
	c := credOf(t, n)
	if content, _ := c["configContent"].(string); !strings.Contains(content, "remote ovpn.example.com 1194") {
		t.Error("configContent must carry the full text losslessly")
	}
	if !hasWarn(r.Warnings, WarnCredentialsNeeded) {
		t.Errorf("expected credentials-required warning, got %v", r.Warnings)
	}
	// 无端口 remote：按 1194 展示并警示。
	r2 := ParseOpenVPNConf("client\nremote h2.example.com\n", Options{})
	n2 := mustNode(t, r2)
	if n2.Port != 1194 || !hasWarn(r2.Warnings, WarnDefaultedField) {
		t.Errorf("defaulted remote = %d %v", n2.Port, r2.Warnings)
	}
	// 非 ovpn 内容被拒。
	r3 := ParseOpenVPNConf("hello world, this is a readme", Options{})
	if r3.Err == nil || r3.Err.Code != ErrBadFormat {
		t.Errorf("garbage ovpn = %v", r3.Err)
	}
}

func TestParseVPNGateCSV(t *testing.T) {
	csvText := "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"jp-host1,203.0.113.10,100,20,5000000,Japan,JP,5,1000,10,10000,2weeks,op,,Y2xpZW50CmRldiB0dW4KcHJvdG8gdWRwCnJlbW90ZSB2cG5ob3N0MS5leGFtcGxlLmNvbSAxMTk1CnJlc29sdi1yZXRyeSBpbmZpbml0ZQpub2JpbmQKcGVyc2lzdC1rZXkKcGVyc2lzdC10dW4KY2lwaGVyIEFFUy0yNTYtR0NNCmF1dGggU0hBMjU2CnZlcmIgMwo8Y2E+Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlCc3pDQ0FSYWdBd0lCQWdJVUZBS0VDRVJURk9SVEVTVE9OTFkwMDAwMDAwMDAwMDAwMDAwMDAwMDAwCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KPC9jYT4K\n" +
		"bad-host,203.0.113.11,90,30,4000000,Japan,JP,3,900,5,5000,2weeks,op,,!!!invalid!!!\n"
	out := ParseVPNGateCSV(csvText, Options{})
	if out.Format != "plugin-csv" {
		t.Fatalf("format = %s", out.Format)
	}
	if out.OK() != 1 || len(out.Items) != 2 {
		t.Fatalf("ok=%d items=%+v", out.OK(), out.Items)
	}
	n := out.Items[0].Node
	if n.Protocol != "openvpn" || n.Source.Kind != "plugin" || n.Source.Authorization != "vpngate-official-csv" {
		t.Errorf("node = %+v", n)
	}
	if !strings.Contains(n.Name, "jp-host1") || !strings.Contains(n.Name, "JP") {
		t.Errorf("name = %q", n.Name)
	}
	if out.Items[1].Err == nil || out.Items[1].Err.Code != ErrBadBase64 {
		t.Errorf("bad row err = %v", out.Items[1].Err)
	}
	sr := out.SourceRecord
	if sr == nil || sr.Kind != "plugin" || sr.Authorization.Status != "A" || sr.Authorization.Basis != "vpngate-official-csv" || sr.DataFormat != "csv" {
		t.Errorf("source record = %+v", sr)
	}
}

// ---------------------------------------------------------------------------
// 弱加密警示实测（Step 5 冻结裁定义务）
// ---------------------------------------------------------------------------

func TestWeakEncryptionWarningEvidence(t *testing.T) {
	// SIP002 形态的老式方法同样必须警示（不止旧式整体 base64）。
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:oldpass"))
	r := ParseLink("ss://"+userinfo+"@old.example.com:8388#Old-SS", Options{})
	n := mustNode(t, r)
	if credOf(t, n)["method"] != "rc4-md5" {
		t.Fatalf("method = %v", credOf(t, n))
	}
	if !hasWarn(r.Warnings, WarnWeakEncryption) {
		t.Fatalf("rc4-md5 must produce weak-encryption warning, got %v", r.Warnings)
	}
	// AEAD 方法不得误报。
	r2 := ParseLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@ss1.example.com:8388#New-SS", Options{})
	_ = mustNode(t, r2)
	if hasWarn(r2.Warnings, WarnWeakEncryption) {
		t.Errorf("AEAD method must not warn weak-encryption: %v", r2.Warnings)
	}
}

// ---------------------------------------------------------------------------
// 产出过 spec schema 校验（等价复用 spec/tests/validate.py 的校验逻辑）
// ---------------------------------------------------------------------------

func TestOutputsValidateAgainstSpecSchema(t *testing.T) {
	dir := t.TempDir()
	idx := 0
	dump := func(prefix string, v any) {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		name := filepath.Join(dir, prefix+string(rune('a'+idx%26))+string(rune('a'+(idx/26)%26))+".json")
		idx++
		if err := os.WriteFile(name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range linkCases() {
		r := ParseLink(tc.raw, Options{})
		dump("node-", mustNode(t, r))
	}
	sub := ParseSubscription([]byte(singBoxSample), SubscriptionOptions{URL: "https://subs.example.com/x", Name: "SB订阅"})
	for _, it := range sub.Items {
		if it.Node != nil {
			dump("node-", it.Node)
		}
	}
	dump("group-", sub.Group)
	dump("sub-", sub.Subscription)
	dump("source-", sub.SourceRecord)
	clash := ParseSubscription([]byte(clashSample), SubscriptionOptions{Name: "Clash订阅"})
	for _, it := range clash.Items {
		if it.Node != nil {
			dump("node-", it.Node)
		}
	}
	dump("group-", clash.Group)
	dump("source-", clash.SourceRecord)
	wgc := ParseWireGuardConf(wgConfSample, Options{})
	for _, it := range wgc.Items {
		if it.Node != nil {
			dump("node-", it.Node)
		}
	}
	dump("node-", mustNode(t, ParseOpenVPNConf(ovpnSample, Options{})))
	vg := ParseVPNGateCSV("HostName,IP,CountryShort,OpenVPN_ConfigData_Base64\njp-host1,203.0.113.10,JP,Y2xpZW50CnJlbW90ZSB2cG5ob3N0MS5leGFtcGxlLmNvbSAxMTk1CjxjYT4KeAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCjwvY2E+Cg==\n", Options{})
	for _, it := range vg.Items {
		if it.Node != nil {
			dump("node-", it.Node)
		}
	}
	dump("source-", vg.SourceRecord)

	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	schema := filepath.Join(pkgDir, "..", "..", "spec", "unified-node-model.schema.json")
	script := filepath.Join(pkgDir, "testdata", "validate_outputs.py")
	cmd := exec.Command("python3", script, schema, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "SKIP") {
			t.Skipf("schema validation skipped: %s", out)
		}
		t.Fatalf("schema validation failed: %v\n%s", err, out)
	}
	t.Logf("schema validation:\n%s", out)
}
