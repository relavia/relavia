package parsers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// 订阅内容解析（4.2 订阅格式）：格式识别 + 分发
// ---------------------------------------------------------------------------

// SubscriptionOptions 在 Options 之外携带订阅登记信息。
type SubscriptionOptions struct {
	Options
	// URL 订阅地址（已知时产出 Subscription 登记对象）。
	URL string
	// Name 订阅名（缺省取 URL 主机名或「导入订阅」）。
	Name string
}

// ParseSubscription 解析一份订阅内容（已拉取的字节流），自动识别：
// sing-box JSON、Clash YAML、V2Ray 订阅（整体 base64 的链接列表）、
// 原始链接列表（明文，或整体 base64）。产出节点批量结果，并按
// Options 构造 Group 登记；给出 URL 时同时产出 Subscription 登记，
// 并为订阅来源产出 Source 登记（kind=subscription、status=B、
// basis=user-provided，对应 7.1/7.4 的用户自有来源口径）。
func ParseSubscription(content []byte, sopt SubscriptionOptions) *BatchResult {
	if len(content) == 0 {
		return &BatchResult{Items: []ItemResult{{Err: perr(ErrEmptyInput, "", "订阅内容为空")}}}
	}
	if len(content) > maxBatchBytes {
		return &BatchResult{Items: []ItemResult{{Err: perr(ErrInputTooLarge, "", "订阅内容超过 %d 字节上限", maxBatchBytes)}}}
	}
	text := strings.TrimSpace(string(content))
	var out *BatchResult
	switch {
	case strings.HasPrefix(text, "{"):
		out = parseSingBoxJSON(text, sopt.Options)
	case looksLikeClashYAML(text):
		out = parseClashYAML(text, sopt.Options)
	default:
		// 链接列表：整段为 base64 时先解码（V2Ray 订阅即此形态）。
		body, format := text, "link-list"
		if !strings.Contains(text, "://") && looksBase64(text) {
			if dec, err := decodeBase64(text); err == nil && strings.Contains(string(dec), "://") {
				body, format = string(dec), "v2ray-base64"
			}
		}
		out = ParseLinkList(body, sopt.Options)
		out.Format = format
	}
	attachSubscriptionRecords(out, sopt)
	return out
}

func looksLikeClashYAML(text string) bool {
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return false
	}
	for _, ln := range splitLines(text) {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "proxies:") {
			return true
		}
	}
	return false
}

// attachSubscriptionRecords 为订阅解析结果补 Group/Subscription/Source 登记。
func attachSubscriptionRecords(out *BatchResult, sopt SubscriptionOptions) {
	name := sopt.Name
	if name == "" {
		name = "导入订阅"
	}
	groupName := sopt.Group
	if groupName == "" {
		groupName = name
	}
	subID := deterministicUUID("subscription|" + sopt.URL + "|" + out.Format + "|" + name)
	var ids []string
	for i := range out.Items {
		if out.Items[i].Node != nil {
			out.Items[i].Node.Group = groupName
			out.Items[i].Node.Source = SourceRef{Kind: "subscription", Ref: subID, Authorization: "user-provided"}
			// 节点 id 已由内容派生，来源变更不影响 id；此处仅补登记。
			ids = append(ids, out.Items[i].Node.ID)
		}
	}
	gid := deterministicUUID("group|" + subID)
	out.Group = &Group{SchemaVersion: "1.0", ID: gid, Name: groupName, NodeIDs: ids, SourceID: &subID}
	srcID := deterministicUUID("source|" + subID)
	out.SourceRecord = &Source{
		SchemaVersion: "1.0",
		ID:            srcID,
		Kind:          "subscription",
		Name:          name,
		Authorization: SourceAuthorization{Status: "B", Basis: "user-provided"},
		DataFormat:    modelDataFormat(out.Format),
	}
	if sopt.URL != "" {
		enabled := true
		out.Subscription = &Subscription{
			SchemaVersion: "1.0",
			ID:            subID,
			Name:          name,
			URL:           sopt.URL,
			Format:        out.Format,
			Enabled:       &enabled,
			SourceID:      &srcID,
			GroupName:     groupName,
		}
	}
}

// modelDataFormat 把内部格式名映射到 Source.dataFormat 枚举。
func modelDataFormat(f string) string {
	switch f {
	case "sing-box-json", "clash-yaml", "v2ray-base64", "link-list", "plugin-csv":
		return f
	}
	return "link-list"
}

// BuildSubscriptionRecord 构造一份订阅登记（URL 已知、内容未拉取时用），
// format 取 auto 或已知的模型枚举值。
func BuildSubscriptionRecord(url, name, format, groupName string) *Subscription {
	if format == "" {
		format = "auto"
	}
	if name == "" {
		name = "导入订阅"
	}
	id := deterministicUUID("subscription|" + url + "|" + format + "|" + name)
	enabled := true
	return &Subscription{
		SchemaVersion: "1.0",
		ID:            id,
		Name:          name,
		URL:           url,
		Format:        format,
		Enabled:       &enabled,
		GroupName:     groupName,
	}
}

// ---------------------------------------------------------------------------
// sing-box JSON 订阅
// ---------------------------------------------------------------------------

func parseSingBoxJSON(text string, opts Options) *BatchResult {
	out := &BatchResult{Format: "sing-box-json"}
	var root map[string]any
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadJSON, "json", "sing-box JSON 解析失败：%v", err)})
		return out
	}
	obs, _ := root["outbounds"].([]any)
	if obs == nil {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadFormat, "outbounds", "sing-box 配置缺少 outbounds 数组")})
		return out
	}
	src := opts.sourceOrDefault(SourceRef{Kind: "subscription", Ref: "sing-box-import", Authorization: "user-provided"})
	idx := 0
	for _, raw := range obs {
		ob, _ := raw.(map[string]any)
		if ob == nil {
			continue
		}
		typ := strOf(ob["type"])
		tag := strOf(ob["tag"])
		switch typ {
		case "direct", "block", "dns", "selector", "urltest":
			out.Warnings = append(out.Warnings, Warning{Code: WarnParamNotModeled, Field: tag,
				Message: fmt.Sprintf("sing-box 出站 %q（type=%s）不是节点，已跳过", tag, typ)})
			continue
		}
		b := &builder{src: src, group: opts.Group}
		res := b.singBoxOutbound(ob, typ, tag)
		it := ItemResult{Index: idx, Raw: truncate(tag+" ("+typ+")", 120), Node: res.Node, Warnings: res.Warnings, Err: res.Err}
		if it.Err != nil {
			e := *it.Err
			e.Index = idx
			it.Err = &e
		}
		out.Items = append(out.Items, it)
		idx++
	}
	return out
}

func (b *builder) singBoxOutbound(ob map[string]any, typ, tag string) LinkResult {
	server := strOf(ob["server"])
	port := intOf(ob["server_port"])
	name := tag
	fail := func(e *ParseError) LinkResult { return LinkResult{Err: e} }
	needServer := func() *ParseError {
		if server == "" {
			return perr(ErrMissingField, "server", "出站 %q 缺少 server", tag)
		}
		if port < 1 || port > 65535 {
			return perr(ErrBadPort, "server_port", "出站 %q 端口非法", tag)
		}
		return nil
	}
	switch typ {
	case "shadowsocks":
		if e := needServer(); e != nil {
			return fail(e)
		}
		method := strOf(ob["method"])
		if err := b.checkSSMethod(method); err != nil {
			return fail(err)
		}
		cred := credSS{Method: method, Password: strOf(ob["password"]), Plugin: strOf(ob["plugin"]), PluginOpts: strOf(ob["plugin_opts"])}
		if cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "出站 %q 缺少 password", tag))
		}
		var udp *bool
		if strings.Contains(strOf(ob["network"]), "udp") {
			udp = boolPtr(true)
		}
		return b.finish("shadowsocks", name, server, port, cred, &Transport{Type: "raw"}, nil, udp, nil, tag)
	case "trojan":
		if e := needServer(); e != nil {
			return fail(e)
		}
		pw := strOf(ob["password"])
		if pw == "" {
			return fail(perr(ErrMissingField, "password", "出站 %q 缺少 password", tag))
		}
		tr, sec := b.singBoxTransportTLS(ob, true)
		return b.finish("trojan", name, server, port, credPassword{Password: pw}, tr, sec, boolPtr(true), nil, tag)
	case "vmess":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(ob["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credVMess{UUID: uuid}
		if v, ok := ob["alter_id"]; ok {
			a := intOf(v)
			cred.AlterID = &a
			if a > 0 {
				b.warn(WarnLegacyParameter, "alter_id", "VMess alter_id 非 0 为旧式用法，已保留导入")
			}
		}
		cipher := strOf(ob["security"])
		if cipher == "" {
			cipher = "auto"
		}
		switch cipher {
		case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
			cred.Cipher = cipher
		default:
			return fail(perr(ErrUnsupportedValue, "security", "不支持的 VMess security %q", cipher))
		}
		tr, sec := b.singBoxTransportTLS(ob, false)
		return b.finish("vmess", name, server, port, cred, tr, sec, boolPtr(true), nil, tag)
	case "vless":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(ob["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credVLESS{UUID: uuid, Flow: strOf(ob["flow"])}
		if cred.Flow != "" && cred.Flow != "xtls-rprx-vision" && cred.Flow != "xtls-rprx-vision-udp443" {
			return fail(perr(ErrUnsupportedValue, "flow", "不支持的 VLESS flow %q", cred.Flow))
		}
		if _, ok := ob["packet_encoding"]; ok {
			b.warn(WarnParamNotModeled, "packet_encoding", "packet_encoding 未在统一模型中建模（spec README 取舍 4），已忽略")
		}
		tr, sec := b.singBoxTransportTLS(ob, false)
		return b.finish("vless", name, server, port, cred, tr, sec, boolPtr(true), nil, tag)
	case "hysteria2":
		if e := needServer(); e != nil {
			return fail(e)
		}
		cred := credHysteria2{Auth: strOf(ob["password"])}
		if cred.Auth == "" {
			return fail(perr(ErrMissingField, "password", "出站 %q 缺少 password（认证串）", tag))
		}
		if obfs, ok := ob["obfs"].(map[string]any); ok {
			t := strOf(obfs["type"])
			if t != "" && t != "salamander" {
				return fail(perr(ErrUnsupportedValue, "obfs.type", "不支持的混淆类型 %q", t))
			}
			cred.ObfsType = t
			cred.ObfsPassword = strOf(obfs["password"])
			if t != "" && cred.ObfsPassword == "" {
				return fail(perr(ErrMissingField, "obfs.password", "obfs 存在时其 password 必填"))
			}
		}
		var extra []string
		for _, p := range arrOf(ob["server_ports"]) {
			s := strOf(p)
			if s != "" {
				if !validPortRange(s) {
					return fail(perr(ErrBadPort, "server_ports", "端口段 %q 非法", s))
				}
				extra = append(extra, s)
			}
		}
		_, sec := b.singBoxTransportTLS(ob, true)
		return b.finish("hysteria2", name, server, port, cred, nil, sec, boolPtr(true), extra, tag)
	case "tuic":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(ob["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credTUIC{UUID: uuid, Password: strOf(ob["password"])}
		if cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "出站 %q 缺少 password", tag))
		}
		var tr *Transport
		cc, urm := strOf(ob["congestion_control"]), strOf(ob["udp_relay_mode"])
		if cc != "" || urm != "" {
			tr = &Transport{Type: "quic", CongestionControl: cc, UDPRelayMode: urm}
		}
		if _, ok := ob["heartbeat"]; ok {
			b.warn(WarnParamNotModeled, "heartbeat", "TUIC heartbeat 等客户端调参未在统一模型中建模（spec README 取舍 3），已忽略")
		}
		_, sec := b.singBoxTransportTLS(ob, true)
		return b.finish("tuic", name, server, port, cred, tr, sec, boolPtr(true), nil, tag)
	case "socks":
		if e := needServer(); e != nil {
			return fail(e)
		}
		if v := strOf(ob["version"]); v != "" && v != "5" {
			return fail(perr(ErrUnsupportedProto, "version", "仅支持 SOCKS5，出站 %q 为 SOCKS%s", tag, v))
		}
		cred := credUserPass{Username: strOf(ob["username"]), Password: strOf(ob["password"])}
		return b.finish("socks5", name, server, port, cred, &Transport{Type: "raw"}, nil, boolPtr(true), nil, tag)
	case "http":
		if e := needServer(); e != nil {
			return fail(e)
		}
		cred := credUserPass{Username: strOf(ob["username"]), Password: strOf(ob["password"])}
		_, sec := b.singBoxTransportTLS(ob, false)
		return b.finish("http", name, server, port, cred, &Transport{Type: "raw"}, sec, nil, nil, tag)
	case "wireguard":
		priv := strOf(ob["private_key"])
		if err := checkWGKey(priv, "private_key"); err != nil {
			return fail(err)
		}
		peers := arrOf(ob["peers"])
		if len(peers) == 0 {
			return fail(perr(ErrMissingField, "peers", "wireguard 出站缺少 peers"))
		}
		peer, _ := peers[0].(map[string]any)
		if len(peers) > 1 {
			b.warn(WarnParamNotModeled, "peers", "统一模型为单 Peer，sing-box wireguard 出站有多个 peers，仅取第一个")
		}
		cred := credWireGuard{PrivateKey: priv}
		cred.PeerPublicKey = strOf(peer["public_key"])
		if err := checkWGKey(cred.PeerPublicKey, "peers.public_key"); err != nil {
			return fail(err)
		}
		cred.PreSharedKey = strOf(peer["pre_shared_key"])
		if cred.PreSharedKey != "" {
			if err := checkWGKey(cred.PreSharedKey, "peers.pre_shared_key"); err != nil {
				return fail(err)
			}
		}
		for _, a := range arrOf(ob["address"]) {
			cred.Addresses = append(cred.Addresses, strOf(a))
		}
		if len(cred.Addresses) == 0 {
			return fail(perr(ErrMissingField, "address", "wireguard 出站缺少 address"))
		}
		for _, a := range arrOf(peer["allowed_ips"]) {
			cred.AllowedIPs = append(cred.AllowedIPs, strOf(a))
		}
		if r := arrOf(peer["reserved"]); len(r) == 3 {
			for _, x := range r {
				cred.Reserved = append(cred.Reserved, intOf(x))
			}
		}
		cred.MTU = intOf(ob["mtu"])
		cred.PersistentKeepalive = intOf(peer["persistent_keepalive"])
		srv := strOf(peer["address"])
		prt := intOf(peer["port"])
		if srv == "" || prt < 1 || prt > 65535 {
			return fail(perr(ErrMissingField, "peers.address", "wireguard peer 缺少合法 address/port"))
		}
		return b.finish("wireguard", name, srv, prt, cred, &Transport{Type: "raw"}, nil, boolPtr(true), nil, tag)
	default:
		return fail(perr(ErrUnsupportedProto, "type", "sing-box 出站类型 %q 暂不支持", typ))
	}
}

// singBoxTransportTLS 解析 sing-box 的 transport 与 tls 对象。
// defaultTLS 为真时（trojan/hy2/tuic）无 tls 对象也产出 tls 安全层。
func (b *builder) singBoxTransportTLS(ob map[string]any, defaultTLS bool) (*Transport, *Security) {
	var tr *Transport
	if tm, ok := ob["transport"].(map[string]any); ok {
		t := strOf(tm["type"])
		if mt, ok2 := mapTransportType(t); ok2 {
			tr = &Transport{Type: mt}
			tr.Path = strOf(tm["path"])
			tr.ServiceName = strOf(tm["service_name"])
			if h, ok := tm["headers"].(map[string]any); ok {
				for k, v := range h {
					var val string
					switch vv := v.(type) {
					case string:
						val = vv
					case []any:
						if len(vv) > 0 {
							val = strOf(vv[0])
						}
					}
					if strings.EqualFold(k, "host") {
						tr.Host = val
					} else {
						if tr.Headers == nil {
							tr.Headers = map[string]string{}
						}
						tr.Headers[k] = val
					}
				}
			}
			if m := strOf(tm["mode"]); m != "" && mt == "xhttp" {
				tr.Mode = m
			}
		} else if t != "" {
			b.warn(WarnUnknownParam, "transport.type", fmt.Sprintf("sing-box 传输类型 %q 无法映射，已忽略", t))
		}
	}
	var sec *Security
	if tm, ok := ob["tls"].(map[string]any); ok {
		if rm, ok := tm["reality"].(map[string]any); ok && boolOf(rm["enabled"]) {
			sec = &Security{Type: "reality", PublicKey: strOf(rm["public_key"]), ShortID: strOf(rm["short_id"])}
		} else if boolOf(tm["enabled"]) {
			sec = &Security{Type: "tls"}
		}
		if sec != nil {
			sec.ServerName = strOf(tm["server_name"])
			sec.ALPN = strArrOf(tm["alpn"])
			if ut, ok := tm["utls"].(map[string]any); ok {
				sec.Fingerprint = strOf(ut["fingerprint"])
			}
			if boolOf(tm["insecure"]) {
				sec.AllowInsecure = boolPtr(true)
				b.noteInsecure("tls.insecure", true)
			}
		}
	}
	if sec == nil && defaultTLS {
		sec = &Security{Type: "tls"}
	}
	return tr, sec
}

// ---------------------------------------------------------------------------
// Clash / mihomo YAML 订阅
// ---------------------------------------------------------------------------

type clashFile struct {
	Proxies []map[string]any `yaml:"proxies"`
}

func parseClashYAML(text string, opts Options) *BatchResult {
	out := &BatchResult{Format: "clash-yaml"}
	var cf clashFile
	if err := yaml.Unmarshal([]byte(text), &cf); err != nil {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadFormat, "yaml", "Clash YAML 解析失败：%v", err)})
		return out
	}
	if len(cf.Proxies) == 0 {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadFormat, "proxies", "Clash 配置缺少 proxies 节点列表")})
		return out
	}
	src := opts.sourceOrDefault(SourceRef{Kind: "subscription", Ref: "clash-import", Authorization: "user-provided"})
	for i, px := range cf.Proxies {
		b := &builder{src: src, group: opts.Group}
		res := b.clashProxy(px)
		it := ItemResult{Index: i, Raw: truncate(strOf(px["name"])+" ("+strOf(px["type"])+")", 120), Node: res.Node, Warnings: res.Warnings, Err: res.Err}
		if it.Err != nil {
			e := *it.Err
			e.Index = i
			it.Err = &e
		}
		out.Items = append(out.Items, it)
	}
	return out
}

func (b *builder) clashProxy(px map[string]any) LinkResult {
	typ := strings.ToLower(strOf(px["type"]))
	name := strOf(px["name"])
	server := strOf(px["server"])
	port := intOf(px["port"])
	fail := func(e *ParseError) LinkResult { return LinkResult{Err: e} }
	needServer := func() *ParseError {
		if server == "" {
			return perr(ErrMissingField, "server", "节点 %q 缺少 server", name)
		}
		if port < 1 || port > 65535 {
			return perr(ErrBadPort, "port", "节点 %q 端口非法", name)
		}
		return nil
	}
	udp := boolPtr(true)
	if v, ok := px["udp"]; ok && !boolOf(v) {
		udp = boolPtr(false)
	}
	skipVerify := boolOf(px["skip-cert-verify"])
	switch typ {
	case "ss":
		if e := needServer(); e != nil {
			return fail(e)
		}
		method := strOf(px["cipher"])
		if err := b.checkSSMethod(method); err != nil {
			return fail(err)
		}
		cred := credSS{Method: method, Password: strOf(px["password"])}
		if cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "节点 %q 缺少 password", name))
		}
		if p := strOf(px["plugin"]); p != "" {
			cred.Plugin = p
			if po, ok := px["plugin-opts"].(map[string]any); ok {
				cred.PluginOpts = flattenPluginOpts(p, po)
			}
		}
		return b.finish("shadowsocks", name, server, port, cred, &Transport{Type: "raw"}, nil, udp, nil, name)
	case "trojan":
		if e := needServer(); e != nil {
			return fail(e)
		}
		pw := strOf(px["password"])
		if pw == "" {
			return fail(perr(ErrMissingField, "password", "节点 %q 缺少 password", name))
		}
		tr := b.clashTransport(px)
		sec := &Security{Type: "tls", ServerName: strOf(px["sni"]), ALPN: strArrOf(px["alpn"]), Fingerprint: strOf(px["client-fingerprint"])}
		if skipVerify {
			sec.AllowInsecure = boolPtr(true)
			b.noteInsecure("skip-cert-verify", true)
		}
		return b.finish("trojan", name, server, port, credPassword{Password: pw}, tr, sec, udp, nil, name)
	case "vmess":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(px["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credVMess{UUID: uuid}
		if v, ok := px["alterId"]; ok {
			a := intOf(v)
			cred.AlterID = &a
			if a > 0 {
				b.warn(WarnLegacyParameter, "alterId", "VMess alterId 非 0 为旧式用法，已保留导入")
			}
		}
		cipher := strOf(px["cipher"])
		if cipher == "" {
			cipher = "auto"
		}
		switch cipher {
		case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
			cred.Cipher = cipher
		default:
			return fail(perr(ErrUnsupportedValue, "cipher", "不支持的 VMess cipher %q", cipher))
		}
		tr := b.clashTransport(px)
		var sec *Security
		if boolOf(px["tls"]) {
			sec = &Security{Type: "tls", ServerName: firstNonEmpty(strOf(px["servername"]), strOf(px["sni"])), ALPN: strArrOf(px["alpn"])}
			if skipVerify {
				sec.AllowInsecure = boolPtr(true)
				b.noteInsecure("skip-cert-verify", true)
			}
		}
		return b.finish("vmess", name, server, port, cred, tr, sec, udp, nil, name)
	case "vless":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(px["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credVLESS{UUID: uuid, Flow: strOf(px["flow"])}
		if cred.Flow != "" && cred.Flow != "xtls-rprx-vision" && cred.Flow != "xtls-rprx-vision-udp443" {
			return fail(perr(ErrUnsupportedValue, "flow", "不支持的 VLESS flow %q", cred.Flow))
		}
		if e := strOf(px["encryption"]); e != "" {
			cred.Encryption = e
		}
		tr := b.clashTransport(px)
		var sec *Security
		if ro, ok := px["reality-opts"].(map[string]any); ok && strOf(ro["public-key"]) != "" {
			sec = &Security{Type: "reality", PublicKey: strOf(ro["public-key"]), ShortID: strOf(ro["short-id"]),
				ServerName: firstNonEmpty(strOf(px["servername"]), strOf(px["sni"])), Fingerprint: strOf(px["client-fingerprint"])}
		} else if boolOf(px["tls"]) {
			sec = &Security{Type: "tls", ServerName: firstNonEmpty(strOf(px["servername"]), strOf(px["sni"])),
				ALPN: strArrOf(px["alpn"]), Fingerprint: strOf(px["client-fingerprint"])}
			if skipVerify {
				sec.AllowInsecure = boolPtr(true)
				b.noteInsecure("skip-cert-verify", true)
			}
		}
		return b.finish("vless", name, server, port, cred, tr, sec, udp, nil, name)
	case "hysteria2", "hy2":
		if e := needServer(); e != nil {
			return fail(e)
		}
		cred := credHysteria2{Auth: strOf(px["password"])}
		if cred.Auth == "" {
			return fail(perr(ErrMissingField, "password", "节点 %q 缺少 password（认证串）", name))
		}
		if obfs := strOf(px["obfs"]); obfs != "" {
			if obfs != "salamander" {
				return fail(perr(ErrUnsupportedValue, "obfs", "不支持的混淆类型 %q", obfs))
			}
			cred.ObfsType = obfs
			cred.ObfsPassword = strOf(px["obfs-password"])
			if cred.ObfsPassword == "" {
				return fail(perr(ErrMissingField, "obfs-password", "obfs 存在时 obfs-password 必填"))
			}
		}
		var extra []string
		if ports := strOf(px["ports"]); ports != "" {
			for _, p := range strings.Split(ports, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if !validPortRange(p) {
					return fail(perr(ErrBadPort, "ports", "端口段 %q 非法", p))
				}
				extra = append(extra, p)
			}
		}
		sec := &Security{Type: "tls", ServerName: strOf(px["sni"]), ALPN: strArrOf(px["alpn"])}
		if skipVerify {
			sec.AllowInsecure = boolPtr(true)
			b.noteInsecure("skip-cert-verify", true)
		}
		return b.finish("hysteria2", name, server, port, cred, nil, sec, udp, extra, name)
	case "tuic":
		if e := needServer(); e != nil {
			return fail(e)
		}
		uuid := strOf(px["uuid"])
		if err := checkUUID(uuid, "uuid"); err != nil {
			return fail(err)
		}
		cred := credTUIC{UUID: uuid, Password: strOf(px["password"])}
		if cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "节点 %q 缺少 password", name))
		}
		var tr *Transport
		cc, urm := strOf(px["congestion-controller"]), strOf(px["udp-relay-mode"])
		if cc != "" || urm != "" {
			tr = &Transport{Type: "quic"}
			switch cc {
			case "", "cubic", "new_reno", "bbr":
				tr.CongestionControl = cc
			default:
				return fail(perr(ErrUnsupportedValue, "congestion-controller", "不支持的拥塞控制 %q", cc))
			}
			switch urm {
			case "", "native", "quic":
				tr.UDPRelayMode = urm
			default:
				return fail(perr(ErrUnsupportedValue, "udp-relay-mode", "不支持的 UDP 中继模式 %q", urm))
			}
		}
		sec := &Security{Type: "tls", ALPN: strArrOf(px["alpn"])}
		if !boolOf(px["disable-sni"]) {
			sec.ServerName = strOf(px["sni"])
		}
		if skipVerify {
			sec.AllowInsecure = boolPtr(true)
			b.noteInsecure("skip-cert-verify", true)
		}
		return b.finish("tuic", name, server, port, cred, tr, sec, udp, nil, name)
	case "socks5":
		if e := needServer(); e != nil {
			return fail(e)
		}
		cred := credUserPass{Username: strOf(px["username"]), Password: strOf(px["password"])}
		if cred.Username != "" && cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "给出 username 时 password 必填"))
		}
		return b.finish("socks5", name, server, port, cred, &Transport{Type: "raw"}, nil, udp, nil, name)
	case "http":
		if e := needServer(); e != nil {
			return fail(e)
		}
		cred := credUserPass{Username: strOf(px["username"]), Password: strOf(px["password"])}
		if cred.Username != "" && cred.Password == "" {
			return fail(perr(ErrMissingField, "password", "给出 username 时 password 必填"))
		}
		var sec *Security
		if boolOf(px["tls"]) {
			sec = &Security{Type: "tls", ServerName: firstNonEmpty(strOf(px["sni"]), server)}
			if skipVerify {
				sec.AllowInsecure = boolPtr(true)
				b.noteInsecure("skip-cert-verify", true)
			}
		}
		return b.finish("http", name, server, port, cred, &Transport{Type: "raw"}, sec, nil, nil, name)
	case "wireguard":
		priv := strOf(px["private-key"])
		if err := checkWGKey(priv, "private-key"); err != nil {
			return fail(err)
		}
		cred := credWireGuard{PrivateKey: priv}
		cred.PeerPublicKey = strOf(px["public-key"])
		if err := checkWGKey(cred.PeerPublicKey, "public-key"); err != nil {
			return fail(err)
		}
		cred.PreSharedKey = strOf(px["preshared-key"])
		if cred.PreSharedKey != "" {
			if err := checkWGKey(cred.PreSharedKey, "preshared-key"); err != nil {
				return fail(err)
			}
		}
		if ip := strOf(px["ip"]); ip != "" {
			cred.Addresses = append(cred.Addresses, ip)
		}
		if ip6 := strOf(px["ipv6"]); ip6 != "" {
			cred.Addresses = append(cred.Addresses, ip6)
		}
		if len(cred.Addresses) == 0 {
			return fail(perr(ErrMissingField, "ip", "wireguard 节点缺少 ip"))
		}
		cred.AllowedIPs = strArrOf(px["allowed-ips"])
		if len(cred.AllowedIPs) == 0 {
			cred.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
			b.warn(WarnDefaultedField, "allowed-ips", "未给出 allowed-ips，已按全隧道补齐")
		}
		cred.DNS = strArrOf(px["dns"])
		cred.MTU = intOf(px["mtu"])
		cred.PersistentKeepalive = intOf(px["keepalive"])
		if r := arrOf(px["reserved"]); len(r) == 3 {
			for _, x := range r {
				cred.Reserved = append(cred.Reserved, intOf(x))
			}
		}
		if e := needServer(); e != nil {
			return fail(e)
		}
		return b.finish("wireguard", name, server, port, cred, &Transport{Type: "raw"}, nil, udp, nil, name)
	default:
		return fail(perr(ErrUnsupportedProto, "type", "Clash 代理类型 %q 不在统一模型协议范围内", typ))
	}
}

// clashTransport 由 Clash 的 network 与 *-opts 构造 Transport。
func (b *builder) clashTransport(px map[string]any) *Transport {
	net0 := strings.ToLower(strOf(px["network"]))
	if net0 == "" {
		net0 = "tcp"
	}
	mt, ok := mapTransportType(net0)
	if !ok {
		b.warn(WarnUnknownParam, "network", fmt.Sprintf("Clash network %q 无法映射，已按 tcp 处理", net0))
		mt = "tcp"
	}
	if mt == "tcp" {
		if _, hasWS := px["ws-opts"]; !hasWS {
			if _, hasGRPC := px["grpc-opts"]; !hasGRPC {
				return nil
			}
		}
	}
	tr := &Transport{Type: mt}
	if wo, ok := px["ws-opts"].(map[string]any); ok {
		tr.Type = "ws"
		tr.Path = strOf(wo["path"])
		if h, ok := wo["headers"].(map[string]any); ok {
			for k, v := range h {
				if strings.EqualFold(k, "host") {
					tr.Host = strOf(v)
				} else {
					if tr.Headers == nil {
						tr.Headers = map[string]string{}
					}
					tr.Headers[k] = strOf(v)
				}
			}
		}
	}
	if gopts, ok := px["grpc-opts"].(map[string]any); ok {
		tr.Type = "grpc"
		tr.ServiceName = strOf(gopts["grpc-service-name"])
	}
	if ho, ok := px["h2-opts"].(map[string]any); ok {
		tr.Type = "http"
		tr.Path = strOf(ho["path"])
		if hosts := strArrOf(ho["host"]); len(hosts) > 0 {
			tr.Host = hosts[0]
		}
	}
	return tr
}

// flattenPluginOpts 把 Clash plugin-opts 映射展平为 ss 链接风格的选项串。
func flattenPluginOpts(plugin string, po map[string]any) string {
	if plugin == "obfs" {
		var parts []string
		if v := strOf(po["mode"]); v != "" {
			parts = append(parts, "obfs="+v)
		}
		if v := strOf(po["host"]); v != "" {
			parts = append(parts, "obfs-host="+v)
		}
		keys := sortedKeys(po)
		for _, k := range keys {
			if k == "mode" || k == "host" {
				continue
			}
			parts = append(parts, k+"="+scalarStr(po[k]))
		}
		return strings.Join(parts, ";")
	}
	keys := sortedKeys(po)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+scalarStr(po[k]))
	}
	return strings.Join(parts, ";")
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func scalarStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// ---------------------------------------------------------------------------
// 通用取值助手（JSON/YAML 泛型映射共用）
// ---------------------------------------------------------------------------

func strOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return scalarStr(t)
	}
}

func intOf(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}

func boolOf(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	}
	return false
}

func arrOf(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func strArrOf(v any) []string {
	var out []string
	for _, x := range arrOf(v) {
		if s := strOf(x); s != "" {
			out = append(out, s)
		}
	}
	if s, ok := v.(string); ok && s != "" {
		out = append(out, s)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
