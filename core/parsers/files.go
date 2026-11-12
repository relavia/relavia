package parsers

import (
	"encoding/csv"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// WireGuard 配置文件（.conf）——4.2「wg:// / WireGuard 配置文件」
// ---------------------------------------------------------------------------

// ParseWireGuardConf 解析 WireGuard .conf 全文为统一模型节点。
// 一个 [Peer] 产出一个节点；多 Peer 时逐个产出（接口参数共享）。
func ParseWireGuardConf(content string, opts Options) *BatchResult {
	out := &BatchResult{Format: "wireguard-conf"}
	if len(content) > maxBatchBytes {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrInputTooLarge, "", "配置文件超过上限")})
		return out
	}
	iface, peers := parseINI(content)
	priv := iface["privatekey"]
	if priv == "" {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrMissingField, "PrivateKey", ".conf 缺少 [Interface] PrivateKey")})
		return out
	}
	if len(peers) == 0 {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrMissingField, "Peer", ".conf 缺少 [Peer] 段")})
		return out
	}
	src := opts.sourceOrDefault(SourceRef{Kind: "file", Ref: "wireguard-conf-import", Authorization: "user-provided"})
	for i, peer := range peers {
		b := &builder{src: src, group: opts.Group, optName: opts.Name}
		q := url.Values{}
		q.Set("publickey", peer["publickey"])
		q.Set("presharedkey", peer["presharedkey"])
		q.Set("address", iface["address"])
		q.Set("dns", iface["dns"])
		q.Set("mtu", iface["mtu"])
		q.Set("allowedips", peer["allowedips"])
		q.Set("keepalive", peer["persistentkeepalive"])
		cred, err := b.wgCredFromParts(priv, q)
		if err != nil {
			pe := err
			pe.Index = i
			out.Items = append(out.Items, ItemResult{Index: i, Err: pe})
			continue
		}
		endpoint := peer["endpoint"]
		if endpoint == "" {
			out.Items = append(out.Items, ItemResult{Index: i, Err: perr(ErrMissingField, "Endpoint", "第 %d 个 [Peer] 缺少 Endpoint", i+1)})
			continue
		}
		host, port, err := splitHostPort(endpoint, 51820)
		if err != nil {
			pe := err
			pe.Index = i
			out.Items = append(out.Items, ItemResult{Index: i, Err: pe})
			continue
		}
		name := opts.Name
		if name == "" {
			name = fmt.Sprintf("WireGuard-%s:%d", host, port)
			if len(peers) > 1 {
				name = fmt.Sprintf("%s #%d", name, i+1)
			}
		}
		res := b.finish("wireguard", name, host, port, cred, &Transport{Type: "raw"}, nil, boolPtr(true), nil, content)
		out.Items = append(out.Items, ItemResult{Index: i, Node: res.Node, Warnings: res.Warnings, Err: res.Err})
	}
	return out
}

// parseINI 解析 .conf 的 [Interface]/[Peer] 键值结构（键名小写化）。
func parseINI(content string) (map[string]string, []map[string]string) {
	iface := map[string]string{}
	var peers []map[string]string
	var cur map[string]string
	section := ""
	for _, ln := range splitLines(content) {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			switch section {
			case "interface":
				cur = iface
			case "peer":
				m := map[string]string{}
				peers = append(peers, m)
				cur = m
			default:
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		eq := strings.Index(t, "=")
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(t[:eq]))
		v := strings.TrimSpace(t[eq+1:])
		cur[k] = v
	}
	return iface, peers
}

// ---------------------------------------------------------------------------
// OpenVPN 配置文件（.ovpn）——4.2「OpenVPN .ovpn 文件」
// ---------------------------------------------------------------------------

// ParseOpenVPNConf 把 .ovpn 全文无损映射为 configContent 模式节点
// （spec README 承载决策：任意指令靠全文模式兜底，不得静默丢弃）。
// 同时尽力提取首个 remote 填充 server/port 便于展示。
func ParseOpenVPNConf(content string, opts Options) LinkResult {
	if strings.TrimSpace(content) == "" {
		return LinkResult{Err: perr(ErrEmptyInput, "", ".ovpn 内容为空")}
	}
	if len(content) > maxBatchBytes {
		return LinkResult{Err: perr(ErrInputTooLarge, "", ".ovpn 内容超过上限")}
	}
	if !strings.Contains(content, "remote ") && !strings.Contains(content, "remote\t") &&
		!strings.Contains(content, "<ca>") && !strings.Contains(content, "client") {
		return LinkResult{Err: perr(ErrBadFormat, "ovpn", "内容不像 OpenVPN 配置（未见 remote/client/<ca> 任一标志）")}
	}
	src := opts.sourceOrDefault(SourceRef{Kind: "file", Ref: "ovpn-import", Authorization: "user-provided"})
	b := &builder{src: src, group: opts.Group, optName: opts.Name}
	server, port := "", 0
	needsCreds := false
	for _, ln := range splitLines(content) {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "remote":
			if server == "" && len(fields) >= 2 {
				server = fields[1]
				port = 1194
				if len(fields) >= 3 {
					if p, err := strconv.Atoi(fields[2]); err == nil && p >= 1 && p <= 65535 {
						port = p
					} else {
						b.warn(WarnDefaultedField, "remote", "remote 行端口无法解析，已按 OpenVPN 默认 1194 展示（全文为准）")
					}
				} else {
					b.warn(WarnDefaultedField, "remote", "remote 行未给出端口，已按 OpenVPN 默认 1194 展示（全文为准）")
				}
			}
		case "auth-user-pass":
			if len(fields) == 1 {
				needsCreds = true
			}
		}
	}
	if needsCreds {
		b.warn(WarnCredentialsNeeded, "auth-user-pass", "该配置要求用户名/密码认证，导入时需另行向用户索取并独立存储")
	}
	cred := credOpenVPNContent{ConfigContent: content}
	return b.finishContentNode("", cred, server, port, content)
}

// ---------------------------------------------------------------------------
// VPN Gate CSV（公共源格式，4.2；完整来源插件行为见方案书 7.3 / Step 14）
// ---------------------------------------------------------------------------

const maxVPNGateRows = 500

// ParseVPNGateCSV 解析 VPN Gate 官方 CSV：逐行把内嵌的
// OpenVPN_ConfigData_Base64 解码为 configContent 模式节点，
// 并产出 Source 登记（kind=plugin、authorization.status=A、
// basis=vpngate-official-csv，对应方案书 7.1/7.2）。
// 本函数只做格式解析；7.3 的强制风险提示页等插件行为不在此实现。
func ParseVPNGateCSV(content string, opts Options) *BatchResult {
	out := &BatchResult{Format: "plugin-csv"}
	if len(content) > maxBatchBytes {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrInputTooLarge, "", "CSV 超过上限")})
		return out
	}
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadFormat, "csv", "CSV 解析失败：%v", err)})
		return out
	}
	// 定位表头（首行可能是以 * 或 # 开头的注释行）。
	hdrIdx := -1
	var colCfg, colHost, colIP, colCountry int = -1, -1, -1, -1
	for i, rec := range records {
		for j, c := range rec {
			switch strings.TrimSpace(c) {
			case "OpenVPN_ConfigData_Base64":
				colCfg = j
			case "HostName":
				colHost = j
			case "IP":
				colIP = j
			case "CountryShort":
				colCountry = j
			}
		}
		if colCfg >= 0 {
			hdrIdx = i
			break
		}
	}
	if hdrIdx < 0 {
		out.Items = append(out.Items, ItemResult{Err: perr(ErrBadFormat, "csv", "未找到 OpenVPN_ConfigData_Base64 列，不像 VPN Gate CSV")})
		return out
	}
	srcRef := SourceRef{Kind: "plugin", Ref: "vpngate", Authorization: "vpngate-official-csv"}
	if opts.Source != nil {
		srcRef = *opts.Source
	}
	op := "VPN Gate (University of Tsukuba)"
	out.SourceRecord = &Source{
		SchemaVersion: "1.0",
		ID:            deterministicUUID("source|vpngate-official-csv"),
		Kind:          "plugin",
		Name:          "VPN Gate 官方公共源",
		Operator:      &op,
		Authorization: SourceAuthorization{Status: "A", Basis: "vpngate-official-csv"},
		DataFormat:    "csv",
	}
	idx := 0
	for i, rec := range records {
		if i <= hdrIdx {
			continue
		}
		if idx >= maxVPNGateRows {
			out.Warnings = append(out.Warnings, Warning{Code: WarnUnknownParam, Message: fmt.Sprintf("CSV 行数超过 %d 上限，其余未导入", maxVPNGateRows)})
			break
		}
		if colCfg >= len(rec) {
			continue
		}
		cfgB64 := strings.TrimSpace(rec[colCfg])
		if cfgB64 == "" {
			continue
		}
		get := func(c int) string {
			if c >= 0 && c < len(rec) {
				return strings.TrimSpace(rec[c])
			}
			return ""
		}
		name := get(colHost)
		if name == "" {
			name = get(colIP)
		}
		if cc := get(colCountry); cc != "" {
			name = fmt.Sprintf("%s [%s] (VPN Gate)", name, cc)
		} else {
			name = fmt.Sprintf("%s (VPN Gate)", name)
		}
		dec, err := decodeBase64(cfgB64)
		if err != nil {
			out.Items = append(out.Items, ItemResult{Index: idx, Err: perr(ErrBadBase64, "OpenVPN_ConfigData_Base64", "第 %d 行内嵌配置解码失败", idx+1)})
			idx++
			continue
		}
		res := ParseOpenVPNConf(string(dec), Options{Source: &srcRef, Group: opts.Group, Name: name})
		out.Items = append(out.Items, ItemResult{Index: idx, Node: res.Node, Warnings: res.Warnings, Err: res.Err})
		idx++
	}
	return out
}
