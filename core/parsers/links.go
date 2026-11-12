package parsers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 凭据结构（与 schema 的 Cred* 定义对应）
// ---------------------------------------------------------------------------

type credSS struct {
	Method     string `json:"method"`
	Password   string `json:"password"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"pluginOpts,omitempty"`
}

type credPassword struct {
	Password string `json:"password"`
}

type credVMess struct {
	UUID    string `json:"uuid"`
	AlterID *int   `json:"alterId,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
}

type credVLESS struct {
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption,omitempty"`
}

type credHysteria2 struct {
	Auth         string `json:"auth"`
	ObfsType     string `json:"obfsType,omitempty"`
	ObfsPassword string `json:"obfsPassword,omitempty"`
}

type credTUIC struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

type credWireGuard struct {
	PrivateKey          string   `json:"privateKey"`
	PeerPublicKey       string   `json:"peerPublicKey"`
	PreSharedKey        string   `json:"preSharedKey,omitempty"`
	Addresses           []string `json:"addresses"`
	AllowedIPs          []string `json:"allowedIPs,omitempty"`
	DNS                 []string `json:"dns,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
	Reserved            []int    `json:"reserved,omitempty"`
}

type credUserPass struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type credOpenVPNContent struct {
	ConfigContent string `json:"configContent"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
}

// 弱加密方法集合（schema CredShadowsocks 枚举中的老式方法，
// Step 5 冻结裁定：保留导入 + 必须警示）。
var weakSSMethods = map[string]bool{
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"chacha20": true, "chacha20-ietf": true, "xchacha20": true,
	"rc4-md5": true, "none": true,
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
	"aes-128-cfb":                   true, "aes-192-cfb": true, "aes-256-cfb": true,
	"chacha20": true, "chacha20-ietf": true, "xchacha20": true,
	"rc4-md5": true, "none": true,
}

// noteSSMethod 校验 method 并按裁定发弱加密警示。
func (b *builder) checkSSMethod(method string) *ParseError {
	if !ssMethods[method] {
		return perr(ErrUnsupportedValue, "method", "不支持的 Shadowsocks 加密方法 %q", method)
	}
	if weakSSMethods[method] {
		b.warn(WarnWeakEncryption, "method",
			fmt.Sprintf("加密方法 %s 为老式弱加密（非 AEAD），仅为无损导入存量订阅而保留；不得默认推荐，应提示用户更换节点", method))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shadowsocks：SIP002 与旧式整体 base64
// ---------------------------------------------------------------------------

func (b *builder) parseSS(raw string) LinkResult {
	rest := raw[len("ss://"):]
	// 旧式整体 base64 形态不含 '@'（base64 字母表无 @）；
	// SIP002 的 userinfo 与 host 之间必有 '@'。先剥离 fragment 与 query 再判。
	frag := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		frag = rest[i+1:]
		rest = rest[:i]
		if n, err := url.QueryUnescape(frag); err == nil {
			frag = strings.TrimSpace(n)
		}
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	q, _ := url.ParseQuery(query)

	var method, password, hostport string
	if strings.Contains(rest, "@") {
		// SIP002
		at := strings.LastIndex(rest, "@")
		userinfo, hp := rest[:at], rest[at+1:]
		hostport = hp
		if strings.Contains(userinfo, ":") {
			// 明文 userinfo 变体（method:password，各自可能被百分号编码）
			m, _ := url.PathUnescape(strings.SplitN(userinfo, ":", 2)[0])
			p, _ := url.PathUnescape(strings.SplitN(userinfo, ":", 2)[1])
			method, password = m, p
		} else {
			dec, err := decodeBase64(userinfo)
			if err != nil {
				return LinkResult{Err: perr(ErrBadBase64, "userinfo", "SIP002 userinfo 不是合法 base64：%v", err)}
			}
			mp := string(dec)
			i := strings.Index(mp, ":")
			if i < 0 {
				return LinkResult{Err: perr(ErrMissingField, "userinfo", "解码后的 userinfo 缺少 method:password 分隔")}
			}
			method, password = mp[:i], mp[i+1:]
		}
	} else {
		// 旧式整体 base64：base64(method:password@host:port)
		dec, err := decodeBase64(rest)
		if err != nil {
			return LinkResult{Err: perr(ErrBadBase64, "uri", "旧式 ss 链接整体 base64 解码失败：%v", err)}
		}
		b.warn(WarnDeprecatedFormat, "uri", "旧式整体 base64 的 ss 链接形态已弃用，已按兼容方式解析，建议来源改用 SIP002")
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return LinkResult{Err: perr(ErrBadFormat, "uri", "旧式 ss 链接解码后缺少 @ 分隔")}
		}
		mp, hp := s[:at], s[at+1:]
		i := strings.Index(mp, ":")
		if i < 0 {
			return LinkResult{Err: perr(ErrMissingField, "userinfo", "旧式 ss 链接解码后缺少 method:password 分隔")}
		}
		method, password, hostport = mp[:i], mp[i+1:], hp
	}
	if err := b.checkSSMethod(method); err != nil {
		return LinkResult{Err: err}
	}
	if password == "" {
		return LinkResult{Err: perr(ErrMissingField, "password", "Shadowsocks 密码为空")}
	}
	host, port, herr := splitHostPort(strings.TrimSuffix(hostport, "/"), 0)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	cred := credSS{Method: method, Password: password}
	if plugin := q.Get("plugin"); plugin != "" {
		parts := strings.Split(plugin, ";")
		cred.Plugin = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			cred.PluginOpts = strings.Join(parts[1:], ";")
		}
	}
	var udp *bool
	if q.Get("udp") == "true" || q.Get("udp") == "1" {
		udp = boolPtr(true)
	}
	b.warnUnknownParams(q, map[string]bool{"plugin": true, "udp": true})
	return b.finish("shadowsocks", frag, host, port, cred, &Transport{Type: "raw"}, nil, udp, nil, raw)
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

func (b *builder) parseVLESS(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if err := checkUUID(uuid, "uuid"); err != nil {
		return LinkResult{Err: err}
	}
	host, port, herr := splitHostPort(u.Host, 0)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	q := u.Query()
	cred := credVLESS{UUID: uuid}
	if enc := q.Get("encryption"); enc != "" {
		cred.Encryption = enc
	}
	if flow := q.Get("flow"); flow != "" {
		switch flow {
		case "xtls-rprx-vision", "xtls-rprx-vision-udp443":
			cred.Flow = flow
		default:
			return LinkResult{Err: perr(ErrUnsupportedValue, "flow", "不支持的 VLESS flow %q", flow)}
		}
	}
	tr, errT := b.transportFromQuery(q, "tcp")
	if errT != nil {
		return LinkResult{Err: errT}
	}
	sec, errS := b.securityFromQuery(q, false)
	if errS != nil {
		return LinkResult{Err: errS}
	}
	b.warnUnknownParams(q, knownTLSQueryParams)
	return b.finish("vless", fragName(u), host, port, cred, tr, sec, boolPtr(true), nil, raw)
}

// transportFromQuery 从分享链接 query 构造 Transport（vless/trojan 共用）。
func (b *builder) transportFromQuery(q url.Values, defType string) (*Transport, *ParseError) {
	t := q.Get("type")
	if t == "" {
		t = defType
	}
	mt, ok := mapTransportType(t)
	if !ok {
		return nil, perr(ErrUnsupportedValue, "type", "不支持的传输类型 %q", t)
	}
	tr := &Transport{Type: mt}
	if p := q.Get("path"); p != "" {
		tr.Path = p
	}
	if h := q.Get("host"); h != "" {
		tr.Host = h
	}
	if ht := q.Get("headerType"); ht != "" {
		tr.HeaderType = ht
	}
	if sn := q.Get("serviceName"); sn != "" {
		tr.ServiceName = sn
	}
	if mode := q.Get("mode"); mode != "" {
		if mt == "grpc" {
			if mode == "gun" || mode == "multi" {
				tr.GRPCMode = mode
			} else {
				b.warn(WarnUnknownParam, "mode", fmt.Sprintf("gRPC mode %q 不在已知取值内，已忽略", mode))
			}
		} else if mt == "xhttp" {
			tr.Mode = mode
		}
	}
	if seed := q.Get("seed"); seed != "" {
		tr.Seed = seed
	}
	return tr, nil
}

var knownTLSQueryParams = map[string]bool{
	"encryption": true, "flow": true, "security": true, "type": true,
	"path": true, "host": true, "headerType": true, "serviceName": true,
	"mode": true, "seed": true, "sni": true, "peer": true, "alpn": true,
	"fp": true, "fingerprint": true, "allowInsecure": true, "pbk": true,
	"sid": true, "spx": true,
}

// securityFromQuery 从 query 构造 Security（vless/trojan 共用）。
// trojan 的 security 参数缺省即 tls；vless 缺省 none。
func (b *builder) securityFromQuery(q url.Values, defaultTLS bool) (*Security, *ParseError) {
	secParam := strings.ToLower(q.Get("security"))
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = q.Get("fingerprint")
	}
	insecure := q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true")
	switch secParam {
	case "reality":
		pbk := q.Get("pbk")
		if pbk == "" {
			return nil, perr(ErrMissingField, "pbk", "security=reality 时 pbk（Reality 公钥）必填")
		}
		sec := &Security{Type: "reality", ServerName: sni, Fingerprint: fp, PublicKey: pbk, ShortID: q.Get("sid")}
		if spx, present := q["spx"]; present && len(spx) > 0 {
			v := spx[0]
			sec.SpiderX = &v
		}
		b.noteInsecure("allowInsecure", insecure)
		if insecure {
			sec.AllowInsecure = boolPtr(true)
		}
		return sec, nil
	case "tls", "xtls":
		sec := &Security{Type: "tls", ServerName: sni, ALPN: alpnList(q.Get("alpn")), Fingerprint: fp}
		if insecure {
			sec.AllowInsecure = boolPtr(true)
			b.noteInsecure("allowInsecure", true)
		}
		return sec, nil
	case "", "none":
		if defaultTLS {
			sec := &Security{Type: "tls", ServerName: sni, ALPN: alpnList(q.Get("alpn")), Fingerprint: fp}
			if insecure {
				sec.AllowInsecure = boolPtr(true)
				b.noteInsecure("allowInsecure", true)
			}
			return sec, nil
		}
		return nil, nil
	default:
		return nil, perr(ErrUnsupportedValue, "security", "不支持的 security 取值 %q", secParam)
	}
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------

func (b *builder) parseTrojan(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			// 罕见的 user:pass 双段形态：整体以冒号拼回为单一密码。
			password = password + ":" + pw
		}
	}
	if password == "" {
		return LinkResult{Err: perr(ErrMissingField, "password", "Trojan 密码为空")}
	}
	host, port, herr := splitHostPort(u.Host, 443)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	q := u.Query()
	var tr *Transport
	if q.Get("type") != "" {
		var errT *ParseError
		tr, errT = b.transportFromQuery(q, "tcp")
		if errT != nil {
			return LinkResult{Err: errT}
		}
		if tr.Type == "tcp" {
			tr = nil // tcp 为 trojan 原生形态，不必显式建模
		}
	}
	sec, errS := b.securityFromQuery(q, true)
	if errS != nil {
		return LinkResult{Err: errS}
	}
	b.warnUnknownParams(q, knownTLSQueryParams)
	return b.finish("trojan", fragName(u), host, port, credPassword{Password: password}, tr, sec, boolPtr(true), nil, raw)
}

// ---------------------------------------------------------------------------
// VMess：base64 JSON 形态与 query 形态
// ---------------------------------------------------------------------------

func (b *builder) parseVMess(raw string) LinkResult {
	rest := raw[len("vmess://"):]
	if strings.Contains(rest, "@") {
		return b.parseVMessQuery(raw)
	}
	dec, err := decodeBase64(rest)
	if err != nil {
		return LinkResult{Err: perr(ErrBadBase64, "uri", "vmess 链接 base64 解码失败：%v", err)}
	}
	var m map[string]any
	if err := json.Unmarshal(dec, &m); err != nil {
		return LinkResult{Err: perr(ErrBadJSON, "json", "vmess 链接 JSON 解析失败：%v", err)}
	}
	get := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			if v == float64(int64(v)) {
				return strconv.FormatInt(int64(v), 10)
			}
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	uuid := get("id")
	if err := checkUUID(uuid, "id"); err != nil {
		return LinkResult{Err: err}
	}
	server := get("add")
	if server == "" {
		return LinkResult{Err: perr(ErrMissingField, "add", "vmess 链接缺少服务器地址 add")}
	}
	port, herr := parsePortStr(get("port"), "port")
	if herr != nil {
		return LinkResult{Err: herr}
	}
	cred := credVMess{UUID: uuid}
	aidStr := get("aid")
	aid := 0
	if aidStr != "" {
		if a, e := strconv.Atoi(aidStr); e == nil && a >= 0 {
			aid = a
		}
	}
	cred.AlterID = &aid
	if aid > 0 {
		b.warn(WarnLegacyParameter, "aid", "VMess alterId 非 0 为旧式（非 AEAD）用法，已保留导入，建议更换节点")
	}
	cipher := get("scy")
	if cipher == "" {
		cipher = "auto"
		b.warn(WarnDefaultedField, "scy", "vmess 链接未给出加密方式 scy，已按 auto 补齐")
	}
	switch cipher {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
		cred.Cipher = cipher
	default:
		return LinkResult{Err: perr(ErrUnsupportedValue, "scy", "不支持的 VMess 加密方式 %q（统一模型枚举外）", cipher)}
	}
	// 传输
	net0 := get("net")
	if net0 == "" {
		net0 = "tcp"
	}
	tr := &Transport{}
	switch net0 {
	case "tcp":
		tr.Type = "tcp"
		if ht := get("type"); ht != "" && ht != "none" {
			tr.HeaderType = ht
		} else if ht == "none" {
			tr.HeaderType = "none"
		}
	case "ws":
		tr.Type = "ws"
		tr.Host = get("host")
		tr.Path = get("path")
	case "h2", "http":
		tr.Type = "http"
		tr.Host = get("host")
		tr.Path = get("path")
	case "grpc":
		tr.Type = "grpc"
		tr.ServiceName = get("path") // 旧式 vmess JSON 以 path 承载 grpc serviceName 的情况亦有，优先 serviceName 字段
		if sn := get("serviceName"); sn != "" {
			tr.ServiceName = sn
		}
	case "kcp":
		tr.Type = "kcp"
		if ht := get("type"); ht != "" {
			tr.HeaderType = ht
		}
	case "quic":
		tr.Type = "quic"
	case "httpupgrade":
		tr.Type = "httpupgrade"
		tr.Host = get("host")
		tr.Path = get("path")
	case "xhttp", "splithttp":
		tr.Type = "xhttp"
		tr.Host = get("host")
		tr.Path = get("path")
	default:
		return LinkResult{Err: perr(ErrUnsupportedValue, "net", "不支持的 VMess 传输 net=%q", net0)}
	}
	// 安全
	var sec *Security
	if get("tls") == "tls" {
		sec = &Security{Type: "tls", ServerName: get("sni"), ALPN: alpnList(get("alpn")), Fingerprint: get("fp")}
	}
	name := strings.TrimSpace(get("ps"))
	return b.finish("vmess", name, server, port, cred, tr, sec, boolPtr(true), nil, raw)
}

func (b *builder) parseVMessQuery(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if err := checkUUID(uuid, "uuid"); err != nil {
		return LinkResult{Err: err}
	}
	host, port, herr := splitHostPort(u.Host, 0)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	q := u.Query()
	cred := credVMess{UUID: uuid, Cipher: "auto"}
	if c := q.Get("scy"); c != "" {
		cred.Cipher = c
	} else if c := q.Get("encryption"); c != "" {
		cred.Cipher = c
	}
	switch cred.Cipher {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
	default:
		return LinkResult{Err: perr(ErrUnsupportedValue, "scy", "不支持的 VMess 加密方式 %q", cred.Cipher)}
	}
	if a := q.Get("aid"); a != "" {
		if av, e := strconv.Atoi(a); e == nil && av >= 0 {
			cred.AlterID = &av
			if av > 0 {
				b.warn(WarnLegacyParameter, "aid", "VMess alterId 非 0 为旧式（非 AEAD）用法，已保留导入")
			}
		}
	}
	tr, errT := b.transportFromQuery(q, "tcp")
	if errT != nil {
		return LinkResult{Err: errT}
	}
	var sec *Security
	if q.Get("security") == "tls" {
		sec = &Security{Type: "tls", ServerName: q.Get("sni"), ALPN: alpnList(q.Get("alpn")), Fingerprint: q.Get("fp")}
	}
	b.warnUnknownParams(q, map[string]bool{
		"type": true, "security": true, "path": true, "host": true, "serviceName": true,
		"headerType": true, "mode": true, "seed": true, "sni": true, "alpn": true, "fp": true,
		"scy": true, "encryption": true, "aid": true, "allowInsecure": true,
	})
	if q.Get("allowInsecure") == "1" && sec != nil {
		sec.AllowInsecure = boolPtr(true)
		b.noteInsecure("allowInsecure", true)
	}
	return b.finish("vmess", fragName(u), host, port, cred, tr, sec, boolPtr(true), nil, raw)
}

// ---------------------------------------------------------------------------
// Hysteria2（含 hy2:// 别名）
// ---------------------------------------------------------------------------

func (b *builder) parseHysteria2(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	q := u.Query()
	auth := q.Get("auth")
	if auth == "" && u.User != nil {
		auth = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			auth = auth + ":" + pw
		}
	}
	if auth == "" {
		return LinkResult{Err: perr(ErrMissingField, "auth", "Hysteria2 认证串为空")}
	}
	host, port, herr := splitHostPort(u.Host, 443)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	cred := credHysteria2{Auth: auth}
	if obfs := q.Get("obfs"); obfs != "" {
		if obfs != "salamander" {
			return LinkResult{Err: perr(ErrUnsupportedValue, "obfs", "不支持的 Hysteria2 混淆类型 %q（现行实现仅 salamander）", obfs)}
		}
		cred.ObfsType = obfs
		obfsPw := q.Get("obfs-password")
		if obfsPw == "" {
			obfsPw = q.Get("obfsParam")
		}
		if obfsPw == "" {
			return LinkResult{Err: perr(ErrMissingField, "obfs-password", "obfs=salamander 时 obfs-password 必填")}
		}
		cred.ObfsPassword = obfsPw
	}
	var extraPorts []string
	if mport := q.Get("mport"); mport != "" {
		for _, p := range strings.Split(mport, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !validPortRange(p) {
				return LinkResult{Err: perr(ErrBadPort, "mport", "端口跳跃段 %q 非法", p)}
			}
			extraPorts = append(extraPorts, p)
		}
	}
	insecure := q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true")
	sec := &Security{Type: "tls", ServerName: q.Get("sni"), ALPN: alpnList(q.Get("alpn"))}
	if pin := q.Get("pinSHA256"); pin != "" {
		sec.CertificatePinSha256 = pin
	}
	if insecure {
		sec.AllowInsecure = boolPtr(true)
		b.noteInsecure("insecure", true)
	}
	b.warnUnknownParams(q, map[string]bool{
		"auth": true, "obfs": true, "obfs-password": true, "obfsParam": true,
		"mport": true, "sni": true, "alpn": true, "insecure": true, "pinSHA256": true,
	})
	return b.finish("hysteria2", fragName(u), host, port, cred, nil, sec, boolPtr(true), extraPorts, raw)
}

func validPortRange(p string) bool {
	parts := strings.Split(p, "-")
	if len(parts) > 2 {
		return false
	}
	for _, x := range parts {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if len(parts) == 2 {
		a, _ := strconv.Atoi(parts[0])
		c, _ := strconv.Atoi(parts[1])
		if a > c {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// TUIC
// ---------------------------------------------------------------------------

func (b *builder) parseTUIC(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	var uuid, password string
	if u.User != nil {
		uuid = u.User.Username()
		password, _ = u.User.Password()
	}
	if err := checkUUID(uuid, "uuid"); err != nil {
		return LinkResult{Err: err}
	}
	if password == "" {
		return LinkResult{Err: perr(ErrMissingField, "password", "TUIC 密码为空")}
	}
	host, port, herr := splitHostPort(u.Host, 443)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	q := u.Query()
	var tr *Transport
	cc, urm := q.Get("congestion_control"), q.Get("udp_relay_mode")
	if cc != "" || urm != "" {
		tr = &Transport{Type: "quic"}
		if cc != "" {
			switch cc {
			case "cubic", "new_reno", "bbr":
				tr.CongestionControl = cc
			default:
				return LinkResult{Err: perr(ErrUnsupportedValue, "congestion_control", "不支持的拥塞控制 %q", cc)}
			}
		}
		if urm != "" {
			switch urm {
			case "native", "quic":
				tr.UDPRelayMode = urm
			default:
				return LinkResult{Err: perr(ErrUnsupportedValue, "udp_relay_mode", "不支持的 UDP 中继模式 %q", urm)}
			}
		}
	}
	sec := &Security{Type: "tls", ALPN: alpnList(q.Get("alpn"))}
	if q.Get("disable_sni") != "1" {
		sec.ServerName = q.Get("sni")
	}
	insecure := q.Get("allow_insecure") == "1" || strings.EqualFold(q.Get("allow_insecure"), "true")
	if insecure {
		sec.AllowInsecure = boolPtr(true)
		b.noteInsecure("allow_insecure", true)
	}
	b.warnUnknownParams(q, map[string]bool{
		"congestion_control": true, "udp_relay_mode": true, "sni": true,
		"alpn": true, "allow_insecure": true, "disable_sni": true,
	})
	return b.finish("tuic", fragName(u), host, port, credTUIC{UUID: uuid, Password: password}, tr, sec, boolPtr(true), nil, raw)
}

// ---------------------------------------------------------------------------
// WireGuard 分享链接（wg:// / wireguard://）
// ---------------------------------------------------------------------------

var wgKeyRe = func() func(string) bool {
	return func(s string) bool {
		if len(s) != 44 || !strings.HasSuffix(s, "=") {
			return false
		}
		for _, r := range s[:43] {
			ok := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/'
			if !ok {
				return false
			}
		}
		return true
	}
}()

func checkWGKey(s, seg string) *ParseError {
	if !wgKeyRe(s) {
		return perr(ErrBadKeyFormat, seg, "%s 不是 44 字符 Base64 的 WireGuard 密钥", seg)
	}
	return nil
}

// parseWireGuardLink 手工解析：密钥为标准 Base64（含 + 与 /），
// 不能交给 net/url 的 userinfo 规则处理。
func (b *builder) parseWireGuardLink(raw string) LinkResult {
	rest := raw[strings.Index(raw, "://")+3:]
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name = rest[i+1:]
		rest = rest[:i]
		if n, err := url.QueryUnescape(name); err == nil {
			name = strings.TrimSpace(n)
		}
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	q, _ := url.ParseQuery(query)
	var priv, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		priv, _ = url.PathUnescape(rest[:at])
		hostport = rest[at+1:]
	} else {
		hostport = rest
		priv = q.Get("privatekey")
	}
	cred, err := b.wgCredFromParts(priv, q)
	if err != nil {
		return LinkResult{Err: err}
	}
	host, port, err2 := splitHostPort(strings.TrimSuffix(hostport, "/"), 51820)
	if err2 != nil {
		return LinkResult{Err: err2}
	}
	return b.finish("wireguard", name, host, port, cred, &Transport{Type: "raw"}, nil, boolPtr(true), nil, raw)
}

// wgCredFromParts 由私钥与参数集构造 WireGuard 凭据（链接与 .conf 共用校验）。
func (b *builder) wgCredFromParts(priv string, q url.Values) (credWireGuard, *ParseError) {
	var cred credWireGuard
	if err := checkWGKey(priv, "privateKey"); err != nil {
		return cred, err
	}
	cred.PrivateKey = priv
	pub := q.Get("publickey")
	if err := checkWGKey(pub, "publicKey"); err != nil {
		return cred, err
	}
	cred.PeerPublicKey = pub
	if psk := q.Get("presharedkey"); psk != "" {
		if err := checkWGKey(psk, "presharedKey"); err != nil {
			return cred, err
		}
		cred.PreSharedKey = psk
	}
	addr := csvList(q.Get("address"))
	if len(addr) == 0 {
		return cred, perr(ErrMissingField, "address", "WireGuard 配置缺少本机地址 address")
	}
	cred.Addresses = addr
	allowed := csvList(q.Get("allowedips"))
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
		b.warn(WarnDefaultedField, "allowedips", "未给出 allowedips，已按全隧道 0.0.0.0/0 与 ::/0 补齐")
	}
	cred.AllowedIPs = allowed
	cred.DNS = csvList(q.Get("dns"))
	if mtu := q.Get("mtu"); mtu != "" {
		n, err := strconv.Atoi(mtu)
		if err != nil || n < 128 || n > 9000 {
			return cred, perr(ErrUnsupportedValue, "mtu", "MTU %q 非法（须为 128-9000）", mtu)
		}
		cred.MTU = n
	}
	if ka := q.Get("keepalive"); ka != "" {
		n, err := strconv.Atoi(ka)
		if err != nil || n < 0 || n > 65535 {
			return cred, perr(ErrUnsupportedValue, "keepalive", "PersistentKeepalive %q 非法", ka)
		}
		cred.PersistentKeepalive = n
	}
	if r := q.Get("reserved"); r != "" {
		parts := strings.FieldsFunc(r, func(c rune) bool { return c == ',' || c == ' ' })
		if len(parts) != 3 {
			return cred, perr(ErrBadFormat, "reserved", "reserved 须为 3 个字节")
		}
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return cred, perr(ErrBadFormat, "reserved", "reserved 字节 %q 非法", p)
			}
			cred.Reserved = append(cred.Reserved, n)
		}
	}
	b.warnUnknownParams(q, map[string]bool{
		"publickey": true, "presharedkey": true, "privatekey": true, "address": true,
		"dns": true, "mtu": true, "allowedips": true, "keepalive": true, "reserved": true,
		"endpoint": true,
	})
	return cred, nil
}

func csvList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// SOCKS5 / HTTP(S) 代理链接（方案书 4.1 第一梯队，spec README 对照表覆盖）
// ---------------------------------------------------------------------------

func (b *builder) parseSOCKS5(raw string) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	host, port, herr := splitHostPort(u.Host, 1080)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	var cred credUserPass
	if u.User != nil {
		cred.Username = u.User.Username()
		cred.Password, _ = u.User.Password()
		if cred.Username != "" && cred.Password == "" {
			return LinkResult{Err: perr(ErrMissingField, "password", "给出用户名时密码必填")}
		}
	}
	udp := boolPtr(true)
	if v := u.Query().Get("udp"); v == "false" || v == "0" {
		udp = boolPtr(false)
	}
	return b.finish("socks5", fragName(u), host, port, cred, &Transport{Type: "raw"}, nil, udp, nil, raw)
}

func (b *builder) parseHTTPProxy(raw string, isHTTPS bool) LinkResult {
	u, err := url.Parse(raw)
	if err != nil {
		return LinkResult{Err: perr(ErrBadURI, "uri", "链接不是合法 URI：%v", err)}
	}
	defPort := 80
	if isHTTPS {
		defPort = 443
	}
	host, port, herr := splitHostPort(u.Host, defPort)
	if herr != nil {
		return LinkResult{Err: herr}
	}
	var cred credUserPass
	if u.User != nil {
		cred.Username = u.User.Username()
		cred.Password, _ = u.User.Password()
		if cred.Username != "" && cred.Password == "" {
			return LinkResult{Err: perr(ErrMissingField, "password", "给出用户名时密码必填")}
		}
	}
	var sec *Security
	if isHTTPS {
		sni := u.Query().Get("sni")
		if sni == "" {
			sni = host
		}
		sec = &Security{Type: "tls", ServerName: sni}
	}
	return b.finish("http", fragName(u), host, port, cred, &Transport{Type: "raw"}, sec, nil, nil, raw)
}
