// Package parsers 实现方案书 4.2 的解析器全家桶（Step 8）：
// 把各协议分享链接、WireGuard/OpenVPN 配置文件与主流订阅格式
// 解析为 spec/ 已冻结的统一节点模型（Step 5）对象。
//
// 设计约束：
//   - 产出对象必须通过 spec/unified-node-model.schema.json 校验；
//   - 异常输入不 panic：错误一律结构化返回（见 ParseError）；
//   - 弱加密、跳过证书校验等风险以结构化 Warning 随产出携带
//     （Step 5 评审冻结裁定义务：老式 SS 方法必须警示、不得默认推荐）；
//   - 批量解析时单条失败不拖垮整批（见 BatchResult）。
package parsers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 模型对象（字段与 spec/unified-node-model.schema.json 的 $defs 一一对应）
// ---------------------------------------------------------------------------

// SourceRef 对应 schema 的 NodeSourceRef。
type SourceRef struct {
	Kind          string `json:"kind"`
	Ref           string `json:"ref"`
	Authorization string `json:"authorization"`
}

// Transport 对应 schema 的 Transport。
type Transport struct {
	Type              string            `json:"type"`
	Path              string            `json:"path,omitempty"`
	Host              string            `json:"host,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	HeaderType        string            `json:"headerType,omitempty"`
	ServiceName       string            `json:"serviceName,omitempty"`
	GRPCMode          string            `json:"grpcMode,omitempty"`
	Seed              string            `json:"seed,omitempty"`
	Mode              string            `json:"mode,omitempty"`
	CongestionControl string            `json:"congestionControl,omitempty"`
	UDPRelayMode      string            `json:"udpRelayMode,omitempty"`
}

// Security 对应 schema 的 Security。
type Security struct {
	Type                 string   `json:"type"`
	ServerName           string   `json:"serverName,omitempty"`
	ALPN                 []string `json:"alpn,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	AllowInsecure        *bool    `json:"allowInsecure,omitempty"`
	CertificatePinSha256 string   `json:"certificatePinSha256,omitempty"`
	PublicKey            string   `json:"publicKey,omitempty"`
	ShortID              string   `json:"shortId,omitempty"`
	SpiderX              *string  `json:"spiderX,omitempty"`
}

// Node 对应 schema 的 Node。
type Node struct {
	SchemaVersion string          `json:"schemaVersion"`
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Protocol      string          `json:"protocol"`
	Server        string          `json:"server,omitempty"`
	Port          int             `json:"port,omitempty"`
	Credential    json.RawMessage `json:"credential"`
	Transport     *Transport      `json:"transport,omitempty"`
	Security      *Security       `json:"security,omitempty"`
	UDP           *bool           `json:"udp,omitempty"`
	ExtraPorts    []string        `json:"extraPorts,omitempty"`
	Source        SourceRef       `json:"source"`
	Group         string          `json:"group,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	Remarks       string          `json:"remarks,omitempty"`
}

// Group 对应 schema 的 Group。
type Group struct {
	SchemaVersion string   `json:"schemaVersion"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	NodeIDs       []string `json:"nodeIds"`
	Description   string   `json:"description,omitempty"`
	SourceID      *string  `json:"sourceId,omitempty"`
}

// SourceAuthorization 对应 schema 的 Source.authorization。
type SourceAuthorization struct {
	Status   string  `json:"status"`
	Basis    string  `json:"basis"`
	TermsURL *string `json:"termsUrl,omitempty"`
}

// Source 对应 schema 的 Source。
type Source struct {
	SchemaVersion         string              `json:"schemaVersion"`
	ID                    string              `json:"id"`
	Kind                  string              `json:"kind"`
	Name                  string              `json:"name"`
	Operator              *string             `json:"operator,omitempty"`
	Authorization         SourceAuthorization `json:"authorization"`
	DataFormat            string              `json:"dataFormat"`
	UpdateIntervalMinutes *int                `json:"updateIntervalMinutes,omitempty"`
	Homepage              *string             `json:"homepage,omitempty"`
}

// SubscriptionTraffic 对应 schema 的 Subscription.traffic。
type SubscriptionTraffic struct {
	Upload   int64   `json:"upload,omitempty"`
	Download int64   `json:"download,omitempty"`
	Total    int64   `json:"total,omitempty"`
	ExpireAt *string `json:"expireAt,omitempty"`
}

// Subscription 对应 schema 的 Subscription。
type Subscription struct {
	SchemaVersion         string               `json:"schemaVersion"`
	ID                    string               `json:"id"`
	Name                  string               `json:"name"`
	URL                   string               `json:"url"`
	Format                string               `json:"format"`
	UserAgent             string               `json:"userAgent,omitempty"`
	Enabled               *bool                `json:"enabled,omitempty"`
	UpdateIntervalMinutes *int                 `json:"updateIntervalMinutes,omitempty"`
	LastUpdatedAt         *string              `json:"lastUpdatedAt,omitempty"`
	SourceID              *string              `json:"sourceId,omitempty"`
	GroupName             string               `json:"groupName,omitempty"`
	Traffic               *SubscriptionTraffic `json:"traffic,omitempty"`
}

// ---------------------------------------------------------------------------
// 警示与错误
// ---------------------------------------------------------------------------

// Warning 是随解析产出携带的结构化警示。Code 为稳定机器可读码，
// Field 指出涉及的链接参数/模型字段，Message 为面向人的说明。
type Warning struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// 警示码（稳定，UI 层按码决定呈现强度）。
const (
	WarnWeakEncryption     = "weak-encryption"         // 弱加密方法（SS 老式方法）：Step 5 冻结裁定义务
	WarnInsecureSkipVerify = "insecure-skip-verify"    // allowInsecure/insecure=true，跳过证书校验
	WarnDeprecatedFormat   = "deprecated-format"       // 已弃用的链接形态（如 ss 旧式整体 base64）
	WarnDefaultedField     = "missing-field-defaulted" // 参数缺失、已按约定默认值补齐
	WarnUnknownParam       = "unknown-param-ignored"   // 无法识别的参数，已忽略
	WarnParamNotModeled    = "param-not-modeled"       // 参数在统一模型中未建模（spec README 已登记取舍），已忽略
	WarnCredentialsNeeded  = "credentials-required"    // 配置要求另行提供用户名/密码
	WarnLegacyParameter    = "legacy-parameter"        // 存量旧参数（如 VMess alterId 非 0）
)

// ParseError 是结构化解析错误。Index 为批量解析中的条目序号（单条解析为 0），
// Segment 指出出错的那一段（scheme/userinfo/host/query/json/<字段名> 等）。
type ParseError struct {
	Code    string `json:"code"`
	Index   int    `json:"index,omitempty"`
	Segment string `json:"segment,omitempty"`
	Detail  string `json:"detail"`
}

func (e *ParseError) Error() string {
	if e.Segment != "" {
		return fmt.Sprintf("%s [%s]: %s", e.Code, e.Segment, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// 错误码（稳定）。
const (
	ErrEmptyInput       = "empty-input"
	ErrInputTooLarge    = "input-too-large"
	ErrUnknownScheme    = "unknown-scheme"
	ErrUnsupportedProto = "unsupported-protocol"
	ErrBadBase64        = "bad-base64"
	ErrBadJSON          = "bad-json"
	ErrBadURI           = "bad-uri"
	ErrMissingField     = "missing-field"
	ErrBadPort          = "bad-port"
	ErrBadUUID          = "bad-uuid"
	ErrBadKeyFormat     = "bad-key-format"
	ErrUnsupportedValue = "unsupported-value"
	ErrBadFormat        = "bad-format"
)

func perr(code, segment, format string, args ...any) *ParseError {
	return &ParseError{Code: code, Segment: segment, Detail: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// 解析选项与结果
// ---------------------------------------------------------------------------

// Options 控制来源标注与分组落点。
type Options struct {
	// Source 来源标注，零值时按入口给默认：
	// ParseLink 默认 {manual, link-import, user-provided}。
	Source *SourceRef
	// Group 非空时写入 Node.group（订阅解析默认写入分组名）。
	Group string
	// Name 覆盖节点名（.conf/.ovpn 等无内嵌名称的格式用，亦可传文件名）。
	Name string
}

// LinkResult 是单条链接/文件的解析结果。
type LinkResult struct {
	Node     *Node       `json:"node,omitempty"`
	Warnings []Warning   `json:"warnings,omitempty"`
	Err      *ParseError `json:"error,omitempty"`
}

// ItemResult 是批量解析中的一条结果（成功或失败）。
type ItemResult struct {
	Index    int         `json:"index"`
	Raw      string      `json:"raw,omitempty"` // 原始条目（截断至 120 字符，仅供定位）
	Node     *Node       `json:"node,omitempty"`
	Warnings []Warning   `json:"warnings,omitempty"`
	Err      *ParseError `json:"error,omitempty"`
}

// BatchResult 是批量解析（链接列表/订阅内容）的整体结果。
type BatchResult struct {
	Items    []ItemResult `json:"items"`
	Warnings []Warning    `json:"warnings,omitempty"`
	// Format 为识别出的订阅/列表格式（模型 Subscription.format /
	// Source.dataFormat 取值），单链接解析时为空。
	Format string `json:"format,omitempty"`
	// Group/Subscription/Source 为订阅解析时一并构造的登记对象（按 Options 决定是否产出）。
	Group        *Group        `json:"group,omitempty"`
	Subscription *Subscription `json:"subscription,omitempty"`
	SourceRecord *Source       `json:"sourceRecord,omitempty"`
}

// OK 统计批量结果中的成功条数。
func (b *BatchResult) OK() int {
	n := 0
	for _, it := range b.Items {
		if it.Err == nil && it.Node != nil {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// 入口：单条链接
// ---------------------------------------------------------------------------

const (
	maxLinkBytes  = 64 * 1024
	maxBatchBytes = 16 * 1024 * 1024
	maxBatchItems = 10000
)

// ParseLink 解析一条分享链接（ss/vless/vmess/trojan/hysteria2/hy2/tuic/
// wg/wireguard/socks5/http/https）。不接受订阅内容与配置文件全文
// （那些走 ParseWireGuardConf / ParseOpenVPNConf / ParseSubscription）。
func ParseLink(raw string, opts Options) LinkResult {
	s := strings.TrimSpace(raw)
	if s == "" {
		return LinkResult{Err: perr(ErrEmptyInput, "", "链接为空")}
	}
	if len(s) > maxLinkBytes {
		return LinkResult{Err: perr(ErrInputTooLarge, "", "单条链接超过 %d 字节上限", maxLinkBytes)}
	}
	src := opts.sourceOrDefault(SourceRef{Kind: "manual", Ref: "link-import", Authorization: "user-provided"})
	b := &builder{src: src, group: opts.Group, optName: opts.Name}
	scheme := schemeOf(s)
	var res LinkResult
	switch scheme {
	case "vless":
		res = b.parseVLESS(s)
	case "vmess":
		res = b.parseVMess(s)
	case "trojan":
		res = b.parseTrojan(s)
	case "ss":
		res = b.parseSS(s)
	case "hysteria2", "hy2":
		res = b.parseHysteria2(s)
	case "tuic":
		res = b.parseTUIC(s)
	case "wg", "wireguard":
		res = b.parseWireGuardLink(s)
	case "socks5":
		res = b.parseSOCKS5(s)
	case "http", "https":
		res = b.parseHTTPProxy(s, scheme == "https")
	default:
		res = LinkResult{Err: perr(ErrUnknownScheme, "scheme", "未知或不支持的链接协议头 %q", scheme)}
	}
	return res
}

// ParseLinkList 解析明文链接列表（一行一条，空行与 # 注释行跳过）。
// 单条失败不拖垮整批：失败条目带结构化 Err 逐条标注。
func ParseLinkList(text string, opts Options) *BatchResult {
	out := &BatchResult{Format: "link-list"}
	if len(text) > maxBatchBytes {
		out.Items = append(out.Items, ItemResult{Index: 0, Err: perr(ErrInputTooLarge, "", "输入超过 %d 字节上限", maxBatchBytes)})
		return out
	}
	lines := splitLines(text)
	idx := 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if idx >= maxBatchItems {
			out.Items = append(out.Items, ItemResult{Index: idx, Err: perr(ErrInputTooLarge, "", "条目数超过 %d 上限，其余已截断", maxBatchItems)})
			break
		}
		r := ParseLink(t, opts)
		it := ItemResult{Index: idx, Raw: truncate(t, 120), Node: r.Node, Warnings: r.Warnings, Err: r.Err}
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

// ---------------------------------------------------------------------------
// 内部构建器与通用助手
// ---------------------------------------------------------------------------

type builder struct {
	src     SourceRef
	group   string
	optName string
	warns   []Warning
}

func (o Options) sourceOrDefault(def SourceRef) SourceRef {
	if o.Source != nil {
		return *o.Source
	}
	return def
}

func (b *builder) warn(code, field, msg string) {
	b.warns = append(b.warns, Warning{Code: code, Field: field, Message: msg})
}

// finish 组装节点公共字段并返回结果。cred 为已构造的凭据对象。
func (b *builder) finish(protocol, name, server string, port int, cred any, tr *Transport, sec *Security, udp *bool, extraPorts []string, canonical string) LinkResult {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return LinkResult{Err: perr(ErrBadFormat, "credential", "凭据序列化失败：%v", err)}
	}
	if name == "" {
		name = b.optName
	}
	if name == "" {
		name = fmt.Sprintf("%s-%s:%d", protocol, server, port)
	}
	idSeed := protocol + "|" + server + "|" + strconv.Itoa(port) + "|" + string(credJSON) + "|" + canonical
	n := &Node{
		SchemaVersion: "1.0",
		ID:            deterministicUUID(idSeed),
		Name:          name,
		Protocol:      protocol,
		Server:        server,
		Port:          port,
		Credential:    credJSON,
		Transport:     tr,
		Security:      sec,
		UDP:           udp,
		ExtraPorts:    extraPorts,
		Source:        b.src,
		Group:         b.group,
	}
	return LinkResult{Node: n, Warnings: b.warns}
}

// omitServerFinish 用于 OpenVPN 全文模式（server/port 可省略）。
func (b *builder) finishContentNode(name string, cred any, server string, port int, canonical string) LinkResult {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return LinkResult{Err: perr(ErrBadFormat, "credential", "凭据序列化失败：%v", err)}
	}
	if name == "" {
		name = b.optName
	}
	if name == "" {
		name = "openvpn-config"
	}
	idSeed := "openvpn|" + server + "|" + strconv.Itoa(port) + "|" + string(credJSON) + "|" + canonical
	n := &Node{
		SchemaVersion: "1.0",
		ID:            deterministicUUID(idSeed),
		Name:          name,
		Protocol:      "openvpn",
		Credential:    credJSON,
		Source:        b.src,
		Group:         b.group,
	}
	if server != "" {
		n.Server = server
		n.Port = port
	}
	return LinkResult{Node: n, Warnings: b.warns}
}

// deterministicUUID 由内容哈希派生稳定 UUID（订阅刷新时同一节点不换 id）。
func deterministicUUID(seed string) string {
	h := sha256.Sum256([]byte("relavia-node-v1\x00" + seed))
	var b [16]byte
	copy(b[:], h[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 风格
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func schemeOf(s string) string {
	i := strings.Index(s, "://")
	if i < 0 {
		return ""
	}
	return strings.ToLower(s[:i])
}

func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// decodeBase64 容忍标准/URL 安全两种字母表与有无填充。
func decodeBase64(s string) ([]byte, error) {
	t := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	encs := []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encs {
		if out, err := enc.DecodeString(t); err == nil {
			return out, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

// looksBase64 粗判一整段文本是否为 base64 订阅 blob。
func looksBase64(s string) bool {
	t := strings.Join(strings.Fields(s), "")
	if len(t) < 16 || len(t)%4 == 1 {
		return false
	}
	for _, r := range t {
		ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '-' || r == '_' || r == '='
		if !ok {
			return false
		}
	}
	return true
}

// splitHostPort 解析 host:port（支持 [IPv6]:port）；defaultPort>0 时缺端口按其补齐。
func splitHostPort(hp string, defaultPort int) (string, int, *ParseError) {
	host, portStr, err := splitHostPortRaw(hp)
	if err != nil {
		return "", 0, err
	}
	if portStr == "" {
		if defaultPort > 0 {
			return host, defaultPort, nil
		}
		return "", 0, perr(ErrMissingField, "host", "缺少端口")
	}
	p, aerr := strconv.Atoi(portStr)
	if aerr != nil || p < 1 || p > 65535 {
		return "", 0, perr(ErrBadPort, "port", "端口 %q 非法（须为 1-65535）", portStr)
	}
	return host, p, nil
}

func splitHostPortRaw(hp string) (host, port string, err *ParseError) {
	hp = strings.TrimSpace(hp)
	if hp == "" {
		return "", "", perr(ErrMissingField, "host", "服务器地址为空")
	}
	if strings.HasPrefix(hp, "[") {
		end := strings.Index(hp, "]")
		if end < 0 {
			return "", "", perr(ErrBadURI, "host", "IPv6 地址缺少 ]")
		}
		host = hp[1:end]
		rest := hp[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", perr(ErrBadURI, "host", "IPv6 地址后存在无法解析的内容")
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return hp, "", nil
	}
	// 裸 IPv6（多个冒号且无端口语义）按整串为主机、缺端口处理。
	if strings.Count(hp, ":") > 1 {
		return hp, "", nil
	}
	return hp[:i], hp[i+1:], nil
}

// fragName 取 URL fragment 作为节点名。
func fragName(u *url.URL) string {
	if u.Fragment == "" {
		return ""
	}
	if n, err := url.QueryUnescape(u.Fragment); err == nil {
		return strings.TrimSpace(n)
	}
	return strings.TrimSpace(u.Fragment)
}

func boolPtr(v bool) *bool { return &v }

// parsePortStr 校验端口字符串。
func parsePortStr(s, seg string) (int, *ParseError) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, perr(ErrBadPort, seg, "端口 %q 非法（须为 1-65535）", s)
	}
	return p, nil
}

var uuidRe = func() func(string) bool {
	return func(s string) bool {
		if len(s) != 36 {
			return false
		}
		for i, r := range s {
			switch i {
			case 8, 13, 18, 23:
				if r != '-' {
					return false
				}
			default:
				if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
					return false
				}
			}
		}
		return true
	}
}()

func checkUUID(s, seg string) *ParseError {
	if !uuidRe(s) {
		return perr(ErrBadUUID, seg, "%q 不是合法 UUID", s)
	}
	return nil
}

// alpnList 解析逗号分隔的 alpn 参数。
func alpnList(s string) []string {
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

// mapTransportType 把链接里的传输名映射到模型 Transport.type 枚举。
func mapTransportType(t string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "tcp":
		return "tcp", true
	case "raw":
		return "raw", true
	case "ws", "websocket":
		return "ws", true
	case "grpc":
		return "grpc", true
	case "http", "h2":
		return "http", true
	case "httpupgrade":
		return "httpupgrade", true
	case "xhttp", "splithttp":
		return "xhttp", true
	case "kcp", "mkcp":
		return "kcp", true
	case "quic":
		return "quic", true
	}
	return "", false
}

// knownParams 登记已知参数；其余参数产生 unknown-param 警示。
func (b *builder) warnUnknownParams(q url.Values, known map[string]bool) {
	for k := range q {
		if !known[k] {
			b.warn(WarnUnknownParam, k, fmt.Sprintf("参数 %s 无法识别，已忽略", k))
		}
	}
}

// insecureWarning 在 allowInsecure 被置 true 时统一发警示。
func (b *builder) noteInsecure(field string, insecure bool) {
	if insecure {
		b.warn(WarnInsecureSkipVerify, field, "该节点跳过 TLS 证书校验（allowInsecure/insecure），存在中间人风险，导入后应在 UI 中显著提示")
	}
}
