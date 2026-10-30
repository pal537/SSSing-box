package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ---------- sing-box 全量配置生成器 ----------
//
// 把面板节点记录翻译成 sing-box JSON。字段名以 sing-box 官方文档为准：
// 入站页（TUIC / Naive / Hysteria2）、TLS 共享页（reality / certificate_path）、
// WireGuard 端点页、路由规则动作页（sniff / route）、V2Ray 传输页。
// 生成结果必须过 `sing-box check` 校验（见 singbox_test.go），文档核对代替不了这一步。
//
// 约定：
//   - 入站 tag 沿用 in-<节点 id>，WireGuard 端点 tag 用 wg-<节点 id>，
//     链式出站 tag 用 chain-<链式 id>，与旧版 xray / 翻译层命名一致。
//   - 旧记录缺 Mode 字段时一律按原默认档处理（VLESS=reality、VMess=tcp、
//     Trojan=reality），老库平移不改行为。

// ---------- 新增协议配置 ----------

type TUICConfig struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Listen   string `json:"listen"`
}

func DefaultTUIC() TUICConfig {
	return TUICConfig{UUID: newUUID(), Password: randHex(8)}
}

type AnyTLSConfig struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Listen   string `json:"listen"`
}

func DefaultAnyTLS() AnyTLSConfig {
	return AnyTLSConfig{Name: "user", Password: randHex(8)}
}

type NaiveConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"` // 真域名：Naive 必须用 CA 证书，自签不行
	Listen   string `json:"listen"`
	CertFile string `json:"cert_file"` // 上传的 CA 证书（Apply 层校验存在）
	KeyFile  string `json:"key_file"`
}

func DefaultNaive() NaiveConfig {
	return NaiveConfig{Username: "user-" + randHex(3), Password: randHex(8)}
}

// ---------- TLS / 传输小件 ----------

// sbListen：入站监听默认值一律双栈 "::"（Linux 默认 bindv6only=0 时
// "::" 同时接受 v4/v6，v4 客户端走 v4-mapped，不用再分两个监听）。
// 安全前提已在甲骨文（有公网 v6）和 RN（无公网 v6、bindv6only=0）上实测：
// "::" 在无公网 v6 的机器上照样起、v4 照样通；显式配过 Listen 的节点不受影响。
func sbListen(listen, def string) string {
	if listen != "" {
		return listen
	}
	return def
}

// realityTLS：入站 Reality。short_id 在 sing-box 是数组，xray 的单个值要包成数组。
func realityTLS(serverName, privateKey, shortID, dest string) map[string]interface{} {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		host, portStr = dest, "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	r := map[string]interface{}{
		"enabled": true,
		"handshake": map[string]interface{}{
			"server":      host,
			"server_port": port,
		},
		"private_key": privateKey,
	}
	if shortID != "" {
		r["short_id"] = []string{shortID}
	}
	tls := map[string]interface{}{"enabled": true, "reality": r}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	return tls
}

// certTLS：证书 TLS（自签或 CA 证书都走这对路径）。server_name 为空时不写该键。
func certTLS(serverName, certPath, keyPath string) map[string]interface{} {
	tls := map[string]interface{}{
		"enabled":          true,
		"certificate_path": certPath,
		"key_path":         keyPath,
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	return tls
}

func wsTransport(path, host string) map[string]interface{} {
	t := map[string]interface{}{"type": "ws"}
	if path != "" {
		t["path"] = path
	}
	if host != "" {
		t["headers"] = map[string]interface{}{"Host": host}
	}
	return t
}

func httpTransport(host, path string) map[string]interface{} {
	t := map[string]interface{}{"type": "http"}
	if host != "" {
		t["host"] = []string{host}
	}
	if path != "" {
		t["path"] = path
	}
	return t
}

func httpUpgradeTransport(host, path string) map[string]interface{} {
	t := map[string]interface{}{"type": "httpupgrade"}
	if host != "" {
		t["host"] = host
	}
	if path != "" {
		t["path"] = path
	}
	return t
}

// ---------- VLESS ----------

// SingBoxVLESSInbound：Mode ""=reality；ws/h2/httpupgrade 走证书 TLS，
// 此时 flow 必须丢掉（xtls-rprx-vision 只用于 TCP 裸流，带传输会直接报错）。
func SingBoxVLESSInbound(tag string, port int, sni string, cfg VLESSConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "reality"
	}
	in := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
	}
	switch mode {
	case "reality":
		dest := cfg.Dest
		if dest == "" {
			dest = sni + ":443"
		}
		user := map[string]interface{}{"uuid": cfg.UUID}
		if cfg.Flow != "" {
			user["flow"] = cfg.Flow
		}
		in["users"] = []interface{}{user}
		in["tls"] = realityTLS(sni, cfg.PrivateKey, cfg.ShortID, dest)
	default:
		// ws / h2 / httpupgrade：证书 TLS 档
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["users"] = []interface{}{map[string]interface{}{"uuid": cfg.UUID}}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		switch mode {
		case "ws":
			in["transport"] = wsTransport(cfg.Path, domain)
		case "h2":
			in["transport"] = httpTransport(domain, cfg.Path)
		case "httpupgrade":
			in["transport"] = httpUpgradeTransport(domain, cfg.Path)
		}
	}
	return in
}

// ---------- VMess ----------

// SingBoxVMessInbound：Mode ""=tcp；cf=WS+TLS（自签，沿用现有 CF 档）；
// http=明文 http 传输；quic=QUIC 传输（必须配 TLS）；h2/httpupgrade=证书 TLS 档。
func SingBoxVMessInbound(tag string, port int, cfg VMessConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "tcp"
	}
	in := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"uuid": cfg.UUID, "alterId": 0}},
	}
	switch mode {
	case "tcp":
		// 裸 TCP：无 transport、无 tls
	case "cf":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = wsTransport(cfg.Path, cfg.Domain)
	case "http":
		in["transport"] = httpTransport(cfg.Domain, cfg.Path)
	case "quic":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = map[string]interface{}{"type": "quic"}
	case "h2":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpTransport(cfg.Domain, cfg.Path)
	case "httpupgrade":
		in["tls"] = certTLS(cfg.Domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpUpgradeTransport(cfg.Domain, cfg.Path)
	}
	return in
}

// ---------- Trojan ----------

// SingBoxTrojanInbound：Mode ""=reality；cf=WS+TLS（自签，沿用现有 CF 档）；
// h2/httpupgrade=证书 TLS 档。
func SingBoxTrojanInbound(tag string, port int, sni string, cfg TrojanConfig) map[string]interface{} {
	mode := cfg.Mode
	if mode == "" {
		mode = "reality"
	}
	in := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"password": cfg.Password}},
	}
	switch mode {
	case "reality":
		dest := cfg.Dest
		if dest == "" {
			dest = sni + ":443"
		}
		in["tls"] = realityTLS(sni, cfg.PrivateKey, cfg.ShortID, dest)
	case "cf":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = wsTransport(cfg.Path, domain)
	case "h2":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpTransport(domain, cfg.Path)
	case "httpupgrade":
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		in["tls"] = certTLS(domain, cfg.CertFile, cfg.KeyFile)
		in["transport"] = httpUpgradeTransport(domain, cfg.Path)
	}
	return in
}

// ---------- Shadowsocks / SOCKS / HTTP ----------

func SingBoxSSInbound(tag string, port int, cfg SSConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"method":      cfg.Method,
		"password":    cfg.Password,
	}
}

func sbUserPassInbound(typ, tag string, port int, listen, user, pass string) map[string]interface{} {
	in := map[string]interface{}{
		"type":        typ,
		"tag":         tag,
		"listen":      sbListen(listen, "::"),
		"listen_port": port,
	}
	if user != "" || pass != "" {
		in["users"] = []interface{}{map[string]interface{}{"username": user, "password": pass}}
	}
	return in
}

func SingBoxSocksInbound(tag string, port int, cfg SocksConfig) map[string]interface{} {
	return sbUserPassInbound("socks", tag, port, cfg.Listen, cfg.User, cfg.Pass)
}

func SingBoxHTTPInbound(tag string, port int, cfg HTTPConfig) map[string]interface{} {
	return sbUserPassInbound("http", tag, port, cfg.Listen, cfg.User, cfg.Pass)
}

// ---------- Hysteria2 / TUIC / AnyTLS / Naive ----------

// SingBoxHy2Inbound：sing-box 原生 hysteria2 入站，hysteria 二进制不再需要。
// server_name 取节点 SNI（自签证书 CN 与之对应）；up/down 为空即自动。
// ignore_client_bandwidth 字段名以 sing-box check 校验为准，不通过则删。
func SingBoxHy2Inbound(tag string, port int, sni, certPath, keyPath string, cfg Hy2Config) map[string]interface{} {
	in := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"password": cfg.Password}},
		"tls":         certTLS(sni, certPath, keyPath),
	}
	// alpn h3 是 Hy2 的固定要求，certTLS 不含 alpn，这里补上。
	in["tls"].(map[string]interface{})["alpn"] = []string{"h3"}
	if cfg.ObfsType != "" {
		in["obfs"] = map[string]interface{}{"type": cfg.ObfsType, "password": cfg.ObfsPassword}
	}
	if v, err := strconv.Atoi(cfg.UpMbps); err == nil && v > 0 {
		in["up_mbps"] = v
	}
	if v, err := strconv.Atoi(cfg.DownMbps); err == nil && v > 0 {
		in["down_mbps"] = v
	}
	if cfg.IgnoreClient {
		in["ignore_client_bandwidth"] = true
	}
	return in
}

// SingBoxTUICInbound：官方默认拥塞算法是 cubic，这里显式写 bbr；
// zero_rtt 官方强烈建议关闭（重放攻击），显式写 false。
// 入站没有 udp_relay_mode 字段（那是客户端出站字段），不要写。
func SingBoxTUICInbound(tag string, port int, sni, certPath, keyPath string, cfg TUICConfig) map[string]interface{} {
	in := map[string]interface{}{
		"type":               "tuic",
		"tag":                tag,
		"listen":             sbListen(cfg.Listen, "::"),
		"listen_port":        port,
		"users":              []interface{}{map[string]interface{}{"uuid": cfg.UUID, "password": cfg.Password}},
		"congestion_control": "bbr",
		"zero_rtt_handshake": false,
		"tls":                certTLS(sni, certPath, keyPath),
	}
	in["tls"].(map[string]interface{})["alpn"] = []string{"h3"}
	return in
}

// SingBoxAnyTLSInbound：padding_scheme 不写，用 sing-anytls 默认方案；
// tls 一律启用 + 自签证书（与 Hy2/TUIC 同款做法）。
func SingBoxAnyTLSInbound(tag string, port int, sni, certPath, keyPath string, cfg AnyTLSConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "anytls",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"users":       []interface{}{map[string]interface{}{"name": cfg.Name, "password": cfg.Password}},
		"tls":         certTLS(sni, certPath, keyPath),
	}
}

// SingBoxNaiveInbound：v1 只用 tcp（HTTP/2），不依赖 QUIC；
// tls 必须用真域名 + CA 证书，自签会破坏 Naive 的设计目的，生产不用。
func SingBoxNaiveInbound(tag string, port int, cfg NaiveConfig, certPath, keyPath string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "naive",
		"tag":         tag,
		"listen":      sbListen(cfg.Listen, "::"),
		"listen_port": port,
		"network":     "tcp",
		"users":       []interface{}{map[string]interface{}{"username": cfg.Username, "password": cfg.Password}},
		"tls":         certTLS(cfg.Domain, certPath, keyPath),
	}
}

// ---------- WireGuard 端点 ----------

// SingBoxWGEndpoint：sing-box 1.11+ 起 WireGuard 是 endpoints 段的端点，不是入站。
// address 是必填新增项：xray 入站不需要服务端隧道地址，sing-box 端点必须有，
// 取 10.0.0.1/32 与客户端 10.0.0.2/32 配对（每节点独立设备，地址可复用）。
// system=false 走 gVisor 用户态，不用内核模块。客户端交付文本不变。
func SingBoxWGEndpoint(tag string, port int, cfg WGConfig) map[string]interface{} {
	ep := map[string]interface{}{
		"type":        "wireguard",
		"tag":         tag,
		"system":      false,
		"mtu":         1420,
		"address":     []string{"10.0.0.1/32"},
		"private_key": cfg.ServerPriv,
		"listen_port": port,
		"peers": []interface{}{map[string]interface{}{
			"public_key":  cfg.ClientPub,
			"allowed_ips": []string{cfg.ClientIP},
		}},
	}
	// Listen 以前被直接丢弃：填了 127.0.0.1 也照样监听全部接口（P1-26）。
	// 只在用户显式填了时透传；不填时保持 sing-box 默认（双栈），不动
	// 已有节点的监听行为。
	if cfg.Listen != "" {
		ep["listen"] = cfg.Listen
	}
	return ep
}

// ---------- B 节点出站转换 ----------
//
// 存储的 B 节点 config 是 xray 格式出站（parseVLESS/parseVMess/parseTrojan/
// parseSS/parseSocksHTTP 的产物），hy2 存的已是 sing-box 格式。
// 转换失败一律返回 error，调用方不得静默丢弃（宁可整条链式报错，不可悄悄直连）。

func sbStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func sbMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func sbList(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

func sbInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// xrayTLSOutbound：xray streamSettings 安全层 → sing-box 出站 tls。
// reality 出站只有 public_key/short_id，没有 handshake（handshake 是入站才有的）。
func xrayTLSOutbound(ss map[string]interface{}) (map[string]interface{}, error) {
	sec := sbStr(ss, "security")
	switch sec {
	case "reality":
		rs := sbMap(ss, "realitySettings")
		tls := map[string]interface{}{
			"enabled": true,
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": sbStr(rs, "publicKey"),
			},
		}
		if sn := sbStr(rs, "serverName"); sn != "" {
			tls["server_name"] = sn
		}
		if sid := sbStr(rs, "shortId"); sid != "" {
			tls["reality"].(map[string]interface{})["short_id"] = sid
		}
		// sing-box reality 客户端强制要求 uTLS（xray 存的 fingerprint 默认 chrome）
		fp := sbStr(rs, "fingerprint")
		if fp == "" {
			fp = "chrome"
		}
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		return tls, nil
	case "tls":
		ts := sbMap(ss, "tlsSettings")
		tls := map[string]interface{}{"enabled": true}
		if sn := sbStr(ts, "serverName"); sn != "" {
			tls["server_name"] = sn
		}
		if b, ok := ts["allowInsecure"].(bool); ok && b {
			tls["insecure"] = true
		}
		if fp := sbStr(ts, "fingerprint"); fp != "" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		if alpn, ok := ts["alpn"].([]interface{}); ok && len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		return tls, nil
	case "none", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("不支持的安全层：%s", sec)
	}
}

// xrayTransportOutbound：xray streamSettings 传输 → sing-box 出站 transport。
// 存储的 B 节点只可能有 tcp/ws/grpc（解析器只接受这三种），其他一律报错。
func xrayTransportOutbound(ss map[string]interface{}) (map[string]interface{}, error) {
	netw := sbStr(ss, "network")
	switch netw {
	case "tcp":
		ts := sbMap(ss, "tcpSettings")
		header := sbMap(ts, "header")
		if sbStr(header, "type") == "http" {
			req := sbMap(header, "request")
			var host, path string
			// xray 格式：request.headers.Host []string，request.path []string
			if hm, ok := req["headers"].(map[string]interface{}); ok {
				if h, ok := hm["Host"].([]interface{}); ok && len(h) > 0 {
					host, _ = h[0].(string)
				}
			}
			if ps, ok := req["path"].([]interface{}); ok && len(ps) > 0 {
				path, _ = ps[0].(string)
			}
			return httpTransport(host, path), nil
		}
		return nil, nil
	case "ws":
		ws := sbMap(ss, "wsSettings")
		var host string
		if hm, ok := ws["headers"].(map[string]interface{}); ok {
			// Host 可能是字符串也可能是数组（xray 两种写法都认）：
			// 以前只断言字符串，数组形态直接得 ""，静默丢 Host。
			switch h := hm["Host"].(type) {
			case string:
				host = h
			case []interface{}:
				if len(h) > 0 {
					host, _ = h[0].(string)
				}
			case []string:
				if len(h) > 0 {
					host = h[0]
				}
			}
		}
		return wsTransport(sbStr(ws, "path"), host), nil
	case "grpc":
		gs := sbMap(ss, "grpcSettings")
		return map[string]interface{}{"type": "grpc", "service_name": sbStr(gs, "serviceName")}, nil
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("不支持的传输：%s", netw)
	}
}

// checkBServer：出站地址与端口校验（以前空地址/0 端口直接进配置，
// sing-box 校验失败时错误里没有 B 节点名，无法定位）。
func checkBServer(ob map[string]interface{}) error {
	if sbStr(ob, "server") == "" {
		return fmt.Errorf("B 节点出站地址为空")
	}
	if p := sbInt(ob["server_port"]); p < 1 || p > 65535 {
		return fmt.Errorf("B 节点出站端口 %d 非法", p)
	}
	return nil
}

// SingBoxBOutbound：存储的 B 节点 → sing-box 出站。tag 由调用方传 chain-<id>。
func SingBoxBOutbound(protocol, configJSON, tag string) (map[string]interface{}, error) {
	// 入站口径与出站口径归一：hy2/ss 存成入站名时也要能转，
	// 以前直接报“不支持的 B 节点协议”，整条链式 Apply 失败。
	switch protocol {
	case "hy2":
		protocol = "hysteria2"
	case "ss":
		protocol = "shadowsocks"
	}
	var stored map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &stored); err != nil {
		return nil, fmt.Errorf("B 节点配置解析失败：%w", err)
	}
	if protocol == "hysteria2" {
		// 已是 sing-box 格式，只换 tag；透传前同样校验必填字段。
		stored["tag"] = tag
		if err := checkBServer(stored); err != nil {
			return nil, err
		}
		return stored, nil
	}
	ss := sbMap(stored, "streamSettings")
	settings := sbMap(stored, "settings")
	switch protocol {
	case "vless", "vmess":
		vnext := sbList(settings, "vnext")
		if len(vnext) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少 vnext", protocol)
		}
		node, _ := vnext[0].(map[string]interface{})
		users := sbList(node, "users")
		if len(users) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少用户", protocol)
		}
		user, _ := users[0].(map[string]interface{})
		tls, err := xrayTLSOutbound(ss)
		if err != nil {
			return nil, err
		}
		tr, err := xrayTransportOutbound(ss)
		if err != nil {
			return nil, err
		}
		ob := map[string]interface{}{
			"type":        protocol,
			"tag":         tag,
			"server":      sbStr(node, "address"),
			"server_port": sbInt(node["port"]),
		}
		if protocol == "vless" {
			ob["uuid"] = sbStr(user, "id")
			// vision 只用于 TCP 裸流：带传输时 flow 必须丢掉
			if tr == nil {
				if f := sbStr(user, "flow"); f != "" {
					ob["flow"] = f
				}
			}
		} else {
			ob["uuid"] = sbStr(user, "id")
			// sing-box vmess 出站没有 alterId 字段（只支持 AEAD）；
			// 存量 B 节点若 alterId 非 0，直接报错，不静默降级。
			if aid := sbInt(user["alterId"]); aid != 0 {
				return nil, fmt.Errorf("vmess B 节点 alterId=%d 非 0，sing-box 只支持 AEAD（alterId=0）", aid)
			}
			if s := sbStr(user, "security"); s != "" {
				ob["security"] = s
			}
		}
		if tls != nil {
			ob["tls"] = tls
		}
		if tr != nil {
			ob["transport"] = tr
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return ob, nil
	case "trojan":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("trojan B 节点缺少服务器")
		}
		srv, _ := servers[0].(map[string]interface{})
		tls, err := xrayTLSOutbound(ss)
		if err != nil {
			return nil, err
		}
		tr, err := xrayTransportOutbound(ss)
		if err != nil {
			return nil, err
		}
		ob := map[string]interface{}{
			"type":        "trojan",
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
			"password":    sbStr(srv, "password"),
		}
		if tls != nil {
			ob["tls"] = tls
		}
		if tr != nil {
			ob["transport"] = tr
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return ob, nil
	case "shadowsocks":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("ss B 节点缺少服务器")
		}
		srv, _ := servers[0].(map[string]interface{})
		ob := map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
			"method":      sbStr(srv, "method"),
			"password":    sbStr(srv, "password"),
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return ob, nil
	case "socks", "http":
		servers := sbList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("%s B 节点缺少服务器", protocol)
		}
		srv, _ := servers[0].(map[string]interface{})
		ob := map[string]interface{}{
			"type":        protocol,
			"tag":         tag,
			"server":      sbStr(srv, "address"),
			"server_port": sbInt(srv["port"]),
		}
		if users := sbList(srv, "users"); len(users) > 0 {
			if u, ok := users[0].(map[string]interface{}); ok {
				ob["username"] = sbStr(u, "user")
				ob["password"] = sbStr(u, "pass")
			}
		}
		// https B 节点记下来的 TLS 原样带到出站（解析层已修：见 parseSocksHTTP）。
		if tls, ok := stored["tls"]; ok {
			ob["tls"] = tls
		}
		if err := checkBServer(ob); err != nil {
			return nil, err
		}
		return ob, nil
	default:
		return nil, fmt.Errorf("不支持的 B 节点协议：%s", protocol)
	}
}

// ---------- 链式路由 ----------

// ChainInput：一条链式（调用方已校验 A 是启用中的 vless 入站）。
type ChainInput struct {
	InboundTag  string // in-<A 节点 id>
	OutboundTag string // chain-<链式 id>
	List        string // 一行一个域名/IP/CIDR
}

// SingBoxChainRules：sniff 规则在前（非终结，嗅探出域名供后续规则匹配），
// 随后每条链式一条域名规则（绑各自入站，防偷渡）。末尾由 FullConfig 补 final direct。
func SingBoxChainRules(chains []ChainInput) []map[string]interface{} {
	if len(chains) == 0 {
		return nil
	}
	var aTags []interface{}
	for _, ch := range chains {
		aTags = append(aTags, ch.InboundTag)
	}
	rules := []map[string]interface{}{
		{"inbound": aTags, "action": "sniff"},
	}
	for _, ch := range chains {
		suffixes, cidrs := splitDomainList(ch.List)
		// 域名与 IP 必须拆成两条规则：sing-box 一条规则内多条件是 AND，
		// 合写会导致两类流量都永不命中；两类都为空时不生成规则——绝不
		// 生成无匹配条件的 catch-all，否则 A 的全部流量都会被送往 B。
		if len(suffixes) > 0 {
			rules = append(rules, map[string]interface{}{
				"inbound":      []string{ch.InboundTag},
				"action":       "route",
				"outbound":     ch.OutboundTag,
				"domain_suffix": suffixes,
			})
		}
		if len(cidrs) > 0 {
			rules = append(rules, map[string]interface{}{
				"inbound":  []string{ch.InboundTag},
				"action":   "route",
				"outbound": ch.OutboundTag,
				"ip_cidr":  cidrs,
			})
		}
	}
	return rules
}

// ParseChainList 解析链式清单：按行切分，去空行/# 注释、去 scheme、
// 路径、端口、前导 *. 与前导点，校验每行是合法域名或 IP/CIDR，返回
// 归一化后的两类清单。非法行按行号报错；解析后两类都为空时报错——
// 绝不生成无匹配条件的 catch-all 规则（否则 A 的全部流量都会走 B）。
// 上限 5000 行、256KB，超了直接拒绝，不让超大文本进配置。
func ParseChainList(listText string) (suffixes, cidrs []string, err error) {
	if len(listText) > 256*1024 {
		return nil, nil, fmt.Errorf("链式清单超过 256KB 上限")
	}
	lines := strings.Split(listText, "\n")
	if len(lines) > 5000 {
		return nil, nil, fmt.Errorf("链式清单超过 5000 行上限")
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "://"); idx >= 0 {
			line = line[idx+3:]
		}
		// CIDR/IP 先认：路径剥离在 "/" 处切，会把 1.2.3.0/24 的掩码切掉。
		if isIPOrCIDR(line) {
			cidrs = append(cidrs, line)
			continue
		}
		if idx := strings.IndexAny(line, "/?"); idx >= 0 {
			line = line[:idx]
		}
		if strings.HasPrefix(line, "[") {
			if idx := strings.Index(line, "]"); idx >= 0 {
				rest := line[idx+1:]
				if rest != "" && !strings.HasPrefix(rest, ":") {
					return nil, nil, fmt.Errorf("第 %d 行 %q 格式不对", i+1, raw)
				}
				line = line[1:idx]
			}
		} else if h, _, splitErr := net.SplitHostPort(line); splitErr == nil {
			line = h
		}
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimPrefix(line, ".")
		if line == "" {
			return nil, nil, fmt.Errorf("第 %d 行 %q 清理后为空", i+1, raw)
		}
		if isIPOrCIDR(line) {
			cidrs = append(cidrs, line)
			continue
		}
		if !validChainDomain(line) {
			return nil, nil, fmt.Errorf("第 %d 行 %q 不是合法域名", i+1, raw)
		}
		suffixes = append(suffixes, line)
	}
	if len(suffixes) == 0 && len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("链式清单解析后为空（只有空行或注释），不会生成分流规则")
	}
	return suffixes, cidrs, nil
}

func validChainDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// splitDomainList：生成器用的宽容版解析——非法清单直接产出空规则集
// （不生成 catch-all），严格校验在创建/编辑接口做。
func splitDomainList(listText string) (suffixes, cidrs []string) {
	suffixes, cidrs, _ = ParseChainList(listText)
	return suffixes, cidrs
}

// ---------- 全量配置 ----------

// SingBoxFullConfig：组装 singbox.json。inbounds 为全部入站，endpoints 为
// WireGuard 端点（为空时不写该键），outbounds 为链式出站（函数自动在首位补 direct）。
func SingBoxFullConfig(inbounds []interface{}, endpoints []interface{}, outbounds []interface{}, rules []map[string]interface{}) map[string]interface{} {
	outs := []interface{}{map[string]interface{}{"type": "direct", "tag": "direct"}}
	outs = append(outs, outbounds...)
	ruleList := []interface{}{}
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	// nil 切片进 JSON 是 null 不是 []：只有 WG 端点、没有 sing-box
	// 入站时 inbounds 就是 nil，sing-box 校验会把 null 当类型错
	// 拒绝（空数组才表示“没有入站”）。
	if inbounds == nil {
		inbounds = []interface{}{}
	}
	cfg := map[string]interface{}{
		"log":       map[string]interface{}{"level": "warn"},
		"inbounds":  inbounds,
		"outbounds": outs,
		"route": map[string]interface{}{
			"rules": ruleList,
			"final": "direct",
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return cfg
}

// ---------- 新协议客户端链接 ----------

// TUICLink：tuic v5 分享格式（v2rayNG/Streisand 通用）。
// 自签证书所以 allow_insecure=1；拥塞算法与服务端一致写 bbr。
func TUICLink(address string, port int, sni string, cfg TUICConfig, name string) string {
	v := url.Values{}
	v.Set("congestion_control", "bbr")
	v.Set("udp_relay_mode", "native")
	v.Set("alpn", "h3")
	if sni != "" {
		v.Set("sni", sni)
	}
	v.Set("allow_insecure", "1")
	u := &url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(cfg.UUID, cfg.Password),
		Host:     hostPort(address, port),
		RawQuery: v.Encode(),
		Fragment: name,
	}
	return u.String()
}

// AnyTLSLink：anytls 分享格式。服务端 users 有 name，但客户端出站只认
// password，所以链接里只放密码（与 sing-box anytls 出站字段一致）。
func AnyTLSLink(address string, port int, sni string, cfg AnyTLSConfig, name string) string {
	v := url.Values{}
	if sni != "" {
		v.Set("sni", sni)
	}
	v.Set("insecure", "1") // 自签证书
	u := &url.URL{
		Scheme:   "anytls",
		User:     url.UserPassword("", cfg.Password),
		Host:     hostPort(address, port),
		RawQuery: v.Encode(),
		Fragment: name,
	}
	s := u.String()
	return strings.Replace(s, "anytls://:", "anytls://", 1)
}

// NaiveLink：Naive 没有通用 URL 分享格式，交付参考客户端的 JSON 配置
// （与 WireGuard 节点交付整份配置文本同款做法，不是 URL，别贴进 URL 导入框）。
func NaiveLink(cfg NaiveConfig, port int) string {
	// 用户名/密码必须 URL 转义：密码里带 @ : / ? 时，裸拼的
	// 链接会被客户端解析错 host、甚至截断密码。
	proxyURL := &url.URL{
		Scheme: "https",
		User:   url.UserPassword(cfg.Username, cfg.Password),
		Host:   hostPort(cfg.Domain, port),
	}
	doc := map[string]interface{}{
		"listen": "socks://127.0.0.1:1080",
		"proxy":  proxyURL.String(),
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
