package proxy

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------- VMess ----------
//
// 2026 年的合理默认值：alterId=0（走 AEAD，不再用老 alterId 混淆），
// security=auto（xray 在 alterId=0 时用 aes-128-gcm）。
// 两种模式：
//   - tcp：直连，不套 TLS，简单；
//   - cf：WS + Cloudflare。访客连 CF:源站端口，CF 按同端口转发
//     到源站（所以链接端口必须等于源站端口，不能写死 443）；
//     域名必须已经接入 CF（橙色云朵）并解析到服务器 IP。
//     源站是 WS+TLS 自签证书：区是 Full 时 CF 到源站走 HTTPS，
//     明文 WS 会 525，自签 Full 接受、Strict 不接受；
//     源站端口必须是 CF 允许的代理端口
//     （443/2053/2083/2087/2096/8443），否则 CF 根本不转发。

type VMessConfig struct {
	UUID     string `json:"uuid"`
	Mode     string `json:"mode"`   // "tcp" | "cf" | "http" | "quic" | "h2" | "httpupgrade"
	Domain   string `json:"domain"` // TLS 档的域名（同时存在 Inbound.SNI 里）
	Path     string `json:"path"`   // TLS 档的路径
	Listen   string `json:"listen"`
	CertFile string `json:"cert_file"` // TLS 档证书（Apply 层生成）
	KeyFile  string `json:"key_file"`
}

// EnsureWSCert：给一个 WS+CF 模式节点准备源站证书。
// 证书已存在且域名对得上、没过期就复用；域名换了或过期就重生成。
// 自签即可：example.com 这类 Full 模式的区，CF 接受任何证书（含自签）；
// Strict 模式不接受自签，那种区面板目前不支持，会在文档里写明。
func EnsureWSCert(dir, prefix, id, domain string) (string, string, error) {
	certFile := filepath.Join(dir, prefix+"-"+id+".crt")
	keyFile := filepath.Join(dir, prefix+"-"+id+".key")
	if b, err := os.ReadFile(certFile); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				ok := cert.Subject.CommonName == domain || len(cert.DNSNames) == 0
				for _, n := range cert.DNSNames {
					if n == domain {
						ok = true
					}
				}
				// 续期窗口 7 天：快到期的证书也别复用，否则
				// 节点会在几天后悄悄握手失败；直接重签一张新的。
				if ok && cert.NotAfter.After(time.Now().Add(7*24*time.Hour)) {
					// 证书与私钥必须配对才复用：只 Stat 不验配对时，换掉
					// 一边的错配对会让之后每次 Apply 都卡在 sing-box 校验。
					if _, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
						return certFile, keyFile, nil
					}
				}
			}
		}
	}
	if err := GenSelfSignedCert(certFile, keyFile, domain); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// EnsureVMessCFCert 保留给 VMess CF 节点（老文件名 vmesscf-* 不动）。
func EnsureVMessCFCert(dir, id, domain string) (string, string, error) {
	return EnsureWSCert(dir, "vmesscf", id, domain)
}

func DefaultVMess() VMessConfig {
	return VMessConfig{UUID: newUUID(), Mode: "tcp"}
}

// CFPorts：Cloudflare 代理流量允许的端口（源站端口只能从这里挑）。
var CFPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

func IsCFPort(p int) bool {
	for _, c := range CFPorts {
		if c == p {
			return true
		}
	}
	return false
}

func VMessLink(address string, port int, cfg VMessConfig, name string, sni string) string {
	m := map[string]interface{}{
		"v":   "2",
		"ps":  name,
		"id":  cfg.UUID,
		"aid": "0",
		"scy": "auto",
		"net": "tcp",
		"tls": "none",
	}
	// 服务端生成证书时 Domain 为空会用 SNI 补齐（tlsModeDomain），
	// 链接侧以前直接用 cfg.Domain，Domain 空时下发 add="" 的死链（P1-24）。
	domain := cfg.Domain
	if domain == "" {
		domain = sni
	}
	switch cfg.Mode {
	case "cf":
		// 链接端口必须等于源站端口：CF 按同端口转发（访客连 CF:2087，
		// CF 就连源站:2087），写 443 但源站是 2087 时，CF 会去连
		// 源站:443，根本到不了 WS 节点。
		m["add"] = domain
		m["port"] = port
		m["net"] = "ws"
		m["type"] = "none"
		m["host"] = domain
		m["path"] = cfg.Path
		m["tls"] = "tls"
		m["sni"] = domain
	case "http":
		// 明文 HTTP 传输：host 是 HTTP Host 头，服务端配了域名约束就用域名，
		// 没配就用地址；不走 TLS。
		host := cfg.Domain
		if host == "" {
			host = address
		}
		m["add"] = address
		m["port"] = port
		m["net"] = "http"
		m["type"] = "none"
		m["host"] = host
		m["path"] = cfg.Path
	case "quic", "h2", "httpupgrade":
		// 直连 TLS 档：自签证书，客户端要 allowInsecure（v2rayNG 认这个扩展字段，
		// 不认的客户端需手动开一次不验证证书）。
		// 域名与 SNI 都空时（默认留空）回退到服务器地址，否则下发 add="" 的死链。
		if domain == "" {
			domain = address
		}
		m["add"] = domain
		m["port"] = port
		m["net"] = cfg.Mode
		m["type"] = "none"
		m["host"] = domain
		m["path"] = cfg.Path
		m["tls"] = "tls"
		m["sni"] = domain
		m["allowInsecure"] = "1"
	default:
		m["add"] = address
		m["port"] = port
		m["type"] = "none"
	}
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// ---------- Shadowsocks ----------
//
// 方法默认 2022-blake3-aes-128-gcm：2022 系列是目前最新的
// SS 协议（密钥派生更强、抗重放），xray 新版全支持；
// 2022 方法的密码必须是对应长度的 base64 密钥（128 位=16 字节，
// 256 位=32 字节），面板创建时自动按方法生成，绝不让用户
// 随便填一个短密码导致 xray 起不来。

type SSConfig struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Listen   string `json:"listen"`
}

func DefaultSS() SSConfig {
	return SSConfig{Method: "2022-blake3-aes-128-gcm", Password: SSKey("2022-blake3-aes-128-gcm")}
}

func SSKey(method string) string {
	switch method {
	case "2022-blake3-aes-256-gcm":
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	case "2022-blake3-aes-128-gcm":
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	default:
		// 老方法：任意密码即可，生成 20 位随机口令。
		return randHex(10)
	}
}

func SSLink(address string, port int, cfg SSConfig, name string) string {
	raw := cfg.Method + ":" + cfg.Password + "@" + hostPort(address, port)
	return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(raw)) + "#" + url.QueryEscape(name)
}

// ---------- SOCKS5 ----------

type SocksConfig struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Listen string `json:"listen"`
}

func DefaultSocks() SocksConfig {
	return SocksConfig{User: "user-" + randHex(3), Pass: randHex(8)}
}

func SocksLink(address string, port int, cfg SocksConfig, name string) string {
	u := &url.URL{
		Scheme:   "socks",
		User:     url.UserPassword(cfg.User, cfg.Pass),
		Host:     hostPort(address, port),
		Fragment: name,
	}
	return u.String()
}

// ---------- HTTP proxy ----------

type HTTPConfig struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Listen string `json:"listen"`
}

func DefaultHTTP() HTTPConfig {
	return HTTPConfig{User: "user-" + randHex(3), Pass: randHex(8)}
}

func HTTPLink(address string, port int, cfg HTTPConfig, name string) string {
	u := &url.URL{
		Scheme:   "http",
		User:     url.UserPassword(cfg.User, cfg.Pass),
		Host:     hostPort(address, port),
		Fragment: name,
	}
	return u.String()
}

// ---------- Trojan ----------

// TrojanConfig：Reality 直连是默认档（和 VLESS 同一套抗封禁组合，
// 只是协议换成 Trojan，没有 flow）；cf 档是 WS + Cloudflare，
// 源站 WS+TLS 自签证书，和 VMess CF 同机制。
type TrojanConfig struct {
	Password   string `json:"password"`
	Mode       string `json:"mode"`        // "reality" | "cf" | "h2" | "httpupgrade"
	Domain     string `json:"domain"`      // TLS 档的域名（同时存在 Inbound.SNI 里）
	Path       string `json:"path"`        // TLS 档的路径
	PrivateKey string `json:"private_key"` // reality 档
	PublicKey  string `json:"public_key"`  // reality 档
	ShortID    string `json:"short_id"`
	Dest       string `json:"dest"` // reality 档，SNI:443
	Listen     string `json:"listen"`
	CertFile   string `json:"cert_file"` // TLS 档证书（Apply 层生成）
	KeyFile    string `json:"key_file"`
}

func DefaultTrojan() TrojanConfig {
	return TrojanConfig{Password: randHex(8), Mode: "reality", ShortID: randHex(4)}
}

func TrojanLink(address string, port int, sni string, cfg TrojanConfig, name string) string {
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.UserPassword("", cfg.Password),
		Host:     hostPort(address, port),
		Fragment: name,
	}
	// trojan 链接的密码习惯放用户名位（trojan://password@host），
	// url.UserPassword("", pw) 会写成 :password@，所以手动拼。
	q := url.Values{}
	if cfg.Mode == "cf" {
		// CF 档与 VMess 同款回退：Domain 空时用 SNI，否则 sni= 空的死链（P1-24）。
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		u.Host = hostPort(domain, port)
		q.Set("security", "tls")
		q.Set("sni", domain)
		q.Set("type", "ws")
		q.Set("path", cfg.Path)
		q.Set("host", domain)
	} else if cfg.Mode == "h2" || cfg.Mode == "httpupgrade" {
		// 直连 TLS 档：自签证书，客户端要 allowInsecure。
		// 域名与 SNI 都空时（默认留空）回退到服务器地址，否则下发死链。
		domain := cfg.Domain
		if domain == "" {
			domain = sni
		}
		if domain == "" {
			domain = address
		}
		u.Host = hostPort(domain, port)
		q.Set("security", "tls")
		q.Set("sni", domain)
		q.Set("type", cfg.Mode)
		q.Set("path", cfg.Path)
		q.Set("host", domain)
		q.Set("allowInsecure", "1")
	} else {
		q.Set("security", "reality")
		q.Set("sni", sni)
		q.Set("pbk", cfg.PublicKey)
		q.Set("sid", cfg.ShortID)
		q.Set("fp", "chrome")
		q.Set("type", "tcp")
	}
	u.RawQuery = q.Encode()
	s := u.String()
	// 把 ":password@" 换成 "password@"（trojan 的惯用写法）
	s = strings.Replace(s, "trojan://:", "trojan://", 1)
	return s
}

// ---------- WireGuard ----------

// WGConfig：面板给每个节点生成两对密钥——服务端一对、客户端一对，
// 客户端公钥直接写进服务端 peer，建好就能用，不用用户再跑 wg genkey。
// 密钥用标准库 crypto/ecdh 的 X25519，和 wg 的 32 字节 base64 格式互通。
type WGConfig struct {
	ServerPriv string `json:"server_priv"`
	ServerPub  string `json:"server_pub"`
	ClientPriv string `json:"client_priv"`
	ClientPub  string `json:"client_pub"`
	ClientIP   string `json:"client_ip"` // 如 10.0.0.2/32（每节点独立设备，可复用）
	Listen     string `json:"listen"`
}

func wgKeypair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func DefaultWG() WGConfig {
	sp, spub, err1 := wgKeypair()
	cp, cpub, err2 := wgKeypair()
	if err1 != nil || err2 != nil {
		return WGConfig{ClientIP: "10.0.0.2/32"}
	}
	return WGConfig{ServerPriv: sp, ServerPub: spub, ClientPriv: cp, ClientPub: cpub, ClientIP: "10.0.0.2/32"}
}

// WGClientConfig：WireGuard 没有标准 URL 链接，交付物就是这份配置文本，
// 贴进官方客户端（或扫它的二维码）就能用。
func WGClientConfig(address string, port int, cfg WGConfig, name string) string {
	return fmt.Sprintf(`[Interface]
# %s
PrivateKey = %s
Address = %s
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, name, cfg.ClientPriv, cfg.ClientIP, cfg.ServerPub, hostPort(address, port))
}

// ---------- Dokodemo-door ----------

// ---------- B-node address (for latency probe) ----------

// BNodeHostPort 从一条 B 节点链接里抠出要测活的主机和端口，
// 供 TCP 探活（本机 → B 节点服务器）用。vmess 链接是 base64 JSON，
// 单独解；其余都是标准 URL，直接取 Host。
func BNodeHostPort(link string) (string, int, error) {
	link = strings.TrimSpace(link)
	// SS 整段 base64 形：ss://base64(method:pass@host:port)#name，
	// 主机藏在 base64 里，通用 URL 解析拿到的 host 是整段密文、
	// 端口为空，会误判为“解析失败”而放行（订阅过滤因此漏掉回环
	// SS B 节点）。先解开再取 host:port；解不开才走通用路径。
	if strings.HasPrefix(link, "ss://") {
		rest := strings.TrimPrefix(link, "ss://")
		rest = strings.SplitN(rest, "#", 2)[0]
		rest = strings.SplitN(rest, "?", 2)[0]
		if !strings.Contains(rest, "@") {
			raw, err := base64.RawURLEncoding.DecodeString(rest)
			if err != nil {
				raw, err = base64.URLEncoding.DecodeString(rest)
			}
			if err == nil {
				if at := strings.LastIndex(string(raw), "@"); at >= 0 {
					if h, p, err := net.SplitHostPort(string(raw)[at+1:]); err == nil {
						if port, _ := strconv.Atoi(p); h != "" && port != 0 {
							return h, port, nil
						}
					}
				}
			}
		}
	}
	if strings.HasPrefix(link, "vmess://") {
		raw := strings.TrimPrefix(link, "vmess://")
		raw = strings.SplitN(raw, "#", 2)[0]
		raw = strings.SplitN(raw, "?", 2)[0]
		b, err := base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			b, err = base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return "", 0, err
			}
		}
		var m struct {
			Add  string      `json:"add"`
			Port interface{} `json:"port"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return "", 0, err
		}
		port := 0
		switch v := m.Port.(type) {
		case float64:
			port = int(v)
		case string:
			fmt.Sscanf(v, "%d", &port)
		}
		if m.Add == "" || port == 0 {
			return "", 0, fmt.Errorf("vmess 链接缺少地址或端口")
		}
		return m.Add, port, nil
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", 0, err
	}
	host := u.Hostname()
	port := 0
	fmt.Sscanf(u.Port(), "%d", &port)
	if host == "" || port == 0 {
		return "", 0, fmt.Errorf("链接缺少地址或端口")
	}
	return host, port, nil
}
