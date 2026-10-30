package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------- Hysteria2 ----------

type Hy2Config struct {
	Password     string `json:"password"`
	ObfsType     string `json:"obfs_type"` // "" or "salamander"
	ObfsPassword string `json:"obfs_password"`
	UpMbps       string `json:"up_mbps"`       // "" = auto
	DownMbps     string `json:"down_mbps"`     // "" = auto
	IgnoreClient bool   `json:"ignore_client"` // ignore client bandwidth
	Listen       string `json:"listen"`        // "" = all interfaces
	StatsPort    int    `json:"stats_port"`    // loopback trafficStats port (internal)
	StatsSecret  string `json:"stats_secret"`  // trafficStats secret (internal)
}

func DefaultHy2() Hy2Config {
	return Hy2Config{Password: randHex(8)}
}

// Hy2ServerYAML renders hysteria2 server config.
func Hy2ServerYAML(port int, certPath, keyPath string, cfg Hy2Config) string {
	var b strings.Builder
	listen := cfg.Listen
	if listen == "" {
		fmt.Fprintf(&b, "listen: :%d\n\n", port)
	} else {
		fmt.Fprintf(&b, "listen: %s:%d\n\n", listen, port)
	}
	b.WriteString("auth:\n  type: password\n  password: " + cfg.Password + "\n\n")
	b.WriteString("tls:\n  cert: " + certPath + "\n  key: " + keyPath + "\n\n")
	if cfg.ObfsType != "" {
		b.WriteString("obfs:\n  type: " + cfg.ObfsType + "\n")
		if cfg.ObfsPassword != "" {
			b.WriteString("  salamander:\n    password: " + cfg.ObfsPassword + "\n")
		}
		b.WriteString("\n")
	}
	if cfg.UpMbps != "" || cfg.DownMbps != "" {
		b.WriteString("bandwidth:\n")
		if cfg.UpMbps != "" {
			b.WriteString("  up: " + cfg.UpMbps + " mbps\n")
		}
		if cfg.DownMbps != "" {
			b.WriteString("  down: " + cfg.DownMbps + " mbps\n")
		}
		b.WriteString("\n")
	}
	if cfg.IgnoreClient {
		b.WriteString("ignoreClientBandwidth: true\n")
	}
	if cfg.StatsPort > 0 && cfg.StatsSecret != "" {
		fmt.Fprintf(&b, "\ntrafficStats:\n  listen: 127.0.0.1:%d\n  secret: %s\n", cfg.StatsPort, cfg.StatsSecret)
	}
	return b.String()
}

func Hy2Link(address string, port int, sni string, cfg Hy2Config, name string) string {
	v := "sni=" + qesc(sni) + "&insecure=1"
	if cfg.ObfsType != "" {
		v += "&obfs=" + qesc(cfg.ObfsType)
		if cfg.ObfsPassword != "" {
			v += "&obfs-password=" + qesc(cfg.ObfsPassword)
		}
	}
	return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", qesc(cfg.Password), hostPort(address, port), v, qesc(name))
}

// GenSelfSignedCert creates a self-signed cert/key pair (for hy2).
func GenSelfSignedCert(certPath, keyPath, commonName string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	// CN 是 IP 时必须放 IP SAN：现代 TLS 校验只看 SAN、不看 CN，
	// DNSNames 里写个 IP 字符串等于没写，按 IP 验就握手失败。
	if ip := net.ParseIP(commonName); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyOut.Close()
	// verify pair loads
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	return err
}

// ---------- MTProto (mtg) ----------

// MTGConfig is one mtg inbound's config (config-file mode).
type MTGConfig struct {
	Secret    string `json:"secret"`
	Listen    string `json:"listen"`     // bind host, default 0.0.0.0
	StatsPort int    `json:"stats_port"` // loopback prometheus port (internal)
}

// MTGSecret builds an mtg fake-TLS ee-secret: "ee" + 32 hex key + hex(domain).
func MTGSecret(domain string) string {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	return "ee" + hex.EncodeToString(key) + hex.EncodeToString([]byte(domain))
}

// MTGDomain extracts the fake-TLS domain from an ee-secret.
func MTGDomain(secret string) string {
	if !strings.HasPrefix(secret, "ee") || len(secret) <= 34 {
		return ""
	}
	raw, err := hex.DecodeString(secret[34:])
	if err != nil {
		return ""
	}
	return string(raw)
}

func MTGLink(address string, port int, secret, name string) (tgLink, tmeLink string) {
	tgLink = fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", address, port, secret)
	tmeLink = fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s", address, port, secret)
	return tgLink, tmeLink
}

// MTGToml renders an mtg config file (v2 config-file mode: `mtg run file`).
// prefer-ipv4 matches the proven RN deployment; stats section follows the
// official example.config.toml ([stats.prometheus]).
func MTGToml(secret, bindAddr string, statsPort int) string {
	var b strings.Builder
	// TOML 基本字符串：secret 是 ee 十六进制、bindAddr 含用户填的
	// Listen，万一带引号/换行会直接把 toml 写坏、mtg 起不来。
	// strconv.Quote 的转义与 TOML 基本字符串兼容。
	b.WriteString("secret = " + strconv.Quote(secret) + "\n")
	b.WriteString("bind-to = " + strconv.Quote(bindAddr) + "\n")
	b.WriteString("prefer-ip = \"prefer-ipv4\"\n")
	b.WriteString("concurrency = 8192\n")
	if statsPort > 0 {
		fmt.Fprintf(&b, "\n[stats.prometheus]\nenabled = true\nbind-to = \"127.0.0.1:%d\"\nhttp-path = \"/\"\nmetric-prefix = \"mtg\"\n", statsPort)
	}
	return b.String()
}
