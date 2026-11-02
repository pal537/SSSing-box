package proxy

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

// SNICandidate is one recommended Reality camouflage domain.
type SNICandidate struct {
	Domain string `json:"domain"`
	Label  string `json:"label"` // what site it is, for the UI hint
}

// Built-in recommended SNI list: real sites, TLS1.3, and NOT the overused
// proxy SNIs (no microsoft/oracle/amazon/google/apple/bing/cloudflare).
// China-reachability is judged from public knowledge and must be confirmed
// by real use; the panel verifies TLS handshake reachability from the server.
// Source: research.md §6 (16 candidates, www. form only).
var SNIList = []SNICandidate{
	{Domain: "www.samsung.com", Label: "三星官网"},
	{Domain: "www.intel.com", Label: "Intel 官网"},
	{Domain: "www.nvidia.com", Label: "英伟达官网"},
	{Domain: "www.adobe.com", Label: "Adobe 官网"},
	{Domain: "www.lenovo.com", Label: "联想官网"},
	{Domain: "www.asus.com", Label: "华硕官网"},
	{Domain: "www.cisco.com", Label: "思科官网"},
	{Domain: "www.dell.com", Label: "戴尔官网"},
	{Domain: "www.hp.com", Label: "惠普官网"},
	{Domain: "www.sony.com", Label: "索尼官网"},
	{Domain: "www.tesla.com", Label: "特斯拉官网"},
	{Domain: "www.ubuntu.com", Label: "Ubuntu 官网"},
	{Domain: "www.mozilla.org", Label: "Mozilla 官网"},
	{Domain: "www.python.org", Label: "Python 官网"},
	{Domain: "www.stackoverflow.com", Label: "Stack Overflow"},
}

// Cloudflare published IP ranges (cloudflare.com/ips). A Reality masquerade
// target must never sit behind Cloudflare: CF-fronted handshakes get scanned
// and abused, and the panel refuses them outright (pool entries are audited
// against this list too — speedtest.net was dropped for exactly this reason).
var cfCIDRs = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
	"104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var cfNets []*net.IPNet

func init() {
	for _, c := range cfCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			cfNets = append(cfNets, n)
		}
	}
}

// IsCloudflareIP reports whether ip belongs to Cloudflare's published ranges.
func IsCloudflareIP(ip net.IP) bool {
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SNIBehindCloudflare resolves sni (hostname or IP literal) and reports
// whether it sits behind Cloudflare. Resolution failure is an error, not a
// pass: a Reality target that cannot be verified must not be created blind.
func SNIBehindCloudflare(sni string) (bool, error) {
	sni = strings.TrimSuffix(sni, ".")
	if ip := net.ParseIP(sni); ip != nil {
		return IsCloudflareIP(ip), nil
	}
	ips, err := net.LookupIP(sni)
	if err != nil || len(ips) == 0 {
		return false, err
	}
	for _, ip := range ips {
		if IsCloudflareIP(ip) {
			return true, nil
		}
	}
	return false, nil
}

// IsRealityMode reports whether this protocol+mode uses the SNI as a Reality
// masquerade target (as opposed to a real TLS cert domain or a self-signed
// cert name). Only Reality targets are subject to the no-Cloudflare rule.
func IsRealityMode(protocol, mode string) bool {
	switch protocol {
	case "vless":
		return mode == "" || mode == "reality"
	case "trojan":
		return mode == "" || mode == "reality"
	}
	return false
}
func RecommendSNI(exclude string) SNICandidate {
	rand.Seed(time.Now().UnixNano())
	pool := make([]SNICandidate, 0, len(SNIList))
	for _, c := range SNIList {
		if c.Domain != exclude {
			pool = append(pool, c)
		}
	}
	if len(pool) == 0 {
		return SNIList[0]
	}
	return pool[rand.Intn(len(pool))]
}
