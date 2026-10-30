package proxy

import (
	"math/rand"
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
	{Domain: "www.speedtest.net", Label: "Speedtest 测速"},
	{Domain: "www.python.org", Label: "Python 官网"},
	{Domain: "www.stackoverflow.com", Label: "Stack Overflow"},
}

// RecommendSNI picks a random candidate different from exclude.
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
