package proxy

import (
	"net"
	"testing"
)

func TestIsCloudflareIP(t *testing.T) {
	// 104.17.0.0/13 是 Cloudflare 段：speedtest.net 当时就解析到这段。
	if !IsCloudflareIP(net.ParseIP("104.17.147.22")) {
		t.Fatal("104.17.147.22 应判定为 Cloudflare")
	}
	if !IsCloudflareIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatal("2606:4700::/32 应判定为 Cloudflare")
	}
	for _, ip := range []string{"1.1.1.1", "104.68.241.34", "151.101.1.19", "23.216.149.143"} {
		if IsCloudflareIP(net.ParseIP(ip)) {
			t.Fatalf("%s 不应判定为 Cloudflare", ip)
		}
	}
}

func TestIsRealityMode(t *testing.T) {
	if !IsRealityMode("vless", "") || !IsRealityMode("vless", "reality") {
		t.Fatal("VLESS 默认/现实档是 Reality")
	}
	if IsRealityMode("vless", "ws") || IsRealityMode("vless", "h2") || IsRealityMode("vless", "httpupgrade") {
		t.Fatal("VLESS TLS 档不是 Reality")
	}
	if !IsRealityMode("trojan", "reality") {
		t.Fatal("Trojan 现实档是 Reality")
	}
	if IsRealityMode("trojan", "cf") || IsRealityMode("trojan", "h2") {
		t.Fatal("Trojan CF/TLS 档不是 Reality")
	}
	if IsRealityMode("hy2", "reality") || IsRealityMode("vmess", "") {
		t.Fatal("HY2/VMess 的 SNI 不是 Reality 伪装目标，不受禁 CF 规则约束")
	}
}

func TestSNIListNoCloudflare(t *testing.T) {
	// 池子已用公开 DoH 逐个验过解析结果：2026-11-02 实测仅 speedtest.net
	// 落在 Cloudflare 段（104.17.x），已从池子里删掉；这里锁死不再加回来。
	for _, c := range SNIList {
		if c.Domain == "www.speedtest.net" {
			t.Fatal("池子里不应再有 speedtest.net（Cloudflare）")
		}
	}
	if len(SNIList) != 15 {
		t.Fatalf("池子应为 15 个，得到 %d", len(SNIList))
	}
}
