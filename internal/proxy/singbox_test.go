package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSingBoxFullConfig 生成一份覆盖全部协议/档位/链式的 singbox.json，
// 供 `sing-box check` 做结构校验（见 /tmp/sssingbox-singbox-check/ 输出）。
// 注意：测试用自签证书只为让 check 能读到证书文件；Naive 生产必须用 CA 证书，
// 那是面板策略，不是 check 的约束。
func TestSingBoxFullConfig(t *testing.T) {
	dir := "/tmp/sssingbox-singbox-check"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := GenSelfSignedCert(certPath, keyPath, "test.example.com"); err != nil {
		t.Fatal(err)
	}

	uuid := "11111111-2222-3333-4444-555555555555"
	priv := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 字节零值，格式合法
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	var inbounds []interface{}
	inbounds = append(inbounds,
		SingBoxVLESSInbound("in-vless", 443, "www.oracle.com", VLESSConfig{UUID: uuid, Flow: "xtls-rprx-vision", ShortID: "abcd1234", PrivateKey: priv, PublicKey: pub}),
		SingBoxVLESSInbound("in-vless-ws", 8443, "test.example.com", VLESSConfig{UUID: uuid, Mode: "ws", Domain: "test.example.com", Path: "/ws", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVLESSInbound("in-vless-h2", 8444, "test.example.com", VLESSConfig{UUID: uuid, Mode: "h2", Domain: "test.example.com", Path: "/h2", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVLESSInbound("in-vless-hu", 8445, "test.example.com", VLESSConfig{UUID: uuid, Mode: "httpupgrade", Domain: "test.example.com", Path: "/hu", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVMessInbound("in-vmess-tcp", 10001, VMessConfig{UUID: uuid, Mode: "tcp"}),
		SingBoxVMessInbound("in-vmess-cf", 10002, VMessConfig{UUID: uuid, Mode: "cf", Domain: "test.example.com", Path: "/vmess", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVMessInbound("in-vmess-http", 10003, VMessConfig{UUID: uuid, Mode: "http", Domain: "test.example.com", Path: "/http"}),
		SingBoxVMessInbound("in-vmess-quic", 10004, VMessConfig{UUID: uuid, Mode: "quic", Domain: "test.example.com", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVMessInbound("in-vmess-h2", 10005, VMessConfig{UUID: uuid, Mode: "h2", Domain: "test.example.com", Path: "/h2", CertFile: certPath, KeyFile: keyPath}),
		SingBoxVMessInbound("in-vmess-hu", 10006, VMessConfig{UUID: uuid, Mode: "httpupgrade", Domain: "test.example.com", Path: "/hu", CertFile: certPath, KeyFile: keyPath}),
		SingBoxTrojanInbound("in-trojan", 10007, "www.microsoft.com", TrojanConfig{Password: "trojanpass", Mode: "reality", ShortID: "ef123456", PrivateKey: priv, PublicKey: pub}),
		SingBoxTrojanInbound("in-trojan-cf", 10008, "test.example.com", TrojanConfig{Password: "trojanpass", Mode: "cf", Domain: "test.example.com", Path: "/trojan", CertFile: certPath, KeyFile: keyPath}),
		SingBoxTrojanInbound("in-trojan-h2", 10009, "test.example.com", TrojanConfig{Password: "trojanpass", Mode: "h2", Domain: "test.example.com", Path: "/h2", CertFile: certPath, KeyFile: keyPath}),
		SingBoxTrojanInbound("in-trojan-hu", 10010, "test.example.com", TrojanConfig{Password: "trojanpass", Mode: "httpupgrade", Domain: "test.example.com", Path: "/hu", CertFile: certPath, KeyFile: keyPath}),
		SingBoxSSInbound("in-ss", 10011, SSConfig{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}),
		SingBoxSocksInbound("in-socks", 10012, SocksConfig{User: "socksuser", Pass: "sockspass"}),
		SingBoxHTTPInbound("in-http", 10013, HTTPConfig{User: "httpuser", Pass: "httppass"}),
		SingBoxHy2Inbound("in-hy2", 10014, "test.example.com", certPath, keyPath, Hy2Config{Password: "hy2pass", ObfsType: "salamander", ObfsPassword: "obfspass", UpMbps: "100", DownMbps: "200"}),
		SingBoxTUICInbound("in-tuic", 10015, "test.example.com", certPath, keyPath, TUICConfig{UUID: uuid, Password: "tuicpass"}),
		SingBoxAnyTLSInbound("in-anytls", 10016, "test.example.com", certPath, keyPath, AnyTLSConfig{Name: "anyuser", Password: "anypass"}),
		SingBoxNaiveInbound("in-naive", 10017, NaiveConfig{Username: "naiveuser", Password: "naivepass", Domain: "test.example.com"}, certPath, keyPath),
	)
	endpoints := []interface{}{
		SingBoxWGEndpoint("wg-1", 10018, WGConfig{ServerPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ServerPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientPub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ClientIP: "10.0.0.2/32"}),
	}

	// B 节点：用存储的 xray 格式 JSON（与 ParseBLink 产物同形）+ hy2 的 sing-box 格式
	bVLESS := `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"` + uuid + `","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"` + pub + `","shortId":"abcd1234","spiderX":"/"}}}`
	bVMessWS := `{"protocol":"vmess","settings":{"vnext":[{"address":"203.0.113.11","port":443,"users":[{"id":"` + uuid + `","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"test.example.com"},"wsSettings":{"path":"/vmess","headers":{"Host":"test.example.com"}}}}`
	bTrojan := `{"protocol":"trojan","settings":{"servers":[{"address":"203.0.113.12","port":443,"password":"bpass"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"` + pub + `","shortId":"abcd1234","spiderX":"/"}}}`
	bSS := `{"protocol":"shadowsocks","settings":{"servers":[{"address":"203.0.113.13","port":8388,"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA=="}]}}`
	bSocks := `{"protocol":"socks","settings":{"servers":[{"address":"203.0.113.14","port":1080,"users":[{"user":"suser","pass":"spass"}]}]}}`
	bHy2 := `{"type":"hysteria2","server":"203.0.113.15","server_port":443,"password":"hy2pass","tls":{"enabled":true,"server_name":"test.example.com","insecure":true,"alpn":["h3"]}}`
	var outbounds []interface{}
	for _, tc := range []struct {
		proto, cfg, tag string
	}{
		{"vless", bVLESS, "chain-1"},
		{"vmess", bVMessWS, "chain-2"},
		{"trojan", bTrojan, "chain-3"},
		{"shadowsocks", bSS, "chain-4"},
		{"socks", bSocks, "chain-5"},
		{"hysteria2", bHy2, "chain-6"},
	} {
		ob, err := SingBoxBOutbound(tc.proto, tc.cfg, tc.tag)
		if err != nil {
			t.Fatalf("B 出站转换失败 %s：%v", tc.tag, err)
		}
		outbounds = append(outbounds, ob)
	}

	rules := SingBoxChainRules([]ChainInput{
		{InboundTag: "in-vless", OutboundTag: "chain-1", List: "example.com\n*.example.org\n1.2.3.0/24\n# 注释行\n"},
		{InboundTag: "in-vless-ws", OutboundTag: "chain-6", List: "hy.example.com\n"},
	})

	full := SingBoxFullConfig(inbounds, endpoints, outbounds, rules)
	data, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "singbox-full.json")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("生成 %s（入站 %d，端点 %d，出站 %d，规则 %d）", outPath, len(inbounds), len(endpoints), len(outbounds), len(rules))

	// 断言 1：VLESS Reality 的 short_id 必须是数组（sing-box 格式，xray 是单值）
	raw := string(data)
	if !strings.Contains(raw, `"short_id": [`) {
		t.Errorf("reality short_id 未写成数组")
	}
	// 断言 2：VLESS WS 档必须丢掉 flow（vision 只用于 TCP 裸流）
	var doc struct {
		Inbounds []struct {
			Tag   string `json:"tag"`
			Users []struct {
				Flow string `json:"flow"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, in := range doc.Inbounds {
		if in.Tag == "in-vless-ws" && len(in.Users) > 0 && in.Users[0].Flow != "" {
			t.Errorf("VLESS WS 档不应带 flow，实为 %q", in.Users[0].Flow)
		}
	}
	// 断言 3：不支持的 B 节点传输必须报错，不能静默
	bad := `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"` + uuid + `"}]}]},"streamSettings":{"network":"kcp","security":"none"}}`
	if _, err := SingBoxBOutbound("vless", bad, "chain-bad"); err == nil {
		t.Errorf("不支持的 B 节点传输应报错，却通过了")
	}
}
