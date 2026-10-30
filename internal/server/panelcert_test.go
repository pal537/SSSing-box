package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(i int) string { return strconv.Itoa(i) }

// makeTestCertPair：生成一张自签证书 + 私钥（PEM），NotAfter 由参数定。
func makeTestCertPair(t *testing.T, dnsName string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestNormalizeCertDomain(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"Example.COM", "example.com", false},
		{" https://foo.bar.com/ ", "foo.bar.com", false},
		{"*.Example.com", "*.example.com", false},
		{"example.com.", "example.com", false},
		{"1.2.3.4", "", true},
		{"localhost", "", true},
		{"a..b.com", "", true},
		{"", "", true},
		{"foo_bar.com", "", true},
		{"-bad.example.com", "", true},
		{"example.com:8443", "", true},
	}
	for _, c := range cases {
		got, err := normalizeCertDomain(c.in)
		if c.wantErr && err == nil {
			t.Errorf("normalizeCertDomain(%q) 应报错", c.in)
		}
		if !c.wantErr && (err != nil || got != c.want) {
			t.Errorf("normalizeCertDomain(%q) = %q, %v； want %q", c.in, got, err, c.want)
		}
	}
}

func TestNormalizeCertDomains(t *testing.T) {
	got, err := normalizeCertDomains([]string{"B.example.com", "a.example.com", "b.example.com"})
	if err != nil || len(got) != 2 || got[0] != "b.example.com" || got[1] != "a.example.com" {
		t.Errorf("去重保序失败：%v, %v", got, err)
	}
	if _, err := normalizeCertDomains(nil); err == nil {
		t.Error("空域名组应报错")
	}
	many := []string{}
	for i := 0; i < 101; i++ {
		many = append(many, "d"+itoa(i)+".example.com")
	}
	if _, err := normalizeCertDomains(many); err == nil {
		t.Error("超 100 个域名应报错")
	}
}

func TestResolveCertApply(t *testing.T) {
	cases := []struct {
		name        string
		domains     []string
		method      string
		cfToken     string
		storedToken string
		port80Free  bool
		wantMethod  string
		wantToken   string
		wantErr     bool
	}{
		{"自动+80空闲", []string{"a.example.com"}, "", "", "", true, "http-01", "", false},
		{"自动+80被占无Token", []string{"a.example.com"}, "", "", "", false, "", "", true},
		{"自动+80被占带Token", []string{"a.example.com"}, "", "tok1", "", false, "dns-01", "tok1", false},
		{"自动+通配符带Token", []string{"*.example.com"}, "", "tok1", "", true, "dns-01", "tok1", false},
		{"自动+通配符无Token", []string{"*.example.com"}, "", "", "", true, "", "", true},
		{"显式HTTP-01但80被占", []string{"a.example.com"}, "http-01", "", "", false, "", "", true},
		{"显式HTTP-01但通配符", []string{"*.example.com"}, "http-01", "", "", true, "", "", true},
		{"显式DNS-01无Token", []string{"a.example.com"}, "dns-01", "", "", true, "", "", true},
		{"DNS-01掩码占位用已存", []string{"a.example.com"}, "dns-01", certTokenMask, "stored1", true, "dns-01", "stored1", false},
		{"DNS-01新Token覆盖已存", []string{"a.example.com"}, "dns-01", "new1", "old1", true, "dns-01", "new1", false},
		{"未知方式", []string{"a.example.com"}, "tls-alpn-01", "", "", true, "", "", true},
	}
	for _, c := range cases {
		domains, method, token, err := resolveCertApply(c.domains, "", c.method, c.cfToken, c.storedToken, c.port80Free)
		if c.wantErr && err == nil {
			t.Errorf("%s：应报错", c.name)
		}
		if !c.wantErr {
			if err != nil {
				t.Errorf("%s：不应报错：%v", c.name, err)
			} else if method != c.wantMethod || token != c.wantToken || len(domains) != 1 {
				t.Errorf("%s：method=%q token=%q domains=%v", c.name, method, token, domains)
			}
		}
	}
}

func TestResolveCFToken(t *testing.T) {
	if got := resolveCFToken(certTokenMask, "stored"); got != "stored" {
		t.Errorf("掩码占位应用已存 Token，got %q", got)
	}
	if got := resolveCFToken("new", "stored"); got != "new" {
		t.Errorf("显式新 Token 应优先，got %q", got)
	}
	if got := resolveCFToken("", ""); got != "" {
		t.Errorf("都空应返回空，got %q", got)
	}
}

func TestCertDirForDomains(t *testing.T) {
	if got := certDirForDomains([]string{"example.com"}); got != "example.com" {
		t.Errorf("got %q", got)
	}
	if got := certDirForDomains([]string{"*.example.com"}); got != "wildcard.example.com" {
		t.Errorf("通配符目录名应为 wildcard.example.com，got %q", got)
	}
}

func TestSanitizeCertDirName(t *testing.T) {
	if got, err := sanitizeCertDirName("my cert!"); err != nil || got != "my-cert-" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "..", "."} {
		if _, err := sanitizeCertDirName(bad); err == nil {
			t.Errorf("sanitizeCertDirName(%q) 应报错", bad)
		}
	}
}

func TestCertNeedsRenewal(t *testing.T) {
	now := time.Now()
	if certNeedsRenewal(now.Add(31*24*time.Hour), now) {
		t.Error("31 天后到期不应续期")
	}
	if !certNeedsRenewal(now.Add(29*24*time.Hour), now) {
		t.Error("29 天后到期应续期")
	}
	if !certNeedsRenewal(now.Add(-time.Hour), now) {
		t.Error("已过期应续期")
	}
	if !certNeedsRenewal(time.Time{}, now) {
		t.Error("读不到到期时间应续期")
	}
}

func TestCertPairValidation(t *testing.T) {
	certPEM, keyPEM := makeTestCertPair(t, "panel.test.example", time.Now().Add(90*24*time.Hour))
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("有效证书对不应报错：%v", err)
	}
	_, otherKey := makeTestCertPair(t, "other.test.example", time.Now().Add(90*24*time.Hour))
	if _, err := tls.X509KeyPair(certPEM, otherKey); err == nil {
		t.Error("证书与他人私钥配对应报错")
	}
}

func TestStoreManualAndList(t *testing.T) {
	m := newPanelCertManager(t.TempDir(), nil, nil)
	certPEM, keyPEM := makeTestCertPair(t, "panel.test.example", time.Now().Add(90*24*time.Hour))
	info, err := m.storeManual("测试证书", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("storeManual: %v", err)
	}
	if info.ID == "" || len(info.Domains) != 1 || info.Domains[0] != "panel.test.example" {
		t.Errorf("storeManual 返回异常：%+v", info)
	}
	if _, err := m.storeManual("测试证书", certPEM, keyPEM); err == nil {
		t.Error("同名证书应拒绝覆盖")
	}
	list := m.listCerts()
	if len(list) != 1 || list[0].ID != info.ID || list[0].DaysLeft < 89 {
		t.Errorf("listCerts 异常：%+v", list)
	}
	// 损坏目录（缺私钥）不应出现在列表里。
	_ = os.MkdirAll(filepath.Join(m.dir, "broken"), 0755)
	_ = os.WriteFile(filepath.Join(m.dir, "broken", "fullchain.pem"), certPEM, 0644)
	if list := m.listCerts(); len(list) != 1 {
		t.Errorf("损坏目录应被跳过，got %d", len(list))
	}
}

func TestMetaRoundTrip(t *testing.T) {
	m := newPanelCertManager(t.TempDir(), nil, nil)
	certPEM, keyPEM := makeTestCertPair(t, "panel.test.example", time.Now().Add(90*24*time.Hour))
	meta := panelCertMeta{Name: "备注名", Domains: []string{"panel.test.example"}, Method: "http-01", AutoRenew: true, Source: "acme"}
	if err := m.writeCert("panel.test.example", certPEM, keyPEM, meta); err != nil {
		t.Fatalf("writeCert: %v", err)
	}
	got, ok := m.readMeta("panel.test.example")
	if !ok || got.Name != "备注名" || !got.AutoRenew || got.Source != "acme" {
		t.Errorf("meta 回读异常：%+v, ok=%v", got, ok)
	}
}

func TestHTTP01ChallengeHandler(t *testing.T) {
	h := newHTTP01Server()
	h.Register("tok123", "tok123.thumbprint")
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/tok123", nil)
	rec := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(rec, req)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "tok123.thumbprint" {
		t.Errorf("已注册挑战应返回 keyAuth，got %d %q", rec.Code, rec.Body.String())
	}
	req2 := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown", nil)
	rec2 := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("未知挑战应 404，got %d", rec2.Code)
	}
	h.Clear("tok123")
	rec3 := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(rec3, httptest.NewRequest("GET", "/.well-known/acme-challenge/tok123", nil))
	if rec3.Code != http.StatusNotFound {
		t.Errorf("清理后挑战应 404，got %d", rec3.Code)
	}
}

func TestJobSingleFlight(t *testing.T) {
	m := newPanelCertManager(t.TempDir(), nil, nil)
	if !m.claimJob([]string{"a.example.com"}, "http-01") {
		t.Fatal("首次认领应成功")
	}
	if m.claimJob([]string{"b.example.com"}, "dns-01") {
		t.Error("任务进行中时二次认领应失败")
	}
	m.finishJob(true, "")
	if !m.claimJob([]string{"b.example.com"}, "dns-01") {
		t.Error("任务结束后应可再次认领")
	}
	m.releaseJob()
	if m.jobSnapshot().Running {
		t.Error("release 后任务应为空闲")
	}
}

// settingsMap：测试用内存设置存储。
type settingsMap map[string]string

func (s settingsMap) Get(key string) string { return s[key] }
func (s settingsMap) Set(key, val string) error {
	s[key] = val
	return nil
}

func TestPanelTLSGating(t *testing.T) {
	dir := t.TempDir()
	settings := settingsMap{}
	m := newPanelCertManager(dir, settings.Get, settings.Set)
	// 默认：未配置 → 关闭。
	if enabled, _, _, _ := m.panelTLSConfig(); enabled {
		t.Error("默认应为 HTTP（关闭）")
	}
	// 开了但没选证书 → 关闭。
	settings["panel_https"] = "1"
	if enabled, _, _, _ := m.panelTLSConfig(); enabled {
		t.Error("未选证书时应回落 HTTP")
	}
	// 选了不存在的证书 → 关闭。
	settings["panel_cert"] = "missing.example.com"
	if enabled, _, _, _ := m.panelTLSConfig(); enabled {
		t.Error("证书不存在时应回落 HTTP")
	}
	// 选了真实有效证书 → 开启。
	certPEM, keyPEM := makeTestCertPair(t, "panel.test.example", time.Now().Add(90*24*time.Hour))
	if err := m.writeCert("panel.test.example", certPEM, keyPEM, panelCertMeta{Name: "x", Domains: []string{"panel.test.example"}, Method: "manual", Source: "manual"}); err != nil {
		t.Fatalf("writeCert: %v", err)
	}
	settings["panel_cert"] = "panel.test.example"
	enabled, dirName, certFile, keyFile := m.panelTLSConfig()
	if !enabled || dirName != "panel.test.example" {
		t.Errorf("有效证书应开启 TLS，got enabled=%v dir=%q", enabled, dirName)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("证书文件应存在：%v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("私钥文件应存在：%v", err)
	}
	// 过期证书：启用时校验应拒绝。
	expCert, expKey := makeTestCertPair(t, "old.test.example", time.Now().Add(-time.Hour))
	if err := m.writeCert("old.test.example", expCert, expKey, panelCertMeta{Name: "old", Domains: []string{"old.test.example"}, Method: "manual", Source: "manual"}); err != nil {
		t.Fatalf("writeCert: %v", err)
	}
	ok, err := m.certNotExpired("old.test.example")
	if err != nil || ok {
		t.Errorf("过期证书 certNotExpired 应为 false，got ok=%v err=%v", ok, err)
	}
	ok, err = m.certNotExpired("panel.test.example")
	if err != nil || !ok {
		t.Errorf("未过期证书 certNotExpired 应为 true，got ok=%v err=%v", ok, err)
	}
	// 过期证书：即使已选，Serve 门控也应回落 HTTP（重启后 http 能进面板再修）。
	settings["panel_cert"] = "old.test.example"
	if enabled, _, _, _ := m.panelTLSConfig(); enabled {
		t.Error("过期证书 Serve 门控应回落 HTTP")
	}
}

// TestDualListener：同一端口上明文 HTTP 与 TLS 都能通。
func TestDualListener(t *testing.T) {
	certPEM, keyPEM := makeTestCertPair(t, "dual.test.example", time.Now().Add(24*time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	go srv.Serve(&dualListener{Listener: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}})
	defer srv.Close()
	addr := ln.Addr().String()
	// 明文。
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("明文 GET：%v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("明文响应 = %q, want ok", body)
	}
	// TLS（自签，跳过校验）。
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err = client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("TLS GET：%v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("TLS 响应 = %q, want ok", body)
	}
}
