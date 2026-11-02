package server

// v1.2.0：2FA（TOTP + 恢复码 + 新 IP 验证）与面板访问（根路径/端口/域名）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 附录 B 的 SHA1 向量：密钥 ASCII "12345678901234567890"，
	// base32 为 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ；8 位码取后 6 位。
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
	}
	for _, c := range cases {
		got, err := totpCodeAt(secret, time.Unix(c.unix, 0))
		if err != nil || got != c.want {
			t.Fatalf("t=%d 应得 %s，得到 %s（err %v）", c.unix, c.want, got, err)
		}
	}
}

func TestTOTP_VerifyWindow(t *testing.T) {
	secret := randTOTPSecret()
	now := time.Now()
	code, _ := totpCodeAt(secret, now)
	if !verifyTOTP(secret, code, now) {
		t.Fatal("当前步的码应能通过")
	}
	if !verifyTOTP(secret, code, now.Add(30*time.Second)) {
		t.Fatal("前后一步容忍：下一秒步应能通过")
	}
	if verifyTOTP(secret, code, now.Add(90*time.Second)) {
		t.Fatal("三步之外应拒绝")
	}
	if verifyTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("错码应拒绝")
	}
}

func TestTOTP_RecoverySingleUse(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	codes := genRecoveryCodes()
	if len(codes) != 10 {
		t.Fatalf("恢复码应为 10 个，得到 %d", len(codes))
	}
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))
	if !s.tryRecoveryCode(codes[3]) {
		t.Fatal("未用过的恢复码应命中")
	}
	if s.tryRecoveryCode(codes[3]) {
		t.Fatal("用过的恢复码再次用应拒绝（一次性）")
	}
	if s.recoveryLeft() != 9 {
		t.Fatalf("用掉 1 个后应剩 9 个，得到 %d", s.recoveryLeft())
	}
}

func TestPanelPath_Validation(t *testing.T) {
	ok := []string{"", "abc12", "a", "Ab3-x_9", strings.Repeat("a", 32)}
	for _, p := range ok {
		if !validPanelPath(p) {
			t.Fatalf("路径 %q 应合法", p)
		}
	}
	bad := []string{"sub", "api", "a/b", "a b", "中文", strings.Repeat("a", 33)}
	for _, p := range bad {
		if validPanelPath(p) {
			t.Fatalf("路径 %q 应拒绝", p)
		}
	}
	if !validPanelDomain("panel.example.com") || !validPanelDomain("") {
		t.Fatal("合法域名与留空应通过")
	}
	if validPanelDomain("http://panel.example.com") || validPanelDomain("panel.example.com/abc") || validPanelDomain("x y.us") {
		t.Fatal("带协议、路径、空格的域名应拒绝")
	}
}

func TestPanelPath_Random(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := randPanelPath()
		if len(p) != 5 || !validPanelPath(p) {
			t.Fatalf("随机路径应为 5 位合法英文，得到 %q", p)
		}
		for _, c := range p {
			if c < 'a' || c > 'z' {
				t.Fatalf("随机路径只用小写英文，得到 %q", p)
			}
		}
	}
}

func TestPanelPath_Gate(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok:" + r.URL.Path)) })
	gate := s.panelPathGate(next)
	get := func(path, remote string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	// 根目录模式：全部放行。
	if code, body := get("/api/me", "203.0.113.9:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("根目录模式应放行，得到 %d %q", code, body)
	}
	_ = s.app.Store.SetSetting("panel_path", "abc12")
	// 带正确前缀：剥掉前缀进内层。
	if code, body := get("/abc12/api/me", "203.0.113.9:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("正确前缀应剥掉放行，得到 %d %q", code, body)
	}
	if code, body := get("/abc12", "203.0.113.9:1234"); code != 200 || body != "ok:/" {
		t.Fatalf("裸前缀应回到首页，得到 %d %q", code, body)
	}
	// 裸地址与错前缀：一律 404，不露面板指纹。
	if code, _ := get("/", "203.0.113.9:1234"); code != 404 {
		t.Fatalf("裸根路径应 404，得到 %d", code)
	}
	if code, _ := get("/api/me", "203.0.113.9:1234"); code != 404 {
		t.Fatalf("无前缀的 API 应 404，得到 %d", code)
	}
	// 订阅链接不进路径门（token 本身就是密钥）。
	if code, _ := get("/sub/anything", "203.0.113.9:1234"); code != 200 {
		t.Fatalf("订阅链接应绕过路径门，得到 %d", code)
	}
	// 本机回环不进路径门（SSH 菜单、安装器），但带了前缀也要剥掉，
	// 否则内层路由拿着 /<路径>/api/... 找不到文件。
	if code, _ := get("/api/me", "127.0.0.1:1234"); code != 200 {
		t.Fatalf("回环应绕过路径门，得到 %d", code)
	}
	if code, body := get("/abc12/api/me", "127.0.0.1:1234"); code != 200 || body != "ok:/api/me" {
		t.Fatalf("回环带前缀也应剥掉放行，得到 %d %q", code, body)
	}
}

func TestPanelAccess_RewriteServicePort(t *testing.T) {
	src := "[Service]\nExecStart=/usr/local/bin/sssingbox -port 18081 -data /var/lib/sssingbox\n"
	got, err := rewriteServicePort(src, 19090)
	if err != nil || !strings.Contains(got, "-port 19090") || strings.Contains(got, "18081") {
		t.Fatalf("应只改 -port 数字，得到 %q（err %v）", got, err)
	}
	if _, err := rewriteServicePort("[Service]\nExecStart=/bin/foo\n", 19090); err == nil {
		t.Fatal("没有 -port 参数应报错")
	}
}
