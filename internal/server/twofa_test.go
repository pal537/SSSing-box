package server

// v1.2.0：2FA 登录全流程。

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustTmp(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		OK   bool `json:"ok"`
		Data struct {
			Need2FA bool   `json:"need_2fa"`
			Tmp     string `json:"tmp"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("解登录响应失败：%v", err)
	}
	if !out.Data.Need2FA || out.Data.Tmp == "" {
		t.Fatal("2FA 开通且新 IP 时登录应返回 need_2fa + tmp")
	}
	return out.Data.Tmp
}

func Test2FA_FullFlow(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)

	// 开通：begin 生成待开通密钥，用它算当前动态码开通。
	rec := postJSON(t, s, s.handle2FABegin, "/api/settings/2fa/begin", `{}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("begin 应成功：%s", msg)
	}
	pending := s.app.Store.GetSetting("totp_pending")
	if pending == "" {
		t.Fatal("begin 后应有待开通密钥")
	}
	code, err := totpCodeAt(pending, time.Now())
	if err != nil {
		t.Fatalf("算码失败：%v", err)
	}
	rec = postJSON(t, s, s.handle2FAEnable, "/api/settings/2fa/enable", `{"code":"`+code+`"}`, c)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("输对动态码应开通：%s", msg)
	}
	// 恢复码明文只在 enable 响应里出现一次；这里只验库里个数（10 个）。
	if s.recoveryLeft() != 10 {
		t.Fatalf("开通后恢复码应为 10 个，得到 %d", s.recoveryLeft())
	}
	// 新 IP（测试请求的 192.0.2.1 与开通时的回环不同）登录：应进第二步。
	// 注意：开通时 totpMarkIP 记的是测试请求的 192.0.2.1，所以先清掉，
	// 模拟“新 IP”；否则同一测试 IP 会直接跳过 2FA。
	_ = s.app.Store.SetSetting("totp_ips", "")
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	tmp := mustTmp(t, rec)

	// 第二步输错码：不给会话。
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"000000"}`, nil)
	if ok, _ := decodeOK(t, rec); ok {
		t.Fatal("错动态码不应登录")
	}
	// 第二步输对码：给会话，且该 IP 被记为已验证。
	secret := s.app.Store.GetSetting("totp_secret")
	code2, _ := totpCodeAt(secret, time.Now())
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"`+code2+`"}`, nil)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("对动态码应登录：%s", msg)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("第二步成功应下发会话 cookie")
	}
	// 同一 IP 再登录：直接给会话，不再要 2FA。
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123","remember":false}`, nil)
	var out struct {
		Data struct {
			Need2FA bool `json:"need_2fa"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Data.Need2FA {
		t.Fatal("已验证 IP 再登录不应再要 2FA")
	}
}

func Test2FA_RecoveryAndReset(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	// 直接布好已开通状态：密钥固定，恢复码已知。
	_ = s.app.Store.SetSetting("totp_secret", "JBSWY3DPEHPK3PXP")
	codes := []string{"ABCD-EFGH", "IJKL-MNOP"}
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))

	// 新 IP 登录进第二步，用恢复码登录成功；同一恢复码再用应失败。
	rec := postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	tmp := mustTmp(t, rec)
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"ABCD-EFGH"}`, nil)
	if ok, msg := decodeOK(t, rec); !ok {
		t.Fatalf("恢复码应能登录：%s", msg)
	}
	_ = s.app.Store.SetSetting("totp_ips", "")
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	tmp = mustTmp(t, rec)
	rec = postJSON(t, s, s.handleLogin2FA, "/api/login/2fa", `{"tmp":"`+tmp+`","code":"ABCD-EFGH"}`, nil)
	if ok, _ := decodeOK(t, rec); ok {
		t.Fatal("用过的恢复码应拒绝（一次性）")
	}

	// reset：非回环拒绝，回环放行（直接调 handler，只验回环门；
	// 会话鉴权在路由层 requireAuth，与其他设置接口同一层）。
	req := httptest.NewRequest("POST", "/api/settings/2fa/reset", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.9:1234"
	req.AddCookie(c)
	rec2 := httptest.NewRecorder()
	s.handle2FAReset(rec2, req)
	if rec2.Code != 403 {
		t.Fatalf("非回环 reset 应 403，得到 %d", rec2.Code)
	}
	req2 := httptest.NewRequest("POST", "/api/settings/2fa/reset", strings.NewReader(`{}`))
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.AddCookie(c)
	rec3 := httptest.NewRecorder()
	s.handle2FAReset(rec3, req2)
	if ok, msg := decodeOK(t, rec3); !ok {
		t.Fatalf("回环 reset 应成功：%s", msg)
	}
	if s.app.Store.GetSetting("totp_secret") != "" {
		t.Fatal("reset 后密钥应清空")
	}
}
