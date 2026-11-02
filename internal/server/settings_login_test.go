package server

// v1.1.7：面板登录一表保存（新账号留空不改、新密码只输一遍）。

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func loginOK(t *testing.T, s *Server, body string) bool {
	t.Helper()
	rec := postJSON(t, s, s.handleLogin, "/api/login", body, nil)
	ok, _ := decodeOK(t, rec)
	return ok && rec.Code == 200
}

func TestSettingsLoginBothEmpty(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"","password":""}`, c)
	if rec.Code != 400 {
		t.Fatalf("两项都空应 400，得到 %d", rec.Code)
	}
	if !loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("拒绝后原账号密码应仍能登录")
	}
}

func TestSettingsLoginShortPassword(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"u2","password":"123"}`, c)
	if rec.Code != 400 {
		t.Fatalf("短密码应 400，得到 %d", rec.Code)
	}
	// 先验后改：短密码被拒时账号也不应被改掉。
	if !loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("短密码被拒后原账号应仍能登录")
	}
	if loginOK(t, s, `{"username":"u2","password":"oldpass123"}`) {
		t.Fatal("短密码被拒后新账号不应生效")
	}
}

func TestSettingsLoginPasswordOnly(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"","password":"newpass456"}`, c)
	if ok, msg := decodeOK(t, rec); !ok || rec.Code != 200 {
		t.Fatalf("只改密码应成功，状态 %d 错误 %s", rec.Code, msg)
	}
	if !loginOK(t, s, `{"username":"u1","password":"newpass456"}`) {
		t.Fatal("新密码应能登录")
	}
	if loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("旧密码改后应登不上")
	}
}

func TestSettingsLoginUsernameOnly(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"u2","password":""}`, c)
	if ok, msg := decodeOK(t, rec); !ok || rec.Code != 200 {
		t.Fatalf("只改账号应成功，状态 %d 错误 %s", rec.Code, msg)
	}
	if !loginOK(t, s, `{"username":"u2","password":"oldpass123"}`) {
		t.Fatal("新账号+旧密码应能登录")
	}
	if loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("旧账号改后应登不上")
	}
}

func TestSettingsLoginBoth(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"u2","password":"newpass456"}`, c)
	if ok, msg := decodeOK(t, rec); !ok || rec.Code != 200 {
		t.Fatalf("账号密码一起改应成功，状态 %d 错误 %s", rec.Code, msg)
	}
	if !loginOK(t, s, `{"username":"u2","password":"newpass456"}`) {
		t.Fatal("新账号+新密码应能登录")
	}
	if loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("旧账号密码改后应登不上")
	}
}

func TestSettingsLoginExistingUsername(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	h, _ := bcrypt.GenerateFromPassword([]byte("otherpass"), bcrypt.DefaultCost)
	if err := s.app.Store.CreateUser("u2", string(h)); err != nil {
		t.Fatalf("建第二个用户失败：%v", err)
	}
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"u2","password":""}`, c)
	if rec.Code != 400 {
		t.Fatalf("改成已存在账号应 400，得到 %d", rec.Code)
	}
	if !loginOK(t, s, `{"username":"u1","password":"oldpass123"}`) {
		t.Fatal("被拒后原账号应仍能登录")
	}
}

func TestSettingsLoginUnauth(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/login", `{"username":"u2","password":"newpass456"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("未登录应 401，得到 %d", rec.Code)
	}
}
