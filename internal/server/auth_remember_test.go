package server

// v1.1.3：记住登录 30 天 + 改密码免旧密码。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sssingbox/internal/store"
)

func newAuthTestServer(t *testing.T, username, password string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("建临时 Store 失败：%v", err)
	}
	t.Cleanup(func() { st.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err := st.CreateUser(username, string(h)); err != nil {
		t.Fatalf("建用户失败：%v", err)
	}
	return &Server{app: &App{Store: st}, sessions: map[string]session{}}
}

func postJSON(t *testing.T, s *Server, handler func(http.ResponseWriter, *http.Request), path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeOK(t *testing.T, rec *httptest.ResponseRecorder) (bool, string) {
	t.Helper()
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("解响应失败：%v", err)
	}
	return out.OK, out.Error
}

func loginCookie(t *testing.T, s *Server, body string) *http.Cookie {
	t.Helper()
	rec := postJSON(t, s, s.handleLogin, "/api/login", body, nil)
	ok, errMsg := decodeOK(t, rec)
	if !ok {
		t.Fatalf("登录应成功，得到错误：%s", errMsg)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sssingbox_session" {
			return c
		}
	}
	t.Fatal("登录成功却没下发会话 cookie")
	return nil
}

func TestLoginRemember30Days(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123","remember":true}`)
	if c.MaxAge != 30*86400 {
		t.Fatalf("记住登录 cookie 应为 30 天，得到 MaxAge=%d", c.MaxAge)
	}
	sess := s.sessions[c.Value]
	if d := time.Until(sess.exp); d < 29*24*time.Hour || d > 30*24*time.Hour+time.Hour {
		t.Fatalf("记住登录会话应约 30 天，得到 %v", d)
	}
}

func TestLoginDefault24Hours(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	if c.MaxAge != 86400 {
		t.Fatalf("不勾记住登录 cookie 应为 24 小时，得到 MaxAge=%d", c.MaxAge)
	}
	sess := s.sessions[c.Value]
	if d := time.Until(sess.exp); d < 23*time.Hour || d > 24*time.Hour+time.Hour {
		t.Fatalf("默认会话应约 24 小时，得到 %v", d)
	}
}

func TestChangePasswordWithoutOld(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	// 不带旧密码、只填两遍新密码就应改成功。
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/password", `{"new":"newpass456","new2":"newpass456"}`, c)
	ok, errMsg := decodeOK(t, rec)
	if !ok || rec.Code != 200 {
		t.Fatalf("免旧密码改密码应成功，状态 %d 错误 %s", rec.Code, errMsg)
	}
	// 新密码能登，旧密码不能登。
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"newpass456"}`, nil)
	if ok, _ := decodeOK(t, rec); !ok {
		t.Fatal("新密码应能登录")
	}
	rec = postJSON(t, s, s.handleLogin, "/api/login", `{"username":"u1","password":"oldpass123"}`, nil)
	if ok, _ := decodeOK(t, rec); ok || rec.Code != 401 {
		t.Fatalf("旧密码改后应登不上，状态 %d", rec.Code)
	}
}

func TestChangePasswordMismatch(t *testing.T) {
	s := newAuthTestServer(t, "u1", "oldpass123")
	c := loginCookie(t, s, `{"username":"u1","password":"oldpass123"}`)
	rec := postJSON(t, s, s.handleSettingsAction, "/api/settings/password", `{"new":"newpass456","new2":"otherpass789"}`, c)
	if rec.Code != 400 {
		t.Fatalf("两次新密码不一致应 400，得到 %d", rec.Code)
	}
	if ok, _ := decodeOK(t, rec); ok {
		t.Fatal("两次新密码不一致不应成功")
	}
}
