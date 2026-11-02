package server

// ---------- 2FA 设置接口 ----------
// 开通流程：begin 生成待开通密钥（二维码 + 手动密钥）→ 用户在验证器里
// 看到 6 位码 → enable 验对一次才正式生效，并一次发 10 个恢复码
// （只显示这一次）。换一个 = 重新生成待开通密钥，旧密钥不受影响，
// 直到新密钥验对开通为止。关闭要验一次动态码（或恢复码）；
// SSH 菜单的 reset 只允许本机回环调用，丢了 2FA 时的恢复口。

import (
	"net/http"
	"time"
)

func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	okJSON(w, map[string]interface{}{
		"enabled":       s.app.Store.GetSetting("totp_secret") != "",
		"recovery_left": s.recoveryLeft(),
	})
}

func (s *Server) totpBeginResponse(w http.ResponseWriter, r *http.Request) {
	secret := randTOTPSecret()
	_ = s.app.Store.SetSetting("totp_pending", secret)
	username, _ := s.sessionUser(r)
	otpauth := totpOTPAuthURL(username, secret)
	qr, err := totpQR(otpauth)
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	okJSON(w, map[string]interface{}{
		"secret":      secret,
		"otpauth_url": otpauth,
		"qr":          qr,
	})
}

func (s *Server) handle2FABegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s.totpBeginResponse(w, r)
}

func (s *Server) handle2FARegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s.totpBeginResponse(w, r)
}

func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	pending := s.app.Store.GetSetting("totp_pending")
	if pending == "" {
		errJSON(w, 400, "请先点开通 2FA 生成密钥")
		return
	}
	if !verifyTOTP(pending, body.Code, time.Now()) {
		errJSON(w, 400, "动态码不对")
		return
	}
	_ = s.app.Store.SetSetting("totp_secret", pending)
	_ = s.app.Store.SetSetting("totp_pending", "")
	codes := genRecoveryCodes()
	_ = s.app.Store.SetSetting("totp_recovery", hashRecoveryCodes(codes))
	s.totpMarkIP(clientIPOf(r))
	okJSON(w, map[string]interface{}{"recovery": codes})
}

func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	secret := s.app.Store.GetSetting("totp_secret")
	if secret == "" {
		errJSON(w, 400, "2FA 未开通")
		return
	}
	if verifyTOTP(secret, body.Code, time.Now()) || s.tryRecoveryCode(body.Code) {
		s.totpClear()
		okJSON(w, nil)
		return
	}
	errJSON(w, 400, "动态码不对")
}

func (s *Server) handle2FAReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	// 只允许本机回环：SSH 菜单跑在本机上，浏览器会话即使被盗也关不掉 2FA。
	if !isLoopbackIP(clientIPOf(r)) {
		errJSON(w, 403, "关闭 2FA 只能在本机 SSH 菜单里操作")
		return
	}
	s.totpClear()
	okJSON(w, nil)
}
