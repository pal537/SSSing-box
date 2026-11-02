package server

// ---------- 二次验证（2FA，龟甲模式） ----------
// TOTP（RFC 6238，SHA1，30 秒一步，6 位），只要标准验证器 App 就能用。
// 行为对齐龟甲：开通时必须输对一次动态码才生效；生效后只有新 IP 才要
// 再次验证动态码（同 IP 直接登录）；恢复码 10 个、一次性、用一次少一个。
// 本机回环（SSH 菜单、安装器）不走 2FA：能登本机的人已经有 root，
// 挡他没有意义；丢了 2FA 时菜单里的“关闭二次验证”就是恢复口。
// 全部标准库实现，不引新依赖；二维码用已有的 go-qrcode。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randTOTPSecret：16 位 base32 密钥（A-Z2-7），验证器 App 直接能扫。
func randTOTPSecret() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return totpB32.EncodeToString(b)
}

func totpCodeAt(secret string, t time.Time) (string, error) {
	key, err := totpB32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		// 容忍带 = 填充的旧格式。
		key, err = base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
		if err != nil {
			return "", err
		}
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (int(sum[off]&0x7f) << 24) | (int(sum[off+1]) << 16) | (int(sum[off+2]) << 8) | int(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// verifyTOTP：前后各容忍一步（手机时钟差 30 秒内都能过）。
func verifyTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, d := range []int64{-1, 0, 1} {
		if c, err := totpCodeAt(secret, t.Add(time.Duration(d)*30*time.Second)); err == nil && c == code {
			return true
		}
	}
	return false
}

func totpOTPAuthURL(username, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", "SSSing-box")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/SSSing-box:" + url.PathEscape(username) + "?" + v.Encode()
}

// 恢复码：10 个 XXXX-XXXX，去掉易混淆的 0/O/1/I，一次性。
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func genRecoveryCodes() []string {
	codes := make([]string, 0, 10)
	for len(codes) < 10 {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		var sb strings.Builder
		for i, x := range b {
			if i == 4 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
	}
	return codes
}

func hashRecoveryCodes(codes []string) string {
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, _ := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
		hashes = append(hashes, string(h))
	}
	b, _ := json.Marshal(hashes)
	return string(b)
}

// tryRecoveryCode：命中则把这条从库里删掉（一次性），返回是否命中。
func (s *Server) tryRecoveryCode(code string) bool {
	raw := s.app.Store.GetSetting("totp_recovery")
	if raw == "" {
		return false
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return false
	}
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(strings.TrimSpace(code))) == nil {
			hashes = append(hashes[:i], hashes[i+1:]...)
			b, _ := json.Marshal(hashes)
			_ = s.app.Store.SetSetting("totp_recovery", string(b))
			return true
		}
	}
	return false
}

func (s *Server) recoveryLeft() int {
	raw := s.app.Store.GetSetting("totp_recovery")
	if raw == "" {
		return 0
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return 0
	}
	return len(hashes)
}

// ---------- 已验证 IP ----------

func (s *Server) totpIPVerified(ip string) bool {
	raw := s.app.Store.GetSetting("totp_ips")
	if raw == "" {
		return false
	}
	var ips []string
	if err := json.Unmarshal([]byte(raw), &ips); err != nil {
		return false
	}
	for _, x := range ips {
		if x == ip {
			return true
		}
	}
	return false
}

func (s *Server) totpMarkIP(ip string) {
	if ip == "" {
		return
	}
	var ips []string
	_ = json.Unmarshal([]byte(s.app.Store.GetSetting("totp_ips")), &ips)
	for _, x := range ips {
		if x == ip {
			return
		}
	}
	ips = append(ips, ip)
	if len(ips) > 100 { // 只留最近 100 个，防无限长。
		ips = ips[len(ips)-100:]
	}
	b, _ := json.Marshal(ips)
	_ = s.app.Store.SetSetting("totp_ips", string(b))
}

func (s *Server) totpClear() {
	_ = s.app.Store.SetSetting("totp_secret", "")
	_ = s.app.Store.SetSetting("totp_pending", "")
	_ = s.app.Store.SetSetting("totp_recovery", "")
	_ = s.app.Store.SetSetting("totp_ips", "")
}

// ---------- 登录第二步的临时凭证 ----------

type totpChallenge struct {
	username string
	remember bool
	exp      time.Time
	attempts int
}

func (s *Server) totpChallengePut(tok string, ch totpChallenge) {
	s.totpTmpMu.Lock()
	if s.totpTmp == nil {
		s.totpTmp = map[string]totpChallenge{}
	}
	s.totpTmp[tok] = ch
	s.totpTmpMu.Unlock()
}

func (s *Server) totpChallengeTake(tok string) (totpChallenge, bool) {
	s.totpTmpMu.Lock()
	defer s.totpTmpMu.Unlock()
	ch, ok := s.totpTmp[tok]
	if !ok || time.Now().After(ch.exp) {
		delete(s.totpTmp, tok)
		return totpChallenge{}, false
	}
	return ch, true
}

func (s *Server) totpChallengeFail(tok string) {
	s.totpTmpMu.Lock()
	defer s.totpTmpMu.Unlock()
	if ch, ok := s.totpTmp[tok]; ok {
		ch.attempts++
		if ch.attempts >= 5 { // 5 次输错，临时凭证作废重来。
			delete(s.totpTmp, tok)
		} else {
			s.totpTmp[tok] = ch
		}
	}
}

func (s *Server) totpChallengeDone(tok string) {
	s.totpTmpMu.Lock()
	delete(s.totpTmp, tok)
	s.totpTmpMu.Unlock()
}

// totpQR：验证器扫码用的二维码 PNG（data URL，前端直接当 img src）。
func totpQR(otpauth string) (string, error) {
	png, err := qrcodeEncode(otpauth)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}