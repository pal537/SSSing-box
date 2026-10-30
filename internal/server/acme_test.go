package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDNS01RecordName(t *testing.T) {
	if got := dns01RecordName("example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("got %q", got)
	}
	// 通配符与根域名共用一条 _acme-challenge 记录名。
	if got := dns01RecordName("*.example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("got %q", got)
	}
	if got := dns01RecordName("a.b.example.com"); got != "_acme-challenge.a.b.example.com" {
		t.Errorf("子域名记录名应带完整前缀，got %q", got)
	}
}

func TestDNS01TXTValue(t *testing.T) {
	// RFC 8555 公式：base64url(SHA256(token + "." + thumbprint))。
	token, thumb := "abc-token", "xyz-thumb"
	sum := sha256.Sum256([]byte(token + "." + thumb))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got := dns01TXTValue(token, thumb)
	if got != want {
		t.Errorf("dns01TXTValue = %q, want %q", got, want)
	}
	if len(got) != 43 {
		t.Errorf("SHA256 base64url 应为 43 字符，got %d", len(got))
	}
	if dns01TXTValue("other", thumb) == got {
		t.Error("不同 token 应算出不同 TXT 值")
	}
}

func TestThumbprintFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &acmeClient{key: key}
	tp, err := c.thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(tp) != 43 {
		t.Errorf("JWK 指纹应为 43 字符，got %d (%q)", len(tp), tp)
	}
	for _, ch := range tp {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			t.Errorf("指纹含非 base64url 字符 %q", ch)
		}
	}
	// 同一密钥指纹稳定。
	tp2, _ := c.thumbprint()
	if tp2 != tp {
		t.Error("同一密钥的指纹应稳定")
	}
	if strings.Contains(tp, "=") {
		t.Error("base64url 指纹不应带填充 =")
	}
}
