package server

// 面板域名 ACME 在线证书：移植龟甲同款（纯标准库手写 JWS，不引 lego）。
// CA 默认 Let's Encrypt；HTTP-01 / DNS-01（Cloudflare）；证书与账号密钥
// 存在面板数据目录 certs/panel/ 下。本文件只放协议客户端与 CF API，
// 证书的存放、任务、续期、面板 HTTPS 开关在 panelcert.go。

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	acmeDirURL     = "https://acme-v02.api.letsencrypt.org/directory"
	acmePollEvery  = 2 * time.Second
	acmePollTimout = 120 * time.Second
	cfAPIBase      = "https://api.cloudflare.com/client/v4"
	cfDoHBase      = "https://cloudflare-dns.com/dns-query"
	cfDoHPollEvery = 5 * time.Second
	cfDoHTimeout   = 120 * time.Second
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// loadOrCreateAccountKey：账户密钥 ECDSA P-256，存指定路径（0600）。
func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if der, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(der); block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeClient struct {
	dirURL  string
	http    *http.Client
	key     *ecdsa.PrivateKey
	kid     string
	dir     acmeDirectory
	nonceMu sync.Mutex
	nonce   string
}

func newAcmeClient(accountKeyPath string) (*acmeClient, error) {
	key, err := loadOrCreateAccountKey(accountKeyPath)
	if err != nil {
		return nil, err
	}
	c := &acmeClient{dirURL: acmeDirURL, http: &http.Client{Timeout: 30 * time.Second}, key: key}
	if err := c.loadDirectory(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *acmeClient) loadDirectory() error {
	resp, err := c.http.Get(c.dirURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ACME 目录请求失败: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(&c.dir)
}

func (c *acmeClient) fetchNonce() error {
	req, _ := http.NewRequest("HEAD", c.dir.NewNonce, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonceMu.Lock()
		c.nonce = n
		c.nonceMu.Unlock()
		return nil
	}
	return errors.New("ACME 服务端未返回 Replay-Nonce")
}

func (c *acmeClient) takeNonce() string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	n := c.nonce
	c.nonce = ""
	return n
}

func (c *acmeClient) storeNonce(h http.Header) {
	if n := h.Get("Replay-Nonce"); n != "" {
		c.nonceMu.Lock()
		c.nonce = n
		c.nonceMu.Unlock()
	}
}

// jwkMap：账户公钥 JWK。
func (c *acmeClient) jwkMap() map[string]string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	c.key.PublicKey.X.FillBytes(x)
	c.key.PublicKey.Y.FillBytes(y)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64url(x), "y": b64url(y)}
}

// thumbprint：RFC 7638 JWK 指纹。
func (c *acmeClient) thumbprint() (string, error) {
	jwk := c.jwkMap()
	raw := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	sum := sha256.Sum256([]byte(raw))
	return b64url(sum[:]), nil
}

// jwsBody：ES256 签名；payload 为 nil 时表示 POST-as-GET（空字符串载荷）。
func (c *acmeClient) jwsBody(url string, payload any, useKid bool) ([]byte, error) {
	nonce := c.takeNonce()
	if nonce == "" {
		if err := c.fetchNonce(); err != nil {
			return nil, err
		}
		nonce = c.takeNonce()
	}
	prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if useKid {
		prot["kid"] = c.kid
	} else {
		prot["jwk"] = c.jwkMap()
	}
	protJSON, _ := json.Marshal(prot)
	var payloadB64 string
	if payload != nil {
		pb, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = b64url(pb)
	}
	sigInput := b64url(protJSON) + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, h[:])
	if err != nil {
		return nil, err
	}
	rb := make([]byte, 32)
	sb := make([]byte, 32)
	r.FillBytes(rb)
	s.FillBytes(sb)
	body, _ := json.Marshal(map[string]string{
		"protected": b64url(protJSON),
		"payload":   payloadB64,
		"signature": b64url(append(rb, sb...)),
	})
	return body, nil
}

type acmeError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (e *acmeError) Error() string {
	if e.Detail != "" {
		return e.Type + ": " + e.Detail
	}
	return e.Type
}

// post：发 JWS 请求；遇 badNonce 自动换 nonce 重试一次。
// payload=nil 表示 POST-as-GET。
func (c *acmeClient) post(url string, payload any, useKid bool) (body []byte, hdr http.Header, status int, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		jb, err := c.jwsBody(url, payload, useKid)
		if err != nil {
			return nil, nil, 0, err
		}
		req, _ := http.NewRequest("POST", url, bytes.NewReader(jb))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, 0, err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.storeNonce(resp.Header)
		if resp.StatusCode == 400 {
			var ae acmeError
			if json.Unmarshal(b, &ae) == nil && strings.Contains(ae.Type, "badNonce") && attempt == 0 {
				c.nonceMu.Lock()
				c.nonce = ""
				c.nonceMu.Unlock()
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var ae acmeError
			if json.Unmarshal(b, &ae) == nil && ae.Type != "" {
				return nil, resp.Header, resp.StatusCode, &ae
			}
			return nil, resp.Header, resp.StatusCode, fmt.Errorf("ACME 请求失败: %s %s", resp.Status, strings.TrimSpace(string(b)))
		}
		return b, resp.Header, resp.StatusCode, nil
	}
	return nil, nil, 0, errors.New("ACME 请求重试失败")
}

func (c *acmeClient) ensureAccount() error {
	_, hdr, _, err := c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true}, false)
	if err != nil {
		return err
	}
	if loc := hdr.Get("Location"); loc != "" {
		c.kid = loc
		return nil
	}
	return errors.New("ACME 账户创建未返回 Location")
}

type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type acmeAuthz struct {
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Status     string `json:"status"`
	Challenges []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		URL    string `json:"url"`
		Token  string `json:"token"`
	} `json:"challenges"`
}

// pollUntil：POST-as-GET 轮询，直到 fn 返回 true（完成）或超时。
func (c *acmeClient) pollUntil(url string, fn func([]byte) (done bool, err error)) error {
	deadline := time.Now().Add(acmePollTimout)
	for {
		b, _, _, err := c.post(url, nil, true)
		if err != nil {
			return err
		}
		done, err := fn(b)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("ACME 轮询超时")
		}
		time.Sleep(acmePollEvery)
	}
}

// http01Challenge：HTTP-01 挑战应答方（调用方在订单期间提供，
// 龟甲用面板前置服务；驿站用订单期间临时绑 :80 的服务器，见 panelcert.go）。
type http01Challenge interface {
	Register(token, keyAuth string)
	Clear(token string)
}

// orderCert：为域名组申请证书，返回 fullchain PEM 与域名私钥 PEM。
// method 只能是 http-01 或 dns-01（自动已在调用方解析）；dns-01 需要 cfToken；
// http-01 需要 h 实时应答挑战（调用方负责在订单期间绑好 :80）。
func (c *acmeClient) orderCert(domains []string, method, cfToken string, h http01Challenge) (fullchainPEM, privkeyPEM []byte, err error) {
	if len(domains) == 0 {
		return nil, nil, errors.New("域名为空")
	}
	if method != "http-01" && method != "dns-01" {
		return nil, nil, errors.New("未知的验证方式: " + method)
	}
	if method == "dns-01" && cfToken == "" {
		return nil, nil, errors.New("DNS-01 需要 Cloudflare API Token")
	}
	if method == "http-01" && h == nil {
		return nil, nil, errors.New("HTTP-01 需要挑战应答服务（80 端口未就绪）")
	}
	if err := c.ensureAccount(); err != nil {
		return nil, nil, err
	}
	idents := []map[string]string{}
	for _, d := range domains {
		idents = append(idents, map[string]string{"type": "dns", "value": d})
	}
	ob, _, _, err := c.post(c.dir.NewOrder, map[string]any{"identifiers": idents}, true)
	if err != nil {
		return nil, nil, err
	}
	var order acmeOrder
	if err := json.Unmarshal(ob, &order); err != nil {
		return nil, nil, err
	}
	thumb, err := c.thumbprint()
	if err != nil {
		return nil, nil, err
	}
	// 逐个授权做验证；清理函数统一 deferred，失败路径也尽力清理 TXT 记录与 HTTP-01 挑战。
	cleanups := []func(){}
	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()
	for _, authzURL := range order.Authorizations {
		ab, _, _, err := c.post(authzURL, nil, true)
		if err != nil {
			return nil, nil, err
		}
		var authz acmeAuthz
		if err := json.Unmarshal(ab, &authz); err != nil {
			return nil, nil, err
		}
		var challURL, token string
		for _, ch := range authz.Challenges {
			if ch.Type == method {
				challURL, token = ch.URL, ch.Token
				break
			}
		}
		if challURL == "" {
			return nil, nil, errors.New("授权中没有 " + method + " 验证方式")
		}
		if method == "http-01" {
			keyAuth := token + "." + thumb
			h.Register(token, keyAuth)
			tok := token
			cleanups = append(cleanups, func() { h.Clear(tok) })
		} else {
			// DNS-01：按授权标识建 TXT → 等 DoH 生效 → 再触发验证；记录按 ID 删除。
			// 通配符与根域名共用一条 _acme-challenge 记录名，但值不同，可并存多条。
			domain := authz.Identifier.Value
			name := dns01RecordName(domain)
			value := dns01TXTValue(token, thumb)
			cfc := newCFClient(cfToken)
			zoneID, err := cfc.findZoneID(domain)
			if err != nil {
				return nil, nil, err
			}
			recID, err := cfc.createTXT(zoneID, name, value)
			if err != nil {
				return nil, nil, err
			}
			z, rid := zoneID, recID
			cleanups = append(cleanups, func() { cfc.deleteTXT(z, rid) })
			if err := cfWaitTXT(name, value); err != nil {
				return nil, nil, err
			}
		}
		if _, _, _, err := c.post(challURL, map[string]any{}, true); err != nil {
			return nil, nil, err
		}
		invalidMsg := "域名验证失败（请确认域名已解析到本机且 80 端口可达）"
		if method == "dns-01" {
			invalidMsg = "域名验证失败（请确认域名已托管到 Cloudflare 且 Token 有 DNS 编辑权限）"
		}
		if err := c.pollUntil(authzURL, func(b []byte) (bool, error) {
			var az acmeAuthz
			if err := json.Unmarshal(b, &az); err != nil {
				return false, err
			}
			if az.Status == "valid" {
				return true, nil
			}
			if az.Status == "invalid" {
				return false, errors.New(invalidMsg)
			}
			return false, nil
		}); err != nil {
			return nil, nil, err
		}
	}
	// 生成域名密钥与 CSR，提交 finalize。
	domKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, domKey)
	if err != nil {
		return nil, nil, err
	}
	fb, _, _, err := c.post(order.Finalize, map[string]any{"csr": b64url(csrDER)}, true)
	if err != nil {
		return nil, nil, err
	}
	var fin acmeOrder
	if err := json.Unmarshal(fb, &fin); err != nil {
		return nil, nil, err
	}
	certURL := fin.Certificate
	if certURL == "" {
		if err := c.pollUntil(order.Finalize, func(b []byte) (bool, error) {
			var o acmeOrder
			if err := json.Unmarshal(b, &o); err != nil {
				return false, err
			}
			if o.Status == "valid" && o.Certificate != "" {
				certURL = o.Certificate
				return true, nil
			}
			if o.Status == "invalid" {
				return false, errors.New("证书签发失败")
			}
			return false, nil
		}); err != nil {
			return nil, nil, err
		}
	}
	// 下载证书链（PEM）。
	jw, err := c.jwsBody(certURL, nil, true)
	if err != nil {
		return nil, nil, err
	}
	req, _ := http.NewRequest("POST", certURL, bytes.NewReader(jw))
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("Accept", "application/pem-certificate-chain")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	chain, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("证书下载失败: %s", resp.Status)
	}
	keyDER, err := x509.MarshalECPrivateKey(domKey)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return chain, privPEM, nil
}

// ---------- Cloudflare API v4 客户端（DNS-01 用） ----------

type cfClient struct {
	token string
	http  *http.Client
	base  string
}

func newCFClient(token string) *cfClient {
	return &cfClient{token: token, http: &http.Client{Timeout: 30 * time.Second}, base: cfAPIBase}
}

type cfAPIResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cfClient) do(method, path string, payload any) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var r cfAPIResp
	if json.Unmarshal(b, &r) != nil {
		return nil, fmt.Errorf("Cloudflare 返回无法解析: %s", resp.Status)
	}
	if !r.Success {
		msgs := []string{}
		for _, e := range r.Errors {
			if e.Message != "" {
				msgs = append(msgs, e.Message)
			}
		}
		if len(msgs) == 0 {
			msgs = append(msgs, resp.Status)
		}
		return nil, fmt.Errorf("Cloudflare API 失败: %s", strings.Join(msgs, "; "))
	}
	return r.Result, nil
}

// dns01BaseDomain：通配符 *.example.com 的 DNS-01 落在 example.com 上。
func dns01BaseDomain(domain string) string { return strings.TrimPrefix(domain, "*.") }

// findZoneID：按域名找最长匹配的托管 zone（子域名归属父 zone，如 a.b.example.com → example.com）。
func (c *cfClient) findZoneID(domain string) (string, error) {
	raw, err := c.do("GET", "/zones?per_page=100", nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &zones) != nil {
		return "", errors.New("Cloudflare zone 列表解析失败")
	}
	base := strings.ToLower(dns01BaseDomain(domain))
	best, bestLen := "", -1
	for _, z := range zones {
		zn := strings.ToLower(z.Name)
		if base == zn || strings.HasSuffix(base, "."+zn) {
			if len(zn) > bestLen {
				best, bestLen = z.ID, len(zn)
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("Cloudflare 未找到域名 %s 的托管 zone（域名须托管到 Cloudflare）", domain)
	}
	return best, nil
}

func (c *cfClient) createTXT(zoneID, name, value string) (string, error) {
	raw, err := c.do("POST", "/zones/"+zoneID+"/dns_records", map[string]any{
		"type": "TXT", "name": name, "content": value, "ttl": 120, "proxied": false,
	})
	if err != nil {
		return "", err
	}
	var res struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &res) != nil || res.ID == "" {
		return "", errors.New("Cloudflare 未返回 TXT 记录 ID")
	}
	return res.ID, nil
}

func (c *cfClient) deleteTXT(zoneID, recordID string) error {
	_, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	return err
}

// ---------- DNS-01 计算与生效确认 ----------

// dns01RecordName：验证记录名（通配符与根域名共用一条 _acme-challenge 记录名）。
func dns01RecordName(domain string) string {
	return "_acme-challenge." + dns01BaseDomain(domain)
}

// dns01TXTValue：RFC 8555 DNS-01 值 = base64url(SHA256(token + "." + thumbprint))。
func dns01TXTValue(token, thumbprint string) string {
	sum := sha256.Sum256([]byte(token + "." + thumbprint))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// cfDoHHasTXT：经 Cloudflare DoH 查一条 TXT 是否已生效（值可能被拆成多段引号字符串）。
func cfDoHHasTXT(name, value string) bool {
	req, err := http.NewRequest("GET", cfDoHBase+"?name="+url.QueryEscape(name)+"&type=TXT", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var dr struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.NewDecoder(resp.Body).Decode(&dr) != nil {
		return false
	}
	for _, a := range dr.Answer {
		joined := strings.ReplaceAll(strings.Join(strings.Fields(a.Data), ""), `"`, "")
		if joined == value {
			return true
		}
	}
	return false
}

// cfWaitTXT：轮询 DoH 直到 TXT 生效，超时报错（触发验证前必须确认，否则 CA 查不到就判失败）。
func cfWaitTXT(name, value string) error {
	deadline := time.Now().Add(cfDoHTimeout)
	for {
		if cfDoHHasTXT(name, value) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DNS TXT 记录未生效（超时）：%s，请确认域名已托管到 Cloudflare", name)
		}
		time.Sleep(cfDoHPollEvery)
	}
}
