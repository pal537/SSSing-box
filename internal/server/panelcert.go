package server

// 面板域名证书：手动添加 + ACME 在线申请（龟甲同款，简化版）。
// 存放：<数据目录>/certs/panel/<目录>/fullchain.pem + privkey.pem + meta.json；
// ACME 目录名取首域名（通配符 *.example.com 记作 wildcard.example.com）；
// 手动证书目录名取用户填的名字（清洗后）。账号密钥与 CF Token 也放本目录，0600。
// 安全红线：面板默认永远走 HTTP；只有用户在设置里选了证书并启用 HTTPS，
// 监听才提供 TLS——且是双协议：TLS 与明文同端口，http://IP:端口 照常能打开
// （只当备用入口，登录信息不加密），日常请用 https 域名。

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// certTokenMask：前端 Token 已保存时的占位；提交该值表示“沿用已存 Token”。
const certTokenMask = "••••••••"

// panelCertMeta：每张证书目录里的 meta.json。
type panelCertMeta struct {
	Name      string   `json:"name"`       // 显示名（备注，空 = 首域名）
	Domains   []string `json:"domains"`    // 域名组
	Method    string   `json:"method"`     // http-01 | dns-01 | manual
	AutoRenew bool     `json:"auto_renew"` // ACME 证书默认 true；手动证书 false
	Source    string   `json:"source"`     // acme | manual
}

// panelCertInfo：列表接口返回的视图。
type panelCertInfo struct {
	ID        string   `json:"id"`      // 目录名
	Name      string   `json:"name"`    // 显示名
	Domains   []string `json:"domains"` // 证书实际域名（SAN，取不到时用 meta）
	Method    string   `json:"method"`
	Source    string   `json:"source"`
	AutoRenew bool     `json:"auto_renew"`
	ExpiresAt string   `json:"expires_at"` // RFC3339，取不到为空
	DaysLeft  int      `json:"days_left"`  // 负数 = 已过期，-9999 = 未知
	Selected  bool     `json:"selected"`   // 是否面板当前选用的证书
}

// panelCertJob：在线申请任务状态（内存态，面板重启即清零）。
type panelCertJob struct {
	Running bool     `json:"running"`
	Domains []string `json:"domains"`
	Method  string   `json:"method"`
	LastOK  string   `json:"last_ok"`
	LastErr string   `json:"last_err"`
}

type panelCertManager struct {
	dir         string
	getSetting  func(string) string
	setSetting  func(string, string) error
	restartFn   func()
	mu          sync.Mutex
	job         panelCertJob
	renewalOnce sync.Once
}

func newPanelCertManager(dir string, getSetting func(string) string, setSetting func(string, string) error) *panelCertManager {
	return &panelCertManager{dir: dir, getSetting: getSetting, setSetting: setSetting}
}

func (m *panelCertManager) certsDir() string {
	_ = os.MkdirAll(m.dir, 0755)
	return m.dir
}

func (m *panelCertManager) accountKeyPath() string {
	return filepath.Join(m.certsDir(), "acme-account.key")
}
func (m *panelCertManager) cfTokenPath() string { return filepath.Join(m.certsDir(), "cf-token") }

func (m *panelCertManager) loadCFToken() string {
	b, err := os.ReadFile(m.cfTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (m *panelCertManager) saveCFToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		_ = os.Remove(m.cfTokenPath())
		return nil
	}
	_ = os.MkdirAll(m.dir, 0755)
	return os.WriteFile(m.cfTokenPath(), []byte(tok), 0600)
}

func (m *panelCertManager) cfTokenConfigured() bool { return m.loadCFToken() != "" }

// resolveCFToken：显式新 Token 优先（掩码占位 = 未改动，用已存的），否则用已存 Token。
func resolveCFToken(explicit, stored string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" && explicit != certTokenMask {
		return explicit
	}
	return strings.TrimSpace(stored)
}

// ---------- 域名归一与申请解析（纯函数，可单测） ----------

// normalizeCertDomain：小写、去首尾空白与末尾点、去 http(s):// 前缀；
// 通配符只认 "*." 开头；拒绝 IP、空标签、超长标签与非法字符。
func normalizeCertDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("域名不能为空")
	}
	if strings.Contains(d, ":") || strings.Contains(d, "/") {
		return "", errors.New("域名格式无效: " + in)
	}
	base := strings.TrimPrefix(d, "*.")
	if base == "" || strings.Contains(base, "*") {
		return "", errors.New("域名格式无效: " + in)
	}
	if net.ParseIP(base) != nil {
		return "", errors.New("不支持 IP 地址证书: " + in)
	}
	if len(d) > 253 {
		return "", errors.New("域名过长: " + in)
	}
	for _, label := range strings.Split(base, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("域名格式无效: " + in)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("域名格式无效: " + in)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("域名格式无效: " + in)
		}
	}
	if !strings.Contains(base, ".") {
		return "", errors.New("域名须为完整域名（带点）: " + in)
	}
	return d, nil
}

// normalizeCertDomains：多行域名归一去重（保序），最多 100 个。
func normalizeCertDomains(raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range raw {
		nd, err := normalizeCertDomain(d)
		if err != nil {
			return nil, err
		}
		if !seen[nd] {
			seen[nd] = true
			out = append(out, nd)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("请填写域名")
	}
	if len(out) > 100 {
		return nil, errors.New("域名过多（最多 100 个）")
	}
	return out, nil
}

// resolveCertApply：申请入参解析。自动：80 空闲走 HTTP-01，80 被占走 DNS-01；
// 通配符只能 DNS-01；显式 HTTP-01 但 80 被占时报错；DNS-01 无 Token 时报错。
func resolveCertApply(domainsIn []string, domainSingle, method, cfToken, storedToken string, port80Free bool) (domains []string, resolvedMethod, token string, err error) {
	raw := append([]string{}, domainsIn...)
	if len(raw) == 0 && domainSingle != "" {
		raw = []string{domainSingle}
	}
	domains, err = normalizeCertDomains(raw)
	if err != nil {
		return nil, "", "", err
	}
	hasWildcard := false
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			hasWildcard = true
		}
	}
	m := strings.ToLower(strings.TrimSpace(method))
	if m == "" {
		m = "auto"
	}
	if m != "auto" && m != "http-01" && m != "dns-01" {
		return nil, "", "", errors.New("未知的验证方式")
	}
	switch m {
	case "http-01":
		if hasWildcard {
			return nil, "", "", errors.New("通配符域名只能用 DNS-01 验证")
		}
		if !port80Free {
			return nil, "", "", errors.New("80 端口被占用，HTTP-01 无法验证：请改选自动（自动走 DNS-01）或 DNS-01，或先释放 80 端口")
		}
		return domains, "http-01", "", nil
	case "dns-01":
		tok := resolveCFToken(cfToken, storedToken)
		if tok == "" {
			return nil, "", "", errors.New("DNS-01 需要 Cloudflare API Token：请填写 Token 后再申请")
		}
		return domains, "dns-01", tok, nil
	default: // auto
		if hasWildcard {
			tok := resolveCFToken(cfToken, storedToken)
			if tok == "" {
				return nil, "", "", errors.New("通配符域名只能用 DNS-01 验证，请填写 Cloudflare API Token 后再申请")
			}
			return domains, "dns-01", tok, nil
		}
		if port80Free {
			return domains, "http-01", "", nil
		}
		tok := resolveCFToken(cfToken, storedToken)
		if tok == "" {
			return nil, "", "", errors.New("80 端口被占用，已自动切换到 DNS-01，但未填写 Cloudflare API Token：请填写 Token 后再申请")
		}
		return domains, "dns-01", tok, nil
	}
}

// ---------- 证书读写 ----------

// certDirForDomains：ACME 目录名取首域名；通配符 *.example.com 记作 wildcard.example.com。
func certDirForDomains(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return strings.Replace(domains[0], "*.", "wildcard.", 1)
}

// sanitizeCertDirName：手动证书名清洗成目录名；非法字符换 -，结果为空或 . / .. 时报错。
func sanitizeCertDirName(name string) (string, error) {
	var b strings.Builder
	for _, c := range strings.TrimSpace(name) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." || len(out) > 128 {
		return "", errors.New("证书名无效")
	}
	return out, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *panelCertManager) writeCert(dirName string, fullchainPEM, privkeyPEM []byte, meta panelCertMeta) error {
	dir := filepath.Join(m.certsDir(), dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "fullchain.pem"), fullchainPEM, 0644); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "privkey.pem"), privkeyPEM, 0600); err != nil {
		return err
	}
	mb, _ := json.Marshal(meta)
	return writeFileAtomic(filepath.Join(dir, "meta.json"), mb, 0644)
}

func (m *panelCertManager) readMeta(dirName string) (panelCertMeta, bool) {
	b, err := os.ReadFile(filepath.Join(m.dir, dirName, "meta.json"))
	if err != nil {
		return panelCertMeta{}, false
	}
	var meta panelCertMeta
	if json.Unmarshal(b, &meta) != nil {
		return panelCertMeta{}, false
	}
	return meta, true
}

// parseLeafCert：取 fullchain 里第一张证书（叶证书）的域名与到期时间。
func parseLeafCert(fullchainPEM []byte) (domains []string, expiresAt time.Time, err error) {
	block, _ := pem.Decode(fullchainPEM)
	if block == nil {
		return nil, time.Time{}, errors.New("证书内容无法解析")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	domains = append([]string{}, cert.DNSNames...)
	if len(domains) == 0 && cert.Subject.CommonName != "" {
		domains = []string{cert.Subject.CommonName}
	}
	return domains, cert.NotAfter, nil
}

// certNeedsRenewal：到期前 30 天内（含已过期）即需续期；到期时间读不到也续。
func certNeedsRenewal(expiresAt time.Time, now time.Time) bool {
	if expiresAt.IsZero() {
		return true
	}
	return time.Until(expiresAt) < 30*24*time.Hour
}

// listCerts：扫描证书目录，只认配齐 fullchain.pem + privkey.pem 且能解析的目录。
func (m *panelCertManager) listCerts() []panelCertInfo {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	selected := ""
	if m.getSetting != nil {
		selected = m.getSetting("panel_cert")
	}
	out := []panelCertInfo{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(m.dir, e.Name())
		chain, err1 := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		key, err2 := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		if err1 != nil || err2 != nil {
			continue
		}
		if _, err := tls.X509KeyPair(chain, key); err != nil {
			continue
		}
		domains, expiresAt, err := parseLeafCert(chain)
		if err != nil {
			continue
		}
		meta, _ := m.readMeta(e.Name())
		name := meta.Name
		if name == "" {
			name = e.Name()
		}
		method := meta.Method
		source := meta.Source
		if source == "" {
			source = "manual"
		}
		if len(domains) == 0 {
			domains = meta.Domains
		}
		info := panelCertInfo{
			ID: e.Name(), Name: name, Domains: domains, Method: method, Source: source,
			AutoRenew: meta.AutoRenew, Selected: e.Name() == selected, DaysLeft: -9999,
		}
		if !expiresAt.IsZero() {
			info.ExpiresAt = expiresAt.Format(time.RFC3339)
			info.DaysLeft = int(time.Until(expiresAt).Hours() / 24)
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// storeManual：手动上传成对 .crt + .key，校验密钥对匹配后落盘。
// name 为空时用叶证书的第一域名；同名目录已存在则拒绝（防覆盖）。
func (m *panelCertManager) storeManual(name string, certPEM, keyPEM []byte) (panelCertInfo, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return panelCertInfo{}, errors.New("证书与私钥都要上传")
	}
	if len(certPEM) > 4<<20 || len(keyPEM) > 4<<20 {
		return panelCertInfo{}, errors.New("证书或私钥文件过大（单文件限 4MB）")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return panelCertInfo{}, errors.New("证书与私钥不匹配或格式不对: " + err.Error())
	}
	domains, expiresAt, err := parseLeafCert(certPEM)
	if err != nil {
		return panelCertInfo{}, errors.New("证书解析失败: " + err.Error())
	}
	if strings.TrimSpace(name) == "" {
		if len(domains) > 0 {
			name = domains[0]
		} else {
			return panelCertInfo{}, errors.New("请填写证书名（证书里也读不到域名）")
		}
	}
	dirName, err := sanitizeCertDirName(name)
	if err != nil {
		return panelCertInfo{}, err
	}
	if _, err := os.Stat(filepath.Join(m.certsDir(), dirName)); err == nil {
		return panelCertInfo{}, errors.New("同名证书已存在: " + dirName)
	}
	meta := panelCertMeta{Name: name, Domains: domains, Method: "manual", AutoRenew: false, Source: "manual"}
	if err := m.writeCert(dirName, certPEM, keyPEM, meta); err != nil {
		return panelCertInfo{}, err
	}
	info := panelCertInfo{ID: dirName, Name: name, Domains: domains, Method: "manual", Source: "manual"}
	if !expiresAt.IsZero() {
		info.ExpiresAt = expiresAt.Format(time.RFC3339)
		info.DaysLeft = int(time.Until(expiresAt).Hours() / 24)
	}
	return info, nil
}

// ---------- HTTP-01 临时应答 ----------

// http01Server：订单期间临时绑 :80 的挑战应答服务；订单结束即停，不常驻。
type http01Server struct {
	mu         sync.Mutex
	challenges map[string]string
	ln         net.Listener
	srv        *http.Server
}

func newHTTP01Server() *http01Server {
	h := &http01Server{challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		h.mu.Lock()
		keyAuth, ok := h.challenges[token]
		h.mu.Unlock()
		if !ok || token == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, keyAuth)
	})
	h.srv = &http.Server{Handler: mux}
	return h
}

func (h *http01Server) Start() error {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("80 端口绑定失败（HTTP-01 无法验证，请改用 DNS-01 或释放 80 端口）: %w", err)
	}
	h.ln = ln
	go func() { _ = h.srv.Serve(ln) }()
	return nil
}

func (h *http01Server) Stop() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
}

func (h *http01Server) Register(token, keyAuth string) {
	h.mu.Lock()
	h.challenges[token] = keyAuth
	h.mu.Unlock()
}

func (h *http01Server) Clear(token string) {
	h.mu.Lock()
	delete(h.challenges, token)
	h.mu.Unlock()
}

// port80Free：试绑 :80 探活（只探不占，真正下单时再绑；竞态下单时绑定失败会明说）。
func port80Free() bool {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// ---------- 申请任务与续期 ----------

func (m *panelCertManager) jobSnapshot() panelCertJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.job
}

// claimJob：认领任务；已有任务在跑时返回 false。
func (m *panelCertManager) claimJob(domains []string, method string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job.Running {
		return false
	}
	m.job.Running = true
	m.job.Domains = domains
	m.job.Method = method
	m.job.LastErr = ""
	return true
}

func (m *panelCertManager) finishJob(ok bool, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.job.Running = false
	if ok {
		m.job.LastOK = time.Now().Format("2006-01-02 15:04")
		m.job.LastErr = ""
	} else {
		m.job.LastErr = errMsg
	}
}

// releaseJob：续期检查结束只释放任务，不改写手动任务的最后成功/失败记录。
func (m *panelCertManager) releaseJob() {
	m.mu.Lock()
	m.job.Running = false
	m.mu.Unlock()
}

// runOrderWork：一次下单实干（调用方须已认领任务）。HTTP-01 时先绑 :80，
// 订单结束即停；写盘成功后按规则自动选中证书、按需重启面板监听。
func (m *panelCertManager) runOrderWork(domains []string, method, cfToken, name string) error {
	var http01 *http01Server
	if method == "http-01" {
		http01 = newHTTP01Server()
		if err := http01.Start(); err != nil {
			return err
		}
		defer http01.Stop()
	}
	client, err := newAcmeClient(m.accountKeyPath())
	if err != nil {
		return err
	}
	chain, priv, err := client.orderCert(domains, method, cfToken, http01)
	if err != nil {
		return err
	}
	dirName := certDirForDomains(domains)
	if dirName == "" {
		return errors.New("域名为空，无法确定证书目录")
	}
	display := strings.TrimSpace(name)
	if display == "" {
		display = domains[0]
	}
	meta := panelCertMeta{Name: display, Domains: domains, Method: method, AutoRenew: true, Source: "acme"}
	if err := m.writeCert(dirName, chain, priv, meta); err != nil {
		return err
	}
	// 未选证书时自动选中新证（一次点申请 + 启用 HTTPS 即可用）；
	// 正在用这张证且 HTTPS 开着时，重启监听换上新证。
	if m.getSetting != nil && m.setSetting != nil {
		if m.getSetting("panel_cert") == "" {
			_ = m.setSetting("panel_cert", dirName)
		}
		if m.getSetting("panel_https") == "1" && m.getSetting("panel_cert") == dirName && m.restartFn != nil {
			m.restartFn()
		}
	}
	return nil
}

// startOrder：异步下单入口；已有任务在跑时直接报错。
func (m *panelCertManager) startOrder(domains []string, method, cfToken, name string) error {
	if !m.claimJob(domains, method) {
		return errors.New("已有证书申请在进行中，请稍后再试")
	}
	go func() {
		err := m.runOrderWork(domains, method, cfToken, name)
		m.finishJob(err == nil, func() string {
			if err == nil {
				return ""
			}
			return err.Error()
		}())
	}()
	return nil
}

// renewalCheck：跑一轮续期检查——只续 source=acme 且自动续签开着、
// 到期前 30 天内（或读不到到期时间）的证书；按 meta 原样沿用域名组与验证方式。
// 续期中途失败只记日志，下个周期重试；有手动任务在跑时整轮跳过。
func (m *panelCertManager) renewalCheck() {
	if !m.claimJob(nil, "renewal") {
		return
	}
	defer m.releaseJob()
	for _, info := range m.listCerts() {
		meta, ok := m.readMeta(info.ID)
		if !ok || meta.Source != "acme" || !meta.AutoRenew {
			continue
		}
		var expiresAt time.Time
		if info.ExpiresAt != "" {
			expiresAt, _ = time.Parse(time.RFC3339, info.ExpiresAt)
		}
		if !certNeedsRenewal(expiresAt, time.Now()) {
			continue
		}
		tok := ""
		if meta.Method == "dns-01" {
			tok = m.loadCFToken()
			if tok == "" {
				log.Printf("证书续期跳过（DNS-01 缺 Token）：%s", info.ID)
				continue
			}
		}
		domains := meta.Domains
		if len(domains) == 0 {
			domains = info.Domains
		}
		if len(domains) == 0 {
			continue
		}
		// 续期沿用原验证方式；HTTP-01 续期时 80 被占则本次跳过，下个周期再试。
		method := meta.Method
		if method == "http-01" && !port80Free() {
			log.Printf("证书续期跳过（80 端口被占，HTTP-01 无法验证）：%s", info.ID)
			continue
		}
		m.mu.Lock()
		m.job.Domains = domains
		m.job.Method = method
		m.mu.Unlock()
		if err := m.runOrderWork(domains, method, tok, meta.Name); err != nil {
			log.Printf("证书续期失败（%s）：%v", info.ID, err)
		}
	}
}

// renewalLoop：面板启动时立即检查一次，之后每 6 小时检查一次。
func (m *panelCertManager) renewalLoop() {
	m.renewalCheck()
	for {
		time.Sleep(6 * time.Hour)
		m.renewalCheck()
	}
}

// ---------- 面板 HTTPS 门控（供 Server.Serve 与接口共用） ----------

// panelTLSConfig：当前面板 HTTPS 配置。默认关闭；只有设置里 panel_https=1
// 且选中的证书真实存在、密钥对能解析，才返回启用。任何一项不满足都回落 HTTP，
// 绝不因证书问题让面板打不开。
func (m *panelCertManager) panelTLSConfig() (enabled bool, dirName, certFile, keyFile string) {
	if m.getSetting == nil {
		return false, "", "", ""
	}
	if m.getSetting("panel_https") != "1" {
		return false, "", "", ""
	}
	dirName = m.getSetting("panel_cert")
	if dirName == "" || strings.Contains(dirName, "/") || strings.Contains(dirName, "..") {
		log.Printf("面板 HTTPS 配置异常（证书未选或非法），回落 HTTP")
		return false, "", "", ""
	}
	certFile = filepath.Join(m.dir, dirName, "fullchain.pem")
	keyFile = filepath.Join(m.dir, dirName, "privkey.pem")
	chain, err1 := os.ReadFile(certFile)
	key, err2 := os.ReadFile(keyFile)
	if err1 != nil || err2 != nil {
		log.Printf("面板 HTTPS 证书文件缺失（%s），回落 HTTP", dirName)
		return false, "", "", ""
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		log.Printf("面板 HTTPS 证书密钥对无效（%s），回落 HTTP：%v", dirName, err)
		return false, "", "", ""
	}
	// 过期证书也不硬撑：重启后同样回落 HTTP，面板总能用 http 打开再修。
	if _, expiresAt, err := parseLeafCert(chain); err == nil && time.Now().After(expiresAt) {
		log.Printf("面板 HTTPS 证书已过期（%s），回落 HTTP", dirName)
		return false, "", "", ""
	}
	return true, dirName, certFile, keyFile
}

// certNotExpired：证书叶到期时间是否在未来（启用 HTTPS 时校验用）。
func (m *panelCertManager) certNotExpired(dirName string) (bool, error) {
	chain, err := os.ReadFile(filepath.Join(m.dir, dirName, "fullchain.pem"))
	if err != nil {
		return false, err
	}
	_, expiresAt, err := parseLeafCert(chain)
	if err != nil {
		return false, err
	}
	return expiresAt.After(time.Now()), nil
}

// ---------- 设置页接口（全部走 /api/settings/，已登录 + 写锁） ----------

func (s *Server) handlePanelCerts(w http.ResponseWriter, r *http.Request) {
	okJSON(w, map[string]interface{}{
		"certs":               s.certs.listCerts(),
		"panel_cert":          s.app.Store.GetSetting("panel_cert"),
		"panel_https":         s.app.Store.GetSetting("panel_https") == "1",
		"cf_token_configured": s.certs.cfTokenConfigured(),
	})
}

func (s *Server) handlePanelCertManual(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		errJSON(w, 400, "表单解析失败: "+err.Error())
		return
	}
	name := r.FormValue("name")
	readPart := func(field string) ([]byte, error) {
		f, _, err := r.FormFile(field)
		if err != nil {
			return nil, errors.New("请同时上传证书与私钥文件")
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, (4<<20)+1))
	}
	certPEM, err := readPart("cert")
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	keyPEM, err := readPart("key")
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	info, err := s.certs.storeManual(name, certPEM, keyPEM)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	// 未选证书时自动选中新证，启用 HTTPS 时不用再选一次。
	if s.app.Store.GetSetting("panel_cert") == "" {
		_ = s.app.Store.SetSetting("panel_cert", info.ID)
	}
	okJSON(w, map[string]interface{}{"cert": info})
}

func (s *Server) handlePanelCertAcme(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain  string   `json:"domain"`
		Domains []string `json:"domains"`
		Method  string   `json:"method"`
		CFToken string   `json:"cfToken"`
		Name    string   `json:"name"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	domains, method, token, err := resolveCertApply(body.Domains, body.Domain, body.Method, body.CFToken, s.certs.loadCFToken(), port80Free())
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	// 新 Token 先落盘（只存服务器本地）：续期要用它；掩码占位表示沿用已存 Token。
	if t := strings.TrimSpace(body.CFToken); t != "" && t != certTokenMask {
		if err := s.certs.saveCFToken(t); err != nil {
			errJSON(w, 500, "Token 保存失败: "+err.Error())
			return
		}
	}
	if err := s.certs.startOrder(domains, method, token, body.Name); err != nil {
		errJSON(w, 409, err.Error())
		return
	}
	okJSON(w, map[string]interface{}{"started": true, "method": method, "domains": domains})
}

func (s *Server) handlePanelCertAcmeStatus(w http.ResponseWriter, r *http.Request) {
	okJSON(w, s.certs.jobSnapshot())
}

func (s *Server) handlePanelHTTPS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool   `json:"enabled"`
		Cert    string `json:"cert"`
	}
	if err := s.readJSON(r, &body); err != nil {
		errJSON(w, 400, "请求格式不对")
		return
	}
	if body.Enabled {
		if strings.TrimSpace(body.Cert) == "" {
			errJSON(w, 400, "请先选择一张证书")
			return
		}
		found := false
		for _, c := range s.certs.listCerts() {
			if c.ID == body.Cert {
				found = true
				break
			}
		}
		if !found {
			errJSON(w, 400, "证书不存在或已损坏")
			return
		}
		ok, err := s.certs.certNotExpired(body.Cert)
		if err != nil || !ok {
			errJSON(w, 400, "证书已过期：请先续期或更换证书再启用 HTTPS")
			return
		}
		if err := s.app.Store.SetSetting("panel_https", "1"); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
		if err := s.app.Store.SetSetting("panel_cert", body.Cert); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
	} else {
		if err := s.app.Store.SetSetting("panel_https", ""); err != nil {
			errJSON(w, 500, err.Error())
			return
		}
	}
	// 只有实际服务方式或证书变了才重启监听；无变化时不动，避免无故断连。
	// 重启晚 300ms 执行：先把本次响应完整发回浏览器，再断监听——
	// 否则 Close 会掐断正在回包的连接，前端会看到一次“启用失败”（实际已生效）。
	tlsNow, certNow := s.servingState()
	restarted := false
	if body.Enabled != tlsNow || (body.Enabled && body.Cert != certNow) {
		go func() {
			time.Sleep(300 * time.Millisecond)
			s.RequestRestart()
		}()
		restarted = true
	}
	okJSON(w, map[string]interface{}{
		"enabled":   body.Enabled,
		"cert":      s.app.Store.GetSetting("panel_cert"),
		"restarted": restarted,
	})
}

// ---------- 监听循环：默认 HTTP，启用 HTTPS 后切 TLS ----------

// servingState：Serve 循环当前实际服务状态（读时加锁，防与监听循环竞态）。
func (s *Server) servingState() (tlsOn bool, cert string) {
	s.serveMu.Lock()
	defer s.serveMu.Unlock()
	return s.servingTLS, s.servingCert
}

// RequestRestart：通知 Serve 循环重启监听。只发信号不够：正在跑的
// ListenAndServe 会一直阻塞，必须先 Close 当前监听让它返回，循环才读得到信号。
// （信号非阻塞；已在排队时丢弃重复信号，一次重启覆盖多次配置变更。）
func (s *Server) RequestRestart() {
	s.serveMu.Lock()
	srv := s.curSrv
	s.serveMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	select {
	case s.restartCh <- struct{}{}:
	default:
	}
}

// Shutdown：关闭当前监听，Serve 循环随即退出（main.go 信号处理用）。
func (s *Server) Shutdown() {
	s.serveMu.Lock()
	s.stopped = true
	srv := s.curSrv
	s.serveMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// Serve：监听循环。每次迭代按当前设置决定 HTTP 还是 TLS；
// 证书缺失/损坏时 panelTLSConfig 回落 HTTP 并打日志，面板永远不因此打不开；
// TLS 监听失败时同样回落本轮 HTTP（下轮继续按设置尝试），绝不空转死循环。
// peekedConn：Accept 时已偷看首字节的连接。先吐出偷看的字节，再接底层流。
type peekedConn struct {
	net.Conn
	peeked []byte
	off    int
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if c.off < len(c.peeked) {
		n := copy(b, c.peeked[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// dualListener：同一端口双协议。首字节 0x16（TLS ClientHello）→ TLS 连接，
// 其余（GET/POST 等明文方法首字母）→ 明文连接。这样 http://IP:端口 与
// https://域名:端口 能共用一个面板端口，IP 入口不再因“明文打 TLS 端口”而复位。
type dualListener struct {
	net.Listener
	tlsCfg *tls.Config
}

func (l *dualListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// 只偷看 1 字节：连上不发数据的客户端 5 秒后断开，不占 Accept 槽位。
		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		one := make([]byte, 1)
		if _, err := io.ReadFull(raw, one); err != nil {
			raw.Close()
			continue
		}
		_ = raw.SetReadDeadline(time.Time{})
		pc := &peekedConn{Conn: raw, peeked: one}
		if one[0] == 0x16 {
			return tls.Server(pc, l.tlsCfg), nil
		}
		return pc, nil
	}
}

func (s *Server) Serve(addr string, handler http.Handler) {
	for {
		enabled, dirName, certFile, keyFile := s.certs.panelTLSConfig()
		srv := &http.Server{Addr: addr, Handler: handler}
		s.serveMu.Lock()
		if s.stopped {
			s.serveMu.Unlock()
			return
		}
		s.curSrv = srv
		s.serveMu.Unlock()
		var err error
		if enabled {
			s.serveMu.Lock()
			s.servingTLS, s.servingCert = true, dirName
			s.serveMu.Unlock()
			cert, err1 := tls.LoadX509KeyPair(certFile, keyFile)
			if err1 != nil {
				log.Printf("面板证书加载失败（%s），3 秒后重试：%v", dirName, err1)
				select {
				case <-s.restartCh:
				case <-time.After(3 * time.Second):
				}
				continue
			}
			ln, err2 := net.Listen("tcp", addr)
			if err2 != nil {
				log.Printf("面板监听失败（%v），3 秒后重试", err2)
				select {
				case <-s.restartCh:
				case <-time.After(3 * time.Second):
				}
				continue
			}
			log.Printf("面板监听 %s（HTTPS + HTTP 同端口，证书 %s）", addr, dirName)
			err = srv.Serve(&dualListener{Listener: ln, tlsCfg: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}})
		} else {
			s.serveMu.Lock()
			s.servingTLS, s.servingCert = false, ""
			s.serveMu.Unlock()
			log.Printf("面板监听 %s（HTTP）", addr)
			err = srv.ListenAndServe()
		}
		s.serveMu.Lock()
		stopped := s.stopped
		s.serveMu.Unlock()
		if stopped {
			return
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("面板监听异常（%v），等待重启信号或 3 秒后重试", err)
		}
		// 重启信号到就立刻重起；否则 3 秒后重试（监听失败时不空转）。
		select {
		case <-s.restartCh:
		case <-time.After(3 * time.Second):
		}
	}
}
