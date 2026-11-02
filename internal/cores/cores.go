package cores

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CoreDef describes one downloadable core.
type CoreDef struct {
	Name     string // xray | hysteria | mtg | sing-box
	Title    string
	Repo     string                   // owner/repo on GitHub
	BinName  string                   // binary file name inside the asset
	AssetSub func(arch string) string // substring that must appear in the asset name
}

func arch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func Defs() []CoreDef {
	// 退役说明：xray 与 hysteria 已从面板下架（sing-box 接管全部非 mtg 节点），
	// 旧二进制仍留在磁盘上，等用户确认后再删；面板不再提供安装/更新入口，
	// 已装旧核的更新检查也随之下线。
	// 顺序即卡片顺序：sing-box 在上（主内核），MTProto 在下。
	return []CoreDef{
		{Name: "sing-box", Title: "Sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box",
			AssetSub: func(arch string) string { return "linux-" + arch }},
		{Name: "mtg", Title: "MTProto", Repo: "9seconds/mtg", BinName: "mtg",
			AssetSub: func(arch string) string { return "linux-" + arch }},
	}
}

// DetectSingBoxVersion runs `sing-box version` and parses its first line
// ("sing-box version 1.14.4"). Used when the binary was placed by hand
// instead of through the panel installer, so the card never shows a blank
// version for an installed core. 5 秒超时：二进制被换成挂起程序时调用方
// 不再永久阻塞；失败与未安装都返回 ""（调用方只在已装时补版本）。
func DetectSingBoxVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "sing-box" && f[1] == "version" {
			return f[2]
		}
	}
	return ""
}

func DefByName(name string) (CoreDef, bool) {
	for _, d := range Defs() {
		if d.Name == name {
			return d, true
		}
	}
	return CoreDef{}, false
}

// ---- GitHub releases ----

type Release struct {
	Tag    string   `json:"tag"`
	Assets []string `json:"assets"`
}

var (
	relCacheMu sync.Mutex
	relCache   = map[string]struct {
		at time.Time
		rs []Release
	}{}
)

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// githubAPIBase：GitHub API 根地址，测试时可指到本地 httptest 服务。
var githubAPIBase = "https://api.github.com"

func ListReleases(repo string) ([]Release, error) {
	relCacheMu.Lock()
	if c, ok := relCache[repo]; ok && time.Since(c.at) < time.Hour {
		relCacheMu.Unlock()
		return c.rs, nil
	}
	relCacheMu.Unlock()
	return ListReleasesFresh(repo)
}

// ListReleasesFresh 不读缓存，直接拉取并刷新缓存。手动“检查更新”和
// “更新到最新版”必须走它，否则 1 小时缓存会让刚发的新版查不到。
func ListReleasesFresh(repo string) ([]Release, error) {
	url := githubAPIBase + "/repos/" + repo + "/releases?per_page=30"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "sssingbox-panel")
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var gr []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, err
	}
	var out []Release
	for _, r := range gr {
		rel := Release{Tag: r.TagName}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, a.Name+"|"+a.BrowserDownloadURL)
		}
		out = append(out, rel)
	}
	relCacheMu.Lock()
	relCache[repo] = struct {
		at time.Time
		rs []Release
	}{time.Now(), out}
	relCacheMu.Unlock()
	return out, nil
}

func FindAsset(repo, version string) (assetName, url string, err error) {
	def, ok := DefByName(repoNameToCore(repo))
	if !ok {
		return "", "", fmt.Errorf("unknown repo %s", repo)
	}
	rels, err := ListReleases(repo)
	if err != nil {
		return "", "", err
	}
	sub := def.AssetSub(arch())
	for _, r := range rels {
		if version != "" && r.Tag != version && strings.TrimPrefix(r.Tag, "v") != strings.TrimPrefix(version, "v") {
			continue
		}
		for _, a := range r.Assets {
			parts := strings.SplitN(a, "|", 2)
			if len(parts) != 2 {
				continue
			}
			name := parts[0]
			if !strings.Contains(name, sub) {
				continue
			}
			// skip checksum/signature sidecars
			lower := strings.ToLower(name)
			if strings.Contains(lower, "sha256") || strings.Contains(lower, "checksum") || strings.HasSuffix(lower, ".sig") || strings.HasSuffix(lower, ".asc") {
				continue
			}
			// xray: prefer the exact zip (avoid .dgst etc.)
			if def.Name == "xray" && !strings.HasSuffix(lower, ".zip") {
				continue
			}
			if def.Name == "sing-box" && !strings.HasSuffix(lower, ".tar.gz") {
				continue
			}
			return name, parts[1], nil
		}
		if version != "" {
			break
		}
	}
	return "", "", fmt.Errorf("no asset for %s %s (%s)", repo, version, sub)
}

func repoNameToCore(repo string) string {
	for _, d := range Defs() {
		if d.Repo == repo {
			return d.Name
		}
	}
	return ""
}

// ---- install ----

type Manager struct {
	Dir string // data dir; cores live in Dir/cores
	mu  sync.Mutex
	// 安装进度：名字 -> downloading/installing。单独一把锁，
	// 绝不能复用 mu——Install 安装时全程占着 mu，进度查询要是也
	// 等 mu，就永远查不到进行中的阶段，前端按钮又会没反馈。
	progMu sync.Mutex
	prog   map[string]string
}

// PanelRepo：面板自己的 GitHub 仓库。MTG 编译版存货就发在这里的
// Release 里（mtg-v1-stock + mtg-v1-stock.version），老 CPU 机器
// 本地没存货时从这里下载，不再直接报“没有编译版存货”。
const PanelRepo = "pal537/SSSing-box"

func (m *Manager) setProgress(name, phase string) {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	if m.prog == nil {
		m.prog = map[string]string{}
	}
	m.prog[name] = phase
}

func (m *Manager) clearProgress(name string) {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	delete(m.prog, name)
}

// Progress 返回一份当前安装进度的快照，供 /api/cores/progress 用。
func (m *Manager) Progress() map[string]string {
	m.progMu.Lock()
	defer m.progMu.Unlock()
	out := map[string]string{}
	for k, v := range m.prog {
		out[k] = v
	}
	return out
}

func NewManager(dir string) *Manager {
	os.MkdirAll(filepath.Join(dir, "cores"), 0755)
	return &Manager{Dir: dir}
}

func (m *Manager) BinPath(name string) string {
	// 名字只允许是单文件名：调用方万一传进带 / 或 .. 的名字，
	// Join 会直接跳出 cores 目录。Base 之后最多是同名文件，
	// 正常名（sing-box、mtg、mtg-<id>）不受影响。
	return filepath.Join(m.Dir, "cores", filepath.Base(name))
}

// InstallStockMTG installs the compiled mtg build shipped in the data dir
// (cores/mtg-v1-stock + cores/mtg-v1-stock.version). Used on old amd64
// CPUs that cannot run the official mtg release (x86-64-v3 required).
// DownloadStockMTG：从面板自己的 GitHub Release 下载编译版存货
// （mtg-v1-stock + mtg-v1-stock.version）到 cores/，供老 CPU 机器用。
// 本地已有存货时直接返回存货版本，不重复下载。
func (m *Manager) DownloadStockMTG() (string, error) {
	stock := filepath.Join(m.Dir, "cores", "mtg-v1-stock")
	if fi, err := os.Stat(stock); err == nil && !fi.IsDir() && fi.Size() > 0 {
		if verB, err := os.ReadFile(filepath.Join(m.Dir, "cores", "mtg-v1-stock.version")); err == nil && strings.TrimSpace(string(verB)) != "" {
			return strings.TrimSpace(string(verB)), nil
		}
	}
	rels, err := ListReleases(PanelRepo)
	if err != nil {
		return "", err
	}
	var stockURL, verURL string
	for _, r := range rels {
		for _, a := range r.Assets {
			parts := strings.SplitN(a, "|", 2)
			if len(parts) != 2 {
				continue
			}
			if parts[0] == "mtg-v1-stock" {
				stockURL = parts[1]
			}
			if parts[0] == "mtg-v1-stock.version" {
				verURL = parts[1]
			}
		}
		if stockURL != "" {
			break
		}
	}
	if stockURL == "" {
		return "", fmt.Errorf("面板 Release 里没有 mtg-v1-stock 存货")
	}
	dl := func(url, dest string) error {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "sssingbox-panel")
		resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("download %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024*1024+1))
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("下载到空文件")
		}
		return os.WriteFile(dest, data, 0755)
	}
	if err := dl(stockURL, stock+".new"); err != nil {
		return "", err
	}
	if err := os.Rename(stock+".new", stock); err != nil {
		return "", err
	}
	ver := ""
	if verURL != "" {
		verB, err := func() ([]byte, error) {
			req, _ := http.NewRequest("GET", verURL, nil)
			req.Header.Set("User-Agent", "sssingbox-panel")
			resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return nil, fmt.Errorf("download %d", resp.StatusCode)
			}
			return io.ReadAll(io.LimitReader(resp.Body, 1024))
		}()
		if err == nil {
			ver = strings.TrimSpace(string(verB))
		}
	}
	if ver == "" {
		ver = "v2.2.8"
	}
	_ = os.WriteFile(filepath.Join(m.Dir, "cores", "mtg-v1-stock.version"), []byte(ver), 0644)
	return ver, nil
}

// HasStockMTG：cores/ 里有没有可用的编译版存货。
func (m *Manager) HasStockMTG() bool {
	fi, err := os.Stat(filepath.Join(m.Dir, "cores", "mtg-v1-stock"))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func (m *Manager) InstallStockMTG() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setProgress("mtg", "installing")
	defer m.clearProgress("mtg")
	stock := filepath.Join(m.Dir, "cores", "mtg-v1-stock")
	binData, err := os.ReadFile(stock)
	if err != nil {
		return "", fmt.Errorf("没有编译版存货")
	}
	if len(binData) == 0 {
		return "", fmt.Errorf("编译版存货为空")
	}
	verB, err := os.ReadFile(filepath.Join(m.Dir, "cores", "mtg-v1-stock.version"))
	if err != nil {
		return "", fmt.Errorf("没有编译版版本记录")
	}
	ver := strings.TrimSpace(string(verB))
	if ver == "" {
		return "", fmt.Errorf("编译版版本记录为空")
	}
	dest := m.BinPath("mtg")
	if err := os.WriteFile(dest+".new", binData, 0755); err != nil {
		return "", err
	}
	if err := os.Rename(dest+".new", dest); err != nil {
		return "", err
	}
	return ver, nil
}

func (m *Manager) LogPath(name string) string {
	return filepath.Join(m.Dir, "cores", filepath.Base(name)+".log")
}

func (m *Manager) Installed(name string) bool {
	fi, err := os.Stat(m.BinPath(name))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// mtgPinnedReason：本机 MTG 是否钉死为源码编译版。任一条件成立即钉死：
// ① cores 目录里有编译版存货（mtg-v1-stock）；② amd64 CPU 无 AVX2
// （官方 mtg 要求 x86-64-v3，起不来）。ARM 不受影响。
func (m *Manager) mtgPinnedReason() string {
	if fi, err := os.Stat(filepath.Join(m.Dir, "cores", "mtg-v1-stock")); err == nil && !fi.IsDir() && fi.Size() > 0 {
		return "本机有编译版存货"
	}
	if runtime.GOARCH == "amd64" && !cpuHasAVX2() {
		return "本机 CPU 无 AVX2"
	}
	return ""
}

// cpuHasAVX2：读 /proc/cpuinfo 的 flags 行。非 Linux 直接放行（面板只跑
// 在 Linux 服务器上，这里不做跨平台误判）。
func cpuHasAVX2() bool {
	if runtime.GOOS != "linux" {
		return true
	}
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "flags") {
			for _, f := range strings.Fields(strings.TrimPrefix(line[strings.Index(line, ":")+1:], " ")) {
				if f == "avx2" {
					return true
				}
			}
			return false
		}
	}
	return false
}

// smokeTest：新二进制必须能被系统执行。错架构/损坏的下载在
// Start 阶段就报 exec format error；能跑起来（哪怕随后因参数
// 退出非零）即算过——这里只防“装了个跑不起来的文件”。
func smokeTest(bin string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Wait()
	return nil
}

// Install downloads version ("" = latest) of a core and places the binary.
func (m *Manager) Install(name, version string) (string, error) {
	// 安装串行化：两个并发安装会共用 dest.new，互相覆盖。
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setProgress(name, "downloading")
	defer m.clearProgress(name)
	// arch() 把非 arm64 一律当 amd64：386/armv7 等机器会下错
	// 包、装完跑不起来。面板只发这两个架构，先拦住。
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", fmt.Errorf("不支持的架构 %s（只支持 amd64/arm64）", runtime.GOARCH)
	}
	def, ok := DefByName(name)
	if !ok {
		return "", fmt.Errorf("unknown core %s", name)
	}
	// MTG 钉死检查（cores 层防线，不依赖调用方自觉）：本机有编译版存货、
	// 或 amd64 CPU 无 AVX2 时，官方 mtg 根本跑不起来，一律拒绝覆盖。
	if name == "mtg" {
		if reason := m.mtgPinnedReason(); reason != "" {
			return "", fmt.Errorf("MTProto 已钉死为源码编译版（%s），官方版跑不起来，拒绝覆盖", reason)
		}
	}
	assetName, url, err := FindAsset(def.Repo, version)
	if err != nil {
		return "", err
	}
	// resolve version tag from releases
	rels, _ := ListReleases(def.Repo)
	tag := ""
	for _, r := range rels {
		for _, a := range r.Assets {
			if strings.HasPrefix(a, assetName+"|") {
				tag = r.Tag
				break
			}
		}
		if tag != "" {
			break
		}
	}
	if tag == "" {
		tag = version
	}
	tmp, err := os.CreateTemp("", "sssingbox-core-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "sssingbox-panel")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		tmp.Close()
		return "", err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		tmp.Close()
		return "", fmt.Errorf("download %d", resp.StatusCode)
	}
	// 下载封顶 512MB：失控的重定向/错误页面不能把磁盘打满。
	const maxDownload = 512 * 1024 * 1024
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	resp.Body.Close()
	tmp.Close()
	if err != nil {
		return "", err
	}
	if n > maxDownload {
		return "", fmt.Errorf("下载超过 512MB 上限，疑似异常响应")
	}
	// 下载完、解压写入开始：前端按钮从“下载中”翻成“安装中”。
	m.setProgress(name, "installing")

	lower := strings.ToLower(assetName)
	var binData []byte
	switch {
	case strings.HasSuffix(lower, ".zip"):
		binData, err = extractZip(tmpName, def.BinName)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		binData, err = extractTarGz(tmpName, def.BinName)
	default:
		binData, err = os.ReadFile(tmpName)
	}
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", assetName, err)
	}
	if len(binData) == 0 {
		return "", fmt.Errorf("empty binary in %s", assetName)
	}
	dest := m.BinPath(name)
	// 先备份旧二进制：新文件冒烟失败时能原样滚回，不留一个
	// 跑不起来的空壳；.new 残留统一清掉。
	defer os.Remove(dest + ".new")
	var hadPrev bool
	if old, err := os.ReadFile(dest); err == nil && len(old) > 0 {
		if err := os.WriteFile(dest+".prev", old, 0755); err == nil {
			hadPrev = true
		}
	}
	defer os.Remove(dest + ".prev")
	if err := os.WriteFile(dest+".new", binData, 0755); err != nil {
		return "", err
	}
	if err := os.Rename(dest+".new", dest); err != nil {
		return "", err
	}
	probe := []string{"--help"}
	if name == "sing-box" {
		probe = []string{"version"}
	}
	if err := smokeTest(dest, probe); err != nil {
		if hadPrev {
			_ = os.Rename(dest+".prev", dest)
		} else {
			_ = os.Remove(dest)
		}
		return "", fmt.Errorf("新二进制冒烟失败（已回滚）：%w", err)
	}
	// xray: also extract geoip.dat/geosite.dat (best-effort) so the
	// geoip:private routing rule can work; failure here is non-fatal.
	if name == "xray" && strings.HasSuffix(lower, ".zip") {
		m.extractGeoFiles(tmpName)
	}
	return tag, nil
}

// extractGeoFiles pulls geoip.dat / geosite.dat out of an xray zip into cores/.
func (m *Manager) extractGeoFiles(zipPath string) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return
	}
	defer r.Close()
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base != "geoip.dat" && base != "geosite.dat" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		_ = os.WriteFile(filepath.Join(m.Dir, "cores", base), data, 0644)
	}
}

func extractZip(path, binName string) ([]byte, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %s not in zip", binName)
}

func extractTarGz(path, binName string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == binName && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %s not in tarball", binName)
}
