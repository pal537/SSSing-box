package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sssingbox/internal/cores"
	"sssingbox/internal/version"
)

// ---------- 面板在线更新 ----------
// 仿龟甲方式：自动检查、手动更新。
// 检查：面板启动后后台每 12 小时查一次 GitHub Release，最新版和检查时间
//   存进 settings；打开面板设置时也会查一次。更新永远是用户手动点，
//   绝不自动装。
// 更新：下载对应架构的 Release 包 → 校验 sha256 → 解包 → 冒烟测新二进制
//   的 version → 备份旧二进制 → 原子替换 → 重启服务。重启只在标准安装
//   路径（/usr/local/bin/sssingbox）下自动做：演示面板等手动起的进程
//   不自动重启，免得误重启生产服务，返回 restart_required 让用户手动重启。

func (s *Server) setUpdPhase(p string) {
	s.updMu.Lock()
	s.updPhase = p
	s.updMu.Unlock()
}

func (s *Server) getUpdPhase() string {
	s.updMu.Lock()
	defer s.updMu.Unlock()
	return s.updPhase
}

func (s *Server) startPanelUpdateChecker() {
	go func() {
		time.Sleep(5 * time.Minute)
		for {
			_, _ = s.checkPanelUpdate()
			time.Sleep(12 * time.Hour)
		}
	}()
}

func normTag(t string) string { return strings.TrimPrefix(t, "v") }

// checkPanelUpdate 查面板最新版，存进 settings，返回最新 tag。
func (s *Server) checkPanelUpdate() (string, error) {
	rels, err := cores.ListReleases(cores.PanelRepo)
	if err != nil {
		return "", err
	}
	if len(rels) == 0 {
		return "", fmt.Errorf("没有找到 Release")
	}
	latest := rels[0].Tag
	if latest == "" {
		return "", fmt.Errorf("最新 Release 没有 tag")
	}
	_ = s.app.Store.SetSetting("panel_latest", latest)
	_ = s.app.Store.SetSetting("panel_latest_at", time.Now().Format("2006-01-02 15:04"))
	return latest, nil
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	latest, err := s.checkPanelUpdate()
	if err != nil {
		// 查不到就回落到上次存的值，别直接报错让设置页空着。
		latest = s.app.Store.GetSetting("panel_latest")
		if latest == "" {
			errJSON(w, 500, "检查失败："+err.Error())
			return
		}
	}
	current := version.Version
	hasUpdate := current != "dev" && latest != "" && normTag(latest) != normTag(current)
	okJSON(w, map[string]interface{}{
		"current":    current,
		"latest":     latest,
		"has_update": hasUpdate,
		"checked_at": s.app.Store.GetSetting("panel_latest_at"),
	})
}

func (s *Server) handleUpdateProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	okJSON(w, map[string]interface{}{"phase": s.getUpdPhase()})
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	current := version.Version
	if current == "dev" {
		errJSON(w, 400, "开发版不走在线更新，请用安装器重装")
		return
	}
	latest, err := s.checkPanelUpdate()
	if err != nil {
		errJSON(w, 500, "检查最新版失败："+err.Error())
		return
	}
	if normTag(latest) == normTag(current) {
		errJSON(w, 400, "已是最新版")
		return
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		errJSON(w, 400, fmt.Sprintf("不支持的架构 %s（只支持 amd64/arm64）", runtime.GOARCH))
		return
	}
	asset := "sssingbox-linux-" + runtime.GOARCH + ".tar.gz"
	rels, err := cores.ListReleases(cores.PanelRepo)
	if err != nil {
		errJSON(w, 500, "获取 Release 失败："+err.Error())
		return
	}
	var assetURL, shaURL string
	for _, rel := range rels {
		if rel.Tag != latest {
			continue
		}
		for _, a := range rel.Assets {
			parts := strings.SplitN(a, "|", 2)
			if len(parts) != 2 {
				continue
			}
			if parts[0] == asset {
				assetURL = parts[1]
			}
			if parts[0] == asset+".sha256" {
				shaURL = parts[1]
			}
		}
		break
	}
	if assetURL == "" {
		errJSON(w, 500, "最新 Release 里没有 "+asset)
		return
	}
	s.setUpdPhase("downloading")
	defer s.setUpdPhase("")
	dl := func(url string, limit int64) ([]byte, error) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "sssingbox-panel")
		resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("download %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, limit+1))
	}
	pkg, err := dl(assetURL, 512*1024*1024)
	if err != nil {
		errJSON(w, 500, "下载失败："+err.Error())
		return
	}
	if shaURL != "" {
		shaB, err := dl(shaURL, 64*1024)
		if err != nil {
			errJSON(w, 500, "下载校验文件失败："+err.Error())
			return
		}
		want := strings.Fields(string(shaB))
		if len(want) == 0 {
			errJSON(w, 500, "校验文件为空")
			return
		}
		sum := sha256.Sum256(pkg)
		if hex.EncodeToString(sum[:]) != strings.ToLower(want[0]) {
			errJSON(w, 500, "sha256 校验失败，包可能损坏，已放弃更新")
			return
		}
	}
	s.setUpdPhase("installing")
	// 解包：tar 里只有一个 sssingbox 二进制。
	newBin, err := extractPanelBinary(pkg)
	if err != nil {
		errJSON(w, 500, "解包失败："+err.Error())
		return
	}
	defer os.Remove(newBin)
	// 冒烟：新二进制必须能跑且报的就是最新版，否则不替换。
	out, err := exec.Command(newBin, "version").Output()
	if err != nil || !strings.Contains(string(out), normTag(latest)) {
		errJSON(w, 500, fmt.Sprintf("新二进制冒烟失败（已放弃更新）：%v，输出：%s", err, strings.TrimSpace(string(out))))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		errJSON(w, 500, "取当前二进制路径失败："+err.Error())
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	oldData, err := os.ReadFile(exe)
	if err != nil {
		errJSON(w, 500, "读旧二进制失败："+err.Error())
		return
	}
	bak := exe + ".bak-" + time.Now().Format("20060102150405")
	if err := os.WriteFile(bak, oldData, 0755); err != nil {
		errJSON(w, 500, "备份旧二进制失败："+err.Error())
		return
	}
	newData, err := os.ReadFile(newBin)
	if err != nil {
		errJSON(w, 500, "读新二进制失败："+err.Error())
		return
	}
	if err := os.WriteFile(exe+".new", newData, 0755); err != nil {
		errJSON(w, 500, "写新二进制失败："+err.Error())
		return
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		errJSON(w, 500, "替换二进制失败："+err.Error())
		return
	}
	// 标准安装路径才自动重启服务；演示/手动起的面板不自动重启，
	// 否则可能误重启同一台机上的生产服务。
	restartRequired := exe != "/usr/local/bin/sssingbox"
	if !restartRequired {
		s.setUpdPhase("restarting")
		go func() {
			time.Sleep(time.Second)
			_ = exec.Command("systemctl", "restart", "sssingbox").Run()
		}()
	}
	okJSON(w, map[string]interface{}{"version": latest, "restart_required": restartRequired, "backup": bak})
}

func extractPanelBinary(pkg []byte) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(hdr.Name) != "sssingbox" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 512*1024*1024+1))
		if err != nil {
			return "", err
		}
		if len(data) == 0 {
			return "", fmt.Errorf("包里的二进制为空")
		}
		tmp, err := os.CreateTemp("", "sssingbox-update-*")
		if err != nil {
			return "", err
		}
		tmpName := tmp.Name()
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return "", err
		}
		tmp.Close()
		_ = os.Chmod(tmpName, 0755)
		return tmpName, nil
	}
	return "", fmt.Errorf("包里没有 sssingbox 二进制")
}
