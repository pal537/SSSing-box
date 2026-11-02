package server

// ---------- 面板访问：根路径防扫 + 端口 + 域名 ----------
// 根路径（3x-ui 式）：面板只活在 /<随机路径>/ 下面，裸 IP:端口扫不到面板。
// 新装默认随机 5 位小写英文（初始设置时生成）；老面板升级后路径为空，
// 仍走根目录（不锁死老用户），去设置页设一个立即生效，不用重启。
// 订阅链接（/sub/<token>）不进路径门：token 本身就是密钥。
// 本机回环（SSH 菜单、安装器）不进路径门：能登本机的人已经有 root。

import (
	crand "crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

const panelServiceFile = "/etc/systemd/system/sssingbox.service"

// clientIPOf：只认 RemoteAddr，不认 X-Forwarded-For（那是能伪造的）。
func clientIPOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopbackIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// panelPath：当前根路径（去头尾斜杠），空 = 根目录模式。
func (s *Server) panelPath() string {
	return strings.Trim(s.app.Store.GetSetting("panel_path"), "/")
}

// panelBase：前端拼地址用的前缀，"" 或 "/abc12"。
func (s *Server) panelBase() string {
	if p := s.panelPath(); p != "" {
		return "/" + p
	}
	return ""
}

// panelPathGate：包在整棵路由外面。它改 r.URL.Path 再交给内层 mux，
// 内层按改写后的路径重新匹配，所以 /api、静态文件都不用改。
func (s *Server) panelPathGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sub/") {
			next.ServeHTTP(w, r)
			return
		}
		if isLoopbackIP(clientIPOf(r)) {
			// 回环同样要剥前缀：否则本机用带路径地址打开时，
			// 内层路由拿着 /<路径>/api/... 找不到文件（实测抓到的 bug）。
			if p := s.panelPath(); p != "" {
				prefix := "/" + p
				if r.URL.Path == prefix {
					r.URL.Path = "/"
				} else if strings.HasPrefix(r.URL.Path, prefix+"/") {
					r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		p := s.panelPath()
		if p == "" {
			next.ServeHTTP(w, r)
			return
		}
		prefix := "/" + p
		if r.URL.Path == prefix {
			r.URL.Path = "/"
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func randPanelPath() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 5)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func validPanelPath(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > 32 || p == "sub" || p == "api" {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// rewriteServicePort：只改服务文件 ExecStart 行里的 -port 数字，其他行原样。
func rewriteServicePort(content string, newPort int) (string, error) {
	lines := strings.Split(content, "\n")
	changed := false
	for i, ln := range lines {
		if !strings.Contains(ln, "ExecStart") || !strings.Contains(ln, "-port") {
			continue
		}
		fields := strings.Fields(ln)
		for j, f := range fields {
			if f == "-port" && j+1 < len(fields) {
				fields[j+1] = strconv.Itoa(newPort)
				changed = true
			} else if strings.HasPrefix(f, "-port=") {
				fields[j] = "-port=" + strconv.Itoa(newPort)
				changed = true
			}
		}
		if changed {
			lines[i] = strings.Join(fields, " ")
		}
	}
	if !changed {
		return "", fmt.Errorf("服务文件里没有 -port 参数")
	}
	return strings.Join(lines, "\n"), nil
}

func firewallAllowPort(port int) {
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("ufw", "allow", strconv.Itoa(port)+"/tcp").Run()
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		_ = exec.Command("firewall-cmd", "--permanent", "--add-port="+strconv.Itoa(port)+"/tcp").Run()
		_ = exec.Command("firewall-cmd", "--reload").Run()
	}
}

// portTaken：新端口能不能绑（面板自己占的当前端口不在此列，因为测的是新端口）。
func portTaken(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}
