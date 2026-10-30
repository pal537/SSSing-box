package cli

// 命令行管理：不用打开面板，在 SSH 里直接管理节点。
// 面板仍是唯一写库、写配置、管 sing-box 的一方，CLI 只调面板 HTTP API，
// 不存在双写冲突。面板没运行时，节点类命令会报错并提示先启动面板。
//
// 凭证：安装器把生成的账号写进 <数据目录>/.cli-credentials（0600，仅 root 可读），
// CLI 读它登录；面板里改过密码后，用 `yizhan login` 重新保存一次即可。

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"yizhan/internal/store"
	"yizhan/internal/version"
)

type options struct {
	dataDir string
	port    int
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func credPath(dataDir string) string { return filepath.Join(dataDir, ".cli-credentials") }

func loadCredentials(dataDir string) (credentials, error) {
	if u := os.Getenv("YIZHAN_USER"); u != "" {
		if p := os.Getenv("YIZHAN_PASS"); p != "" {
			return credentials{Username: u, Password: p}, nil
		}
	}
	b, err := os.ReadFile(credPath(dataDir))
	if err != nil {
		return credentials{}, fmt.Errorf("未找到 CLI 凭证文件 %s（安装器自动生成；面板里改过密码后请跑 yizhan login 重新保存）", credPath(dataDir))
	}
	var c credentials
	if err := json.Unmarshal(b, &c); err != nil || c.Username == "" {
		return credentials{}, fmt.Errorf("CLI 凭证文件损坏，请跑 yizhan login 重新保存")
	}
	return c, nil
}

func saveCredentials(dataDir string, c credentials) error {
	b, _ := json.Marshal(c)
	return os.WriteFile(credPath(dataDir), b, 0600)
}

// client：带登录态的面板 API 客户端。先试 HTTP（双协议监听下本地 HTTP 一直通），
// 不通再试 HTTPS（忽略自签证书校验，只走本机回环）。
type client struct {
	base string
	http *http.Client
}

func newClient(o options) (*client, error) {
	cred, err := loadCredentials(o.dataDir)
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	for _, scheme := range []string{"http", "https"} {
		base := fmt.Sprintf("%s://127.0.0.1:%d", scheme, o.port)
		if scheme == "https" {
			hc.Transport = insecureTransport()
		}
		body, _ := json.Marshal(map[string]string{"username": cred.Username, "password": cred.Password})
		req, _ := http.NewRequest("POST", base+"/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if out.OK {
			return &client{base: base, http: hc}, nil
		}
		return nil, fmt.Errorf("面板登录失败：%s（账号密码不对，或凭证文件已过期，跑 yizhan login 重新保存）", out.Error)
	}
	return nil, fmt.Errorf("连不上本机面板（端口 %d）：面板没运行的话先 systemctl start yizhan", o.port)
}

func (c *client) call(method, path string, payload interface{}) (map[string]interface{}, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("面板返回了解析不了的内容（HTTP %d）", resp.StatusCode)
	}
	if ok, _ := out["ok"].(bool); !ok {
		if e, _ := out["error"].(string); e != "" {
			return nil, fmt.Errorf("%s", e)
		}
		return nil, fmt.Errorf("面板返回失败（HTTP %d）", resp.StatusCode)
	}
	data, _ := out["data"].(map[string]interface{})
	if data == nil {
		data = out
	}
	return data, nil
}

func (c *client) settings() (map[string]interface{}, error) { return c.call("GET", "/api/settings", nil) }

type nodeRow struct {
	ID       string
	Name     string
	Protocol string
	Port     int
	Enabled  bool
}

func (c *client) listNodes() ([]nodeRow, error) {
	// /api/inbounds GET 返回行数组（data 本身就是数组，不包在对象里）。
	var body io.Reader
	req, _ := http.NewRequest("GET", c.base+"/api/inbounds", body)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool            `json:"ok"`
		Error string          `json:"error"`
		Data  json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("面板返回了解析不了的内容")
	}
	if !out.OK {
		return nil, fmt.Errorf("%s", out.Error)
	}
	var rows []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.Unmarshal(out.Data, &rows); err != nil {
		return nil, fmt.Errorf("节点列表解析失败：%v", err)
	}
	var res []nodeRow
	for _, r := range rows {
		res = append(res, nodeRow(r))
	}
	return res, nil
}

// resolveNode：按 id、端口或名字定位节点，歧义时报错。
func (c *client) resolveNode(ident string) (nodeRow, error) {
	nodes, err := c.listNodes()
	if err != nil {
		return nodeRow{}, err
	}
	var hits []nodeRow
	for _, n := range nodes {
		if n.ID == ident || strconv.Itoa(n.Port) == ident || n.Name == ident {
			hits = append(hits, n)
		}
	}
	if len(hits) == 0 {
		return nodeRow{}, fmt.Errorf("找不到节点：%s", ident)
	}
	if len(hits) > 1 {
		return nodeRow{}, fmt.Errorf("有多个节点匹配 %s，请用 id 或端口指定", ident)
	}
	return hits[0], nil
}

func createPayload(protocol string, port int, name, sni string, advanced map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"protocol": protocol, "port": port, "name": name,
		"address": "", "sni": sni, "advanced": advanced,
	}
}

// Run：argv[0] 是子命令。返回进程退出码。
func Run(args []string) int {
	if len(args) == 0 {
		fmt.Println("用法：yizhan menu | yizhan node list|add|rm|on|off | yizhan status | yizhan sub | yizhan login | yizhan admin reset | yizhan version")
		return 2
	}
	// 子命令后的 flag（如 yizhan node add -protocol vless）由各子命令自己再解析，
	// 这里只把 -data/-port 摘出来，其余原样留给子命令。
	// 例外：node add 自带 -port（节点监听端口，0=自动分配），不能被当成面板端口摘走，
	// 否则 yizhan node add -port 0 会去连面板 0 端口。node add 的面板端口固定走默认 18081。
	isNodeAdd := len(args) >= 2 && args[0] == "node" && args[1] == "add"
	dataDir := "/var/lib/yizhan"
	port := 18081
	var rest []string
	for i := 1; i < len(args); i++ {
		if args[i] == "-data" && i+1 < len(args) {
			dataDir = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "-data=") {
			dataDir = strings.TrimPrefix(args[i], "-data=")
		} else if args[i] == "-port" && i+1 < len(args) && !isNodeAdd {
			port, _ = strconv.Atoi(args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "-port=") && !isNodeAdd {
			port, _ = strconv.Atoi(strings.TrimPrefix(args[i], "-port="))
		} else {
			rest = append(rest, args[i])
		}
	}
	o := options{dataDir: dataDir, port: port}
	switch args[0] {
	case "menu":
		return runMenu(o)
	case "status":
		return runStatus(o)
	case "sub":
		return runSub(o)
	case "login":
		return runLogin(o)
	case "admin":
		if len(rest) > 0 && rest[0] == "reset" {
			return runAdminReset(o)
		}
		fmt.Println("用法：yizhan admin reset（重置面板管理员密码）")
		return 2
	case "node":
		return runNode(o, rest)
	case "version":
		fmt.Printf("yizhan %s\n", version.Version)
		return 0
	default:
		fmt.Printf("未知子命令：%s\n用法：yizhan menu | yizhan node list|add|rm|on|off | yizhan status | yizhan sub | yizhan login | yizhan admin reset | yizhan version\n", args[0])
		return 2
	}
}

func runStatus(o options) int {
	c, err := newClient(o)
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	on := 0
	for _, n := range nodes {
		if n.Enabled {
			on++
		}
	}
	fmt.Printf("面板版本：%v\n面板地址：http://%v:%v/\n节点：%d 个（启用 %d 个）\n",
		st["version"], st["public_ip"], st["panel_port"], len(nodes), on)
	return 0
}

func runSub(o options) int {
	c, err := newClient(o)
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	tok, _ := st["sub_token"].(string)
	if tok == "" {
		fmt.Println("订阅 token 为空，面板可能还没初始化完成")
		return 1
	}
	fmt.Printf("http://%v:%v/sub/%s\n", st["public_ip"], st["panel_port"], tok)
	return 0
}

func runLogin(o options) int {
	user := prompt("面板账号：")
	pass := readPassword("面板密码：")
	if user == "" || pass == "" {
		fmt.Println("账号密码不能为空")
		return 1
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	var lastErr error
	for _, scheme := range []string{"http", "https"} {
		base := fmt.Sprintf("%s://127.0.0.1:%d", scheme, o.port)
		if scheme == "https" {
			hc.Transport = insecureTransport()
		}
		req, _ := http.NewRequest("POST", base+"/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if out.OK {
			if err := saveCredentials(o.dataDir, credentials{Username: user, Password: pass}); err != nil {
				fmt.Println("登录成功，但凭证文件保存失败：", err)
				return 1
			}
			fmt.Println("登录成功，凭证已保存（仅 root 可读），以后 yizhan 命令不用再输密码")
			return 0
		}
		fmt.Println("登录失败：", out.Error)
		return 1
	}
	fmt.Println("连不上本机面板：", lastErr)
	return 1
}

func runAdminReset(o options) int {
	st, err := store.Open(filepath.Join(o.dataDir, "yizhan.db"))
	if err != nil {
		fmt.Println("打开数据库失败：", err)
		return 1
	}
	defer st.Close()
	user := prompt("要重置的账号（留空用第一个管理员）：")
	if user == "" {
		// 没有列用户的接口，直接试常见的 admin，不存在再报错。
		user = "admin"
	}
	if _, err := st.GetUser(user); err != nil {
		fmt.Printf("账号 %s 不存在（面板里改过用户名的话，yizhan admin reset 目前只认 admin）\n", user)
		return 1
	}
	p1 := readPassword("新密码：")
	p2 := readPassword("再输一次：")
	if p1 == "" || p1 != p2 {
		fmt.Println("两次密码不一致或为空")
		return 1
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(p1), bcrypt.DefaultCost)
	if err := st.UpdatePassword(user, string(hash)); err != nil {
		fmt.Println("密码更新失败：", err)
		return 1
	}
	// CLI 凭证同步更新，否则下次 yizhan 命令会用旧密码登录失败。
	_ = saveCredentials(o.dataDir, credentials{Username: user, Password: p1})
	fmt.Println("密码已重置，CLI 凭证已同步更新（面板里已登录的会话不受影响）")
	return 0
}

func runNode(o options, args []string) int {
	if len(args) == 0 {
		fmt.Println("用法：yizhan node list | yizhan node add -protocol vless [-mode reality] [-port 0] | yizhan node rm <id/端口/名字> | yizhan node on|off <id/端口/名字>")
		return 2
	}
	switch args[0] {
	case "list":
		c, err := newClient(o)
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		nodes, err := c.listNodes()
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		if len(nodes) == 0 {
			fmt.Println("还没有节点")
			return 0
		}
		for _, n := range nodes {
			state := "停用"
			if n.Enabled {
				state = "启用"
			}
			fmt.Printf("%-28s %-10s %-6d %s  %s\n", n.Name, n.Protocol, n.Port, state, n.ID)
		}
		return 0
	case "add":
		fs := flag.NewFlagSet("add", flag.ContinueOnError)
		protocol := fs.String("protocol", "", "协议：vless/hy2/mtg/vmess/ss/socks/http/trojan/wireguard/tuic/anytls/naive")
		port := fs.Int("port", 0, "端口（0=自动分配）")
		name := fs.String("name", "", "节点名（留空自动）")
		sni := fs.String("sni", "", "SNI/域名（留空自动）")
		mode := fs.String("mode", "", "传输方式（vless: reality/ws/h2/httpupgrade；vmess: tcp/cf/http/quic/h2/httpupgrade；trojan: reality/cf/h2/httpupgrade）")
		path := fs.String("path", "", "路径（TLS 档留空自动生成）")
		method := fs.String("method", "2022-blake3-aes-128-gcm", "SS 加密方式")
		cert := fs.String("cert", "", "Naive 证书文件路径")
		key := fs.String("key", "", "Naive 密钥文件路径")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *protocol == "" {
			fmt.Println("请用 -protocol 指定协议")
			return 2
		}
		adv := map[string]interface{}{}
		switch *protocol {
		case "vless":
			if *mode == "" {
				*mode = "reality"
			}
			adv = map[string]interface{}{"mode": *mode, "path": *path, "flow": "xtls-rprx-vision", "fingerprint": "chrome", "spider_x": "/"}
		case "vmess":
			if *mode == "" {
				*mode = "tcp"
			}
			adv = map[string]interface{}{"mode": *mode, "path": *path}
		case "trojan":
			if *mode == "" {
				*mode = "reality"
			}
			adv = map[string]interface{}{"mode": *mode, "path": *path}
		case "ss":
			adv = map[string]interface{}{"method": *method}
		}
		c, err := newClient(o)
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		data, err := c.call("POST", "/api/inbounds", createPayload(*protocol, *port, *name, *sni, adv))
		if err != nil {
			fmt.Println("创建失败：", err)
			return 1
		}
		inb, _ := data["inbound"].(map[string]interface{})
		id, _ := inb["id"].(string)
		fmt.Printf("已创建：%v（端口 %v）\n链接：%v\n", inb["name"], inb["port"], data["link"])
		if l6, _ := data["link6"].(string); l6 != "" {
			fmt.Printf("IPv6 链接：%v\n", l6)
		}
		if *protocol == "naive" {
			if *cert != "" && *key != "" {
				cb, err1 := os.ReadFile(*cert)
				kb, err2 := os.ReadFile(*key)
				if err1 != nil || err2 != nil {
					fmt.Println("证书文件读不到，建好后请在面板里上传证书")
				} else if _, err := c.call("POST", "/api/inbounds/"+id+"/cert", map[string]string{"cert": string(cb), "key": string(kb)}); err != nil {
					fmt.Println("证书上传失败：", err)
				} else {
					fmt.Println("证书已上传，节点已生效")
				}
			} else {
				fmt.Println("提醒：Naive 需要 CA 证书，建好后请在面板节点菜单里上传证书，或创建时加 -cert/-key")
			}
		}
		return 0
	case "rm":
		if len(args) < 2 {
			fmt.Println("用法：yizhan node rm <id/端口/名字>")
			return 2
		}
		c, err := newClient(o)
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		n, err := c.resolveNode(args[1])
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		if !confirm(fmt.Sprintf("确认删除节点 %s（%s:%d）？", n.Name, n.Protocol, n.Port)) {
			fmt.Println("已取消")
			return 0
		}
		if _, err := c.call("DELETE", "/api/inbounds/"+n.ID, nil); err != nil {
			fmt.Println("删除失败：", err)
			return 1
		}
		fmt.Println("已删除")
		return 0
	case "on", "off":
		if len(args) < 2 {
			fmt.Println("用法：yizhan node on|off <id/端口/名字>")
			return 2
		}
		c, err := newClient(o)
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		n, err := c.resolveNode(args[1])
		if err != nil {
			fmt.Println("错误：", err)
			return 1
		}
		enabled := args[0] == "on"
		if _, err := c.call("PUT", "/api/inbounds/"+n.ID, map[string]interface{}{"enabled": enabled}); err != nil {
			fmt.Println("操作失败：", err)
			return 1
		}
		fmt.Println("已", map[bool]string{true: "启用", false: "停用"}[enabled])
		return 0
	default:
		fmt.Println("用法：yizhan node list | yizhan node add -protocol vless | yizhan node rm <id/端口/名字> | yizhan node on|off <id/端口/名字>")
		return 2
	}
}

func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

func confirm(msg string) bool {
	fmt.Printf("%s [y/N] ", msg)
	var line string
	fmt.Scanln(&line)
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
