package cli

// 交互菜单：SSH 里跑 `yizhan menu`，不用打开面板就能建节点、管节点。

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
	fmt.Print(msg)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

// readPassword：关回显读一行（stty 不可用时退化为明文读）。
func readPassword(msg string) string {
	fmt.Print(msg)
	stty := func(args ...string) {
		cmd := exec.Command("stty", args...)
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
	}
	stty("-echo")
	line, _ := stdin.ReadString('\n')
	stty("echo")
	fmt.Println()
	return strings.TrimSpace(line)
}

func promptInt(msg string, def int) int {
	for {
		s := prompt(msg)
		if s == "" {
			return def
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
		fmt.Println("请输入数字")
	}
}

func runMenu(o options) int {
	c, err := newClient(o)
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	for {
		fmt.Println()
		fmt.Println("============ 驿站管理 ============")
		fmt.Println("1. 创建节点")
		fmt.Println("2. 节点列表")
		fmt.Println("3. 删除节点")
		fmt.Println("4. 启用/停用节点")
		fmt.Println("5. 面板状态")
		fmt.Println("6. 订阅链接")
		fmt.Println("0. 退出")
		switch prompt("请选择：") {
		case "1":
			menuCreate(c)
		case "2":
			menuList(c)
		case "3":
			menuDelete(c)
		case "4":
			menuToggle(c)
		case "5":
			menuStatus(c)
		case "6":
			menuSub(c)
		case "0":
			return 0
		default:
			fmt.Println("没有这个选项")
		}
	}
}

func menuList(c *client) {
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	if len(nodes) == 0 {
		fmt.Println("还没有节点")
		return
	}
	for i, n := range nodes {
		state := "停用"
		if n.Enabled {
			state = "启用"
		}
		fmt.Printf("%d. %-28s %-10s %-6d %s\n", i+1, n.Name, n.Protocol, n.Port, state)
	}
}

// pickNode：列出节点让用户按序号选，返回选中的行。
func pickNode(c *client) (nodeRow, bool) {
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return nodeRow{}, false
	}
	if len(nodes) == 0 {
		fmt.Println("还没有节点")
		return nodeRow{}, false
	}
	for i, n := range nodes {
		state := "停用"
		if n.Enabled {
			state = "启用"
		}
		fmt.Printf("%d. %-28s %-10s %-6d %s\n", i+1, n.Name, n.Protocol, n.Port, state)
	}
	i := promptInt("选序号（0 取消）：", 0)
	if i < 1 || i > len(nodes) {
		return nodeRow{}, false
	}
	return nodes[i-1], true
}

func menuDelete(c *client) {
	n, ok := pickNode(c)
	if !ok {
		return
	}
	if !confirm(fmt.Sprintf("确认删除节点 %s（%s:%d）？", n.Name, n.Protocol, n.Port)) {
		fmt.Println("已取消")
		return
	}
	if _, err := c.call("DELETE", "/api/inbounds/"+n.ID, nil); err != nil {
		fmt.Println("删除失败：", err)
		return
	}
	fmt.Println("已删除")
}

func menuToggle(c *client) {
	n, ok := pickNode(c)
	if !ok {
		return
	}
	target := !n.Enabled
	word := "停用"
	if target {
		word = "启用"
	}
	if _, err := c.call("PUT", "/api/inbounds/"+n.ID, map[string]interface{}{"enabled": target}); err != nil {
		fmt.Println("操作失败：", err)
		return
	}
	fmt.Printf("已%s %s\n", word, n.Name)
}

func menuStatus(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	on := 0
	for _, n := range nodes {
		if n.Enabled {
			on++
		}
	}
	fmt.Printf("面板版本：%v\n面板地址：http://%v:%v/\n节点：%d 个（启用 %d 个）\n",
		st["version"], st["public_ip"], st["panel_port"], len(nodes), on)
}

func menuSub(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	tok, _ := st["sub_token"].(string)
	if tok == "" {
		fmt.Println("订阅 token 为空")
		return
	}
	fmt.Printf("http://%v:%v/sub/%s\n", st["public_ip"], st["panel_port"], tok)
}

var protocols = []struct {
	key  string
	name string
}{
	{"vless", "VLESS"},
	{"hy2", "Hysteria2"},
	{"mtg", "MTProto"},
	{"vmess", "VMess"},
	{"ss", "Shadowsocks"},
	{"socks", "SOCKS5"},
	{"http", "HTTP 代理"},
	{"trojan", "Trojan"},
	{"wireguard", "WireGuard"},
	{"tuic", "TUIC"},
	{"anytls", "AnyTLS"},
	{"naive", "Naive"},
}

func menuCreate(c *client) {
	fmt.Println()
	fmt.Println("选择协议：")
	for i, p := range protocols {
		fmt.Printf("%d. %s\n", i+1, p.name)
	}
	fmt.Println("0. 返回")
	i := promptInt("请选择：", 0)
	if i < 1 || i > len(protocols) {
		return
	}
	proto := protocols[i-1].key
	port := promptInt("端口（留空自动分配）：", 0)
	name := prompt("节点名（留空自动）：")
	sni := ""
	adv := map[string]interface{}{}
	switch proto {
	case "vless":
		fmt.Println("传输方式：1. Reality  2. WS  3. H2  4. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "reality", "1": "reality", "2": "ws", "3": "h2", "4": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		sni = prompt("伪装域名/SNI（Reality 留空自动推荐，TLS 档留空用服务器 IP）：")
		path := ""
		if mode != "reality" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path, "flow": "xtls-rprx-vision", "fingerprint": "chrome", "spider_x": "/"}
	case "vmess":
		fmt.Println("传输方式：1. TCP  2. CF  3. HTTP  4. QUIC  5. H2  6. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "tcp", "1": "tcp", "2": "cf", "3": "http", "4": "quic", "5": "h2", "6": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		if mode != "tcp" {
			for {
				sni = prompt("域名（CF 模式必填，其他留空用服务器 IP）：")
				if mode != "cf" || sni != "" {
					break
				}
				fmt.Println("CF 模式必须填已接入 Cloudflare 的域名")
			}
		}
		path := ""
		if mode == "cf" || mode == "http" || mode == "h2" || mode == "httpupgrade" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path}
	case "trojan":
		fmt.Println("传输方式：1. Reality  2. CF  3. H2  4. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "reality", "1": "reality", "2": "cf", "3": "h2", "4": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		if mode == "reality" {
			sni = prompt("伪装域名（留空自动推荐）：")
		} else {
			for {
				sni = prompt("域名（CF 模式必填，其他留空用服务器 IP）：")
				if mode != "cf" || sni != "" {
					break
				}
				fmt.Println("CF 模式必须填已接入 Cloudflare 的域名")
			}
		}
		path := ""
		if mode != "reality" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path}
	case "hy2", "mtg", "tuic", "anytls":
		sni = prompt("SNI（留空自动推荐）：")
	case "naive":
		for {
			sni = prompt("域名（必填，CA 证书上的域名，须解析到本机）：")
			if sni != "" {
				break
			}
			fmt.Println("Naive 必须填真实域名")
		}
	case "ss":
		fmt.Println("加密方式：1. 2022-blake3-aes-128-gcm  2. 2022-blake3-aes-256-gcm  3. aes-256-gcm  4. chacha20-ietf-poly1305")
		m := prompt("请选择（默认 1）：")
		method := map[string]string{"": "2022-blake3-aes-128-gcm", "1": "2022-blake3-aes-128-gcm", "2": "2022-blake3-aes-256-gcm", "3": "aes-256-gcm", "4": "chacha20-ietf-poly1305"}[m]
		if method == "" {
			fmt.Println("没有这个选项")
			return
		}
		adv = map[string]interface{}{"method": method}
	}
	data, err := c.call("POST", "/api/inbounds", createPayload(proto, port, name, sni, adv))
	if err != nil {
		fmt.Println("创建失败：", err)
		return
	}
	inb, _ := data["inbound"].(map[string]interface{})
	fmt.Printf("已创建：%v（端口 %v）\n链接：%v\n", inb["name"], inb["port"], data["link"])
	if l6, _ := data["link6"].(string); l6 != "" {
		fmt.Printf("IPv6 链接：%v\n", l6)
	}
	if proto == "naive" {
		certFile := prompt("证书文件路径（.crt，留空则建好后去面板上传）：")
		keyFile := ""
		if certFile != "" {
			keyFile = prompt("密钥文件路径（.key）：")
		}
		if certFile != "" && keyFile != "" {
			cb, err1 := os.ReadFile(certFile)
			kb, err2 := os.ReadFile(keyFile)
			id, _ := inb["id"].(string)
			if err1 != nil || err2 != nil {
				fmt.Println("证书文件读不到，建好后请在面板里上传证书")
			} else if _, err := c.call("POST", "/api/inbounds/"+id+"/cert", map[string]string{"cert": string(cb), "key": string(kb)}); err != nil {
				fmt.Println("证书上传失败：", err)
			} else {
				fmt.Println("证书已上传，节点已生效")
			}
		} else if certFile != "" {
			fmt.Println("只填了证书没填密钥，建好后请在面板里上传证书")
		} else {
			fmt.Println("提醒：Naive 需要 CA 证书，建好后请在面板节点菜单里上传证书")
		}
	}
}
