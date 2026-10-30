package stats

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ---------- nftables per-port 统计 ----------
//
// sing-box 没有 xray 那种按入站累计的 stats API（Clash API 只有实时
// 流量和当前连接快照），所以用量改走 nftables：每个节点端口 4 条规则
// （入方向 tcp/udp dport、出方向 tcp/sport），计数器即累计字节。
// 方向约定与旧 xray 一致：入方向 = 客户端上传（up），出方向 = 客户端下载（down）。
//
// 规则管理原则：
//   - 表和链由面板创建（inet sssingbox-<数据目录哈希> / in / out，见 SetDataDir），
//     只动自己 comment 标记的规则，绝不 flush 整表——flush 会清零所有计数器。
//   - 轮询循环每次同步规则（只增缺失、只删多余），重启/手动 flush 后自愈。
//   - 计数器重置（重启、规则重建）由 PollOnce 的“当前 < 上次则按当前算”兜底，
//     与旧核心重启语义一致。

const nftComment = "sssingbox-stats"

// nftTable is per panel instance, derived from the data directory, so two
// panels on one machine (production + a test instance, or two test
// instances) never share one table. Sharing one table was a real bug:
// SyncStatsRules deletes "sssingbox-stats" rules for ports it doesn't want,
// so two panels kept deleting each other's rules and resetting counters.
// Production /var/lib/sssingbox and a test /tmp/.../data therefore get
// different tables deterministically, with no config to remember.
var nftTable = "sssingbox"

// SetDataDir fixes the stats table for this panel instance. It must be
// called once at startup, before any stats call.
func SetDataDir(dir string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs))
	nftTable = "sssingbox-" + hex.EncodeToString(sum[:])[:8]
}

// TableName reports the stats table this instance uses (for logs/docs).
func TableName() string { return nftTable }

// ErrNoTable 表示 nft 统计表不存在（首次运行或重启后规则丢失），调用方应
// Ensure + Sync 后重试，而不是把这次当成“流量为 0”。
var ErrNoTable = errors.New("nft 统计表不存在")

func nftRun(args ...string) (string, error) {
	cmd := exec.Command("nft", args...)
	out, err := cmd.Output()
	if err != nil {
		// stderr 里有 nft 的真实原因（表不存在、权限、语法），
		// 丢了它调用方只能看到 exit status，无法区分“表没了”
		// 还是“别的错”，自愈逻辑也就无从谈起。
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg := strings.TrimSpace(string(ee.Stderr))
			if msg != "" {
				return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, msg)
			}
		}
		return "", fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func nftAvailable() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// EnsureStatsTable：表或链缺失时创建，已存在则不动（不碰计数器）。
// 只查表存在就放行是个洞：表在、链被人删了时，Sync/Counters
// 每轮都报错，面板用量永久挂掉——链也要逐条验、缺了补。
func EnsureStatsTable() error {
	if !nftAvailable() {
		return fmt.Errorf("系统没有 nft 命令，无法统计 sing-box 节点用量")
	}
	if _, err := nftRun("list", "table", "inet", nftTable); err != nil {
		return createStatsTable()
	}
	for _, chain := range []string{"in", "out"} {
		if _, err := nftRun("list", "chain", "inet", nftTable, chain); err != nil {
			hook := "input"
			if chain == "out" {
				hook = "output"
			}
			if _, err := nftRun("add", "chain", "inet", nftTable, chain, "{", "type", "filter", "hook", hook, "priority", "0;", "policy", "accept;", "}"); err != nil {
				return fmt.Errorf("补建 nft 链 %s 失败：%w", chain, err)
			}
		}
	}
	return nil
}

func createStatsTable() error {
	script := "table inet " + nftTable + " {\n" +
		"  chain in { type filter hook input priority 0; policy accept; }\n" +
		"  chain out { type filter hook output priority 0; policy accept; }\n" +
		"}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建 nft 表失败：%v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

type nftRule struct {
	Chain    string
	Handle   int
	Protocol string // tcp | udp
	Field    string // dport | sport
	Port     int
	Bytes    int64
	Ours     bool
}

// listChainRules 读一条链的规则（JSON 形式）。
func listChainRules(chain string) ([]nftRule, error) {
	out, err := nftRun("-j", "list", "chain", "inet", nftTable, chain)
	if err != nil {
		// 区分“表/链不存在”和“其他错误”：表不存在时调用方自愈重建，
		// 其他错误（如权限）必须原样上报，不能误当成表缺失。
		// nftRun 已把 stderr 写进 error：表/链缺失时 nft 报错含
		// No such file 或 does not exist，据此判定，不再多查一次表。
		msg := err.Error()
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil, ErrNoTable
		}
		return nil, err
	}
	rules, err := parseNftRules([]byte(out))
	if err != nil {
		return nil, err
	}
	// list chain 输出的 rule 不带 chain 字段（查的就是这条链）。
	for i := range rules {
		rules[i].Chain = chain
	}
	return rules, nil
}

// listTableRules 一次读整张表的规则（in/out 两条链一起）。
// Counters 用它：以前 in/out 分两次查，中间规则一变（节点删改、
// 同步删规则），两边就对不上号——入方向算了、出方向漏了。
func listTableRules() ([]nftRule, error) {
	out, err := nftRun("-j", "list", "table", "inet", nftTable)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil, ErrNoTable
		}
		return nil, err
	}
	return parseNftRules([]byte(out))
}

func parseNftRules(out []byte) ([]nftRule, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Chain   string `json:"chain"`
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
				Expr    []struct {
					Match *struct {
						Left struct {
							Payload *struct {
								Protocol string `json:"protocol"`
								Field    string `json:"field"`
							} `json:"payload"`
						} `json:"left"`
						Right interface{} `json:"right"`
					} `json:"match"`
					Counter *struct {
						Bytes int64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("解析 nft 规则失败：%w", err)
	}
	var rules []nftRule
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		// chain 取自 rule 自身（整表输出里有；单链输出里没有，
		// 调用方 listChainRules 会再按查询的链覆写一次）。
		r := nftRule{Chain: item.Rule.Chain, Handle: item.Rule.Handle, Ours: item.Rule.Comment == nftComment}
		for _, e := range item.Rule.Expr {
			if e.Match != nil && e.Match.Left.Payload != nil {
				r.Protocol = e.Match.Left.Payload.Protocol
				r.Field = e.Match.Left.Payload.Field
				r.Port = toInt(e.Match.Right)
			}
			if e.Counter != nil {
				r.Bytes = e.Counter.Bytes
			}
		}
		// 只有“单端口匹配 + 计数器”形状的才算统计规则，其他规则不动。
		if (r.Field == "dport" || r.Field == "sport") && r.Port > 0 {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// SyncStatsRules：让两条链的统计规则与 wantPorts 一致（只增缺失、只删
// 本面板多余的规则）。入链按 dport、出链按 sport，各补 tcp/udp 两条。
func SyncStatsRules(wantPorts map[int]bool) error {
	if err := EnsureStatsTable(); err != nil {
		return err
	}
	// 非法端口（手改库、旧脏数据）直接跳过：以前含 0/负数/超范围端口时
	// nft add rule 报错、整轮同步中途返回，另一条链和其他端口全停摆。
	clean := map[int]bool{}
	for port := range wantPorts {
		if port >= 1 && port <= 65535 {
			clean[port] = true
		}
	}
	wantPorts = clean
	for _, chain := range []string{"in", "out"} {
		rules, err := listChainRules(chain)
		if err != nil {
			return err
		}
		// have 只认本面板标记的规则：管理员自己的同端口规则
		// 不能算数，否则面板会跳过建自己的计数器、该端口用量恒 0。
		have := map[string]bool{}
		for _, r := range rules {
			if r.Ours {
				have[r.Protocol+"|"+r.Field+"|"+strconv.Itoa(r.Port)] = true
			}
		}
		field := "dport"
		if chain == "out" {
			field = "sport"
		}
		for port := range wantPorts {
			for _, proto := range []string{"tcp", "udp"} {
				key := proto + "|" + field + "|" + strconv.Itoa(port)
				if have[key] {
					continue
				}
				if _, err := nftRun("add", "rule", "inet", nftTable, chain, proto, field, strconv.Itoa(port), "counter", "comment", `"sssingbox-stats"`); err != nil {
					return err
				}
			}
		}
		// 删多余：只删本面板标记过的规则，且端口已不在 want 里。
		// 删除失败不再静默丢弃：本轮记下来、最后汇总上报；
		// 调用方（后台轮询）即使同步失败也会继续 PollOnce，
		// 计数器本身不停，只是多余规则晚一轮再清。
		var delErr error
		for _, r := range rules {
			if !r.Ours {
				continue
			}
			if wantPorts[r.Port] {
				continue
			}
			// 只删形状完整的统计规则（协议+方向+端口齐全）。
			if r.Protocol == "" || r.Field == "" {
				continue
			}
			if _, err := nftRun("delete", "rule", "inet", nftTable, chain, "handle", strconv.Itoa(r.Handle)); err != nil && delErr == nil {
				delErr = fmt.Errorf("删 %s 链 handle %d 失败：%w", chain, r.Handle, err)
			}
		}
		if delErr != nil {
			return delErr
		}
	}
	return nil
}

// Counters 读累计字节：端口 -> [up, down]。入链 dport 是 up，出链 sport 是 down。
// 整表一次读完：in/out 分两次查时，中间规则一变两边就对不上号。
func Counters() (map[int][2]int64, error) {
	res := map[int][2]int64{}
	rules, err := listTableRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		// 只加本面板的计数器：管理员或其他软件的同端口规则
		// 也会被读到，加进来就是别人的流量。
		if !r.Ours {
			continue
		}
		cur := res[r.Port]
		if r.Chain == "in" && r.Field == "dport" {
			cur[0] += r.Bytes
		} else if r.Chain == "out" && r.Field == "sport" {
			cur[1] += r.Bytes
		} else {
			continue
		}
		res[r.Port] = cur
	}
	return res, nil
}
