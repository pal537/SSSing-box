package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type System struct {
	CPUPercent  float64 `json:"cpu_percent"`
	CPUCores    int     `json:"cpu_cores"`
	MemUsed     uint64  `json:"mem_used"`
	MemTotal    uint64  `json:"mem_total"`
	MemPercent  float64 `json:"mem_percent"`
	SwapUsed    uint64  `json:"swap_used"`
	SwapTotal   uint64  `json:"swap_total"`
	SwapPercent float64 `json:"swap_percent"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskPercent float64 `json:"disk_percent"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	UptimeSec   int64   `json:"uptime_sec"`
	PanelMem    uint64  `json:"panel_mem"`
	PanelGor    int     `json:"panel_goroutines"`
	TCPConns    int     `json:"tcp_conns"`
	UDPConns    int     `json:"udp_conns"`
}

var (
	mu       sync.Mutex
	lastCPU  [2]uint64
	lastTime time.Time
)

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var sum uint64
		for i, v := range fields {
			n, _ := strconv.ParseUint(v, 10, 64)
			sum += n
			if i == 3 || i == 4 { // idle + iowait
				idle += n
			}
		}
		return idle, sum, nil
	}
	return 0, 0, fmt.Errorf("cpu line not found")
}

func cpuPercent() float64 {
	idle, total, err := readCPUStat()
	if err != nil {
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	if lastTime.IsZero() {
		lastCPU = [2]uint64{idle, total}
		lastTime = now
		return 0
	}
	dIdle := float64(idle - lastCPU[0])
	dTotal := float64(total - lastCPU[1])
	lastCPU = [2]uint64{idle, total}
	lastTime = now
	if dTotal <= 0 {
		return 0
	}
	p := (1 - dIdle/dTotal) * 100
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
}

func memInfo() (memTotal, memAvail, swapTotal, swapFree uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(parts[1], 10, 64)
		v *= 1024
		switch parts[0] {
		case "MemTotal:":
			memTotal = v
		case "MemAvailable:":
			memAvail = v
		case "SwapTotal:":
			swapTotal = v
		case "SwapFree:":
			swapFree = v
		}
	}
	return
}

func diskUsage(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total < free {
		return 0, total
	}
	return total - free, total
}

func loadAvg() (l1, l5, l15 float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fmt.Sscanf(string(b), "%f %f %f", &l1, &l5, &l15)
	return
}

func uptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var up float64
	fmt.Sscanf(string(b), "%f", &up)
	return int64(up)
}

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// parseProcNetPorts returns listening TCP ports and bound UDP ports.
func procNetPorts() (tcpListen, udpBound map[int]bool) {
	tcpListen = map[int]bool{}
	udpBound = map[int]bool{}
	parse := func(path string, out map[int]bool, wantListen bool) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[0] == "sl" {
				continue
			}
			if wantListen && fields[3] != "0A" { // LISTEN
				continue
			}
			la := fields[1]
			idx := strings.LastIndex(la, ":")
			if idx < 0 {
				continue
			}
			p, err := strconv.ParseUint(la[idx+1:], 16, 32)
			if err != nil {
				continue
			}
			out[int(p)] = true
		}
	}
	parse("/proc/net/tcp", tcpListen, true)
	parse("/proc/net/tcp6", tcpListen, true)
	parse("/proc/net/udp", udpBound, false)
	parse("/proc/net/udp6", udpBound, false)
	return
}

func ListeningTCPPorts() map[int]bool {
	t, _ := procNetPorts()
	return t
}

func BoundUDPPorts() map[int]bool {
	_, u := procNetPorts()
	return u
}

// TCPConnections counts established TCP connections whose LOCAL port is in ports.
func TCPConnections(ports map[int]bool) int {
	if len(ports) == 0 {
		return 0
	}
	count := 0
	parse := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[0] == "sl" {
				continue
			}
			if fields[3] != "01" { // ESTABLISHED
				continue
			}
			la := fields[1]
			idx := strings.LastIndex(la, ":")
			if idx < 0 {
				continue
			}
			p, err := strconv.ParseUint(la[idx+1:], 16, 32)
			if err != nil {
				continue
			}
			if ports[int(p)] {
				count++
			}
		}
	}
	parse("/proc/net/tcp")
	parse("/proc/net/tcp6")
	return count
}

// UDPConntrack counts UDP sessions (from nf_conntrack if available) whose local port is in ports.
func UDPConntrack(ports map[int]bool) int {
	if len(ports) == 0 {
		return 0
	}
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return -1
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "udp") {
			continue
		}
		// format: ... src=X dst=Y sport=A dport=B [UNREPLIED] src=Y dst=X sport=B dport=A ...
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "dport=") {
				p, err := strconv.Atoi(strings.TrimPrefix(field, "dport="))
				if err == nil && ports[p] {
					count++
					break
				}
			}
		}
	}
	return count
}

func Snapshot(diskPath string) System {
	mt, ma, st, sf := memInfo()
	du, dt := diskUsage(diskPath)
	l1, l5, l15 := loadAvg()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return System{
		CPUPercent:  cpuPercent(),
		CPUCores:    runtime.NumCPU(),
		MemUsed:     mt - ma,
		MemTotal:    mt,
		MemPercent:  pct(mt-ma, mt),
		SwapUsed:    st - sf,
		SwapTotal:   st,
		SwapPercent: pct(st-sf, st),
		DiskUsed:    du,
		DiskTotal:   dt,
		DiskPercent: pct(du, dt),
		Load1:       l1,
		Load5:       l5,
		Load15:      l15,
		UptimeSec:   uptime(),
		PanelMem:    ms.Alloc,
		PanelGor:    runtime.NumGoroutine(),
	}
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 6 * time.Second}
}

// PublicIPv4 fetches the machine's public IPv4 (cached by caller).
func PublicIPv4() string {
	// api4.ipify.org answers only over IPv4.
	for _, url := range []string{"https://api4.ipify.org", "https://ipv4.icanhazip.com"} {
		if ip := fetchIP(url); ip != "" {
			return ip
		}
	}
	return ""
}

// PublicIPv6 fetches the machine's public IPv6 (cached by caller).
// Returns "" when the machine has no IPv6 egress.
func PublicIPv6() string {
	// api6.ipify.org answers only over IPv6.
	for _, url := range []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"} {
		if ip := fetchIP6(url); ip != "" {
			return ip
		}
	}
	return ""
}

func fetchIP6(url string) string {
	c := httpClient()
	resp, err := c.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 128)
	n, _ := resp.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ""
	}
	return parsed.String()
}

func fetchIP(url string) string {
	// tiny http client with timeout; no external deps
	c := httpClient()
	resp, err := c.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))
	// validate dotted quad
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return ""
		}
	}
	return ip
}
