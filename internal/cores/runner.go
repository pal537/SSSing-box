package cores

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Runner supervises one core process.
//
// Wait 的唯一归属是 watch goroutine：它在进程退出后关闭 done。
// stop 只等 done，绝不自己再 Wait 一次——两个 Wait 抢同一个
// Cmd 会互相干扰（一个先收走退出状态，另一个拿到“已等过”的错）。
// running 的判定也是 done 而不是 cmd 非空：进程已死但 watch
// 还没拿到锁清掉指针时，cmd 非空是假“运行中”。
type Runner struct {
	Name      string
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	args      []string
	dir       string
	wanted    bool
	startedAt time.Time
	restarts  int
	logFile   *os.File
}

// runningLocked：进程指针存在且 done 未关闭。
func (r *Runner) runningLocked() bool {
	if r.cmd == nil || r.cmd.Process == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

// binFor maps a runner name to its core binary name: per-instance runners
// (hy2-<id>, mtg-<id>) resolve to their core binary (hysteria, mtg).
func binFor(name string) string {
	if strings.HasPrefix(name, "hy2-") {
		return "hysteria"
	}
	if strings.HasPrefix(name, "mtg-") {
		return "mtg"
	}
	return name
}

type Supervisor struct {
	mgr     *Manager
	mu      sync.Mutex
	runners map[string]*Runner
}

func NewSupervisor(mgr *Manager) *Supervisor {
	return &Supervisor{mgr: mgr, runners: map[string]*Runner{}}
}

func (s *Supervisor) get(name string) *Runner {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runners[name]
	if !ok {
		r = &Runner{Name: name}
		s.runners[name] = r
	}
	return r
}

// Start launches the core with args (no-op if already running with same args).
// 日志保留策略：单个日志文件超过 10MB 时只留最新 2000 行，免得一直堆；
// 手动清理则直接清空。重启时与后台轮询里都会执行一次。
const logTrimSize = 10 * 1024 * 1024
const logTrimLines = 2000

func trimLogFile(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= logTrimSize {
		return
	}
	sizeBefore := fi.Size()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// 防并发写丢失：如果读文件期间又有新日志进来（文件变大了），这次放弃，
	// 下一轮轮询再试——否则会用读到的旧快照覆盖掉刚写进来的新行。
	if fi2, err := os.Stat(path); err != nil || fi2.Size() != sizeBefore {
		return
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > logTrimLines {
		lines = lines[len(lines)-logTrimLines:]
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// TrimLogs trims every core log file that grew past the cap.
// Called from the panel's background poll loop, so a core that runs for
// months without a restart still can't grow its log forever. It scans the
// cores directory instead of the runner list, so logs of deleted nodes
// are covered too.
func (s *Supervisor) TrimLogs() {
	dir := filepath.Join(s.mgr.Dir, "cores")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		trimLogFile(filepath.Join(dir, e.Name()))
	}
}

// validRunnerName：监督器名字白名单。名字一旦来自用户输入，
// filepath.Join 会清理 ../，ClearLog 就能截断 cores 目录外的日志文件。
// 合法名只有 sing-box、mtg 与 mtg-<id>（id 是服务端生成的 hex）。
func validRunnerName(name string) bool {
	if name == "sing-box" || name == "mtg" {
		return true
	}
	if !strings.HasPrefix(name, "mtg-") {
		return false
	}
	suffix := strings.TrimPrefix(name, "mtg-")
	if suffix == "" {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ClearLog empties one core's log file immediately. Safe while the core
// is running: the supervisor holds the file O_APPEND, so later writes
// land at the new end instead of recreating a sparse file.
func (s *Supervisor) ClearLog(name string) {
	if !validRunnerName(name) {
		return
	}
	_ = os.Truncate(s.mgr.LogPath(name), 0)
}

func (s *Supervisor) Start(name string, args []string) error {
	return s.StartWithDir(name, args, "")
}

// StartWithDir is Start with a working directory for the process.
func (s *Supervisor) StartWithDir(name string, args []string, dir string) error {
	// 执行白名单：退役的 xray/hysteria 哪怕二进制还在磁盘上，也不许再拉起；
	// 只有 sing-box 与 mtg（及 mtg-<节点 id> 派生名）能进监督器，
	// 且派生名后缀只允许安全字符（防 ../ 跳出 cores 目录）。
	if !validRunnerName(name) {
		return fmt.Errorf("核心 %s 已退役或名字非法，拒绝启动", name)
	}
	r := s.get(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runningLocked() {
		// already running; restart only if args or dir changed
		same := len(r.args) == len(args) && r.dir == dir
		if same {
			for i := range args {
				if r.args[i] != args[i] {
					same = false
					break
				}
			}
		}
		if same {
			r.wanted = true
			return nil
		}
		s.stopLocked(r)
	} else {
		// 指针残留（进程已死、watch 还没清掉）：直接丢弃，
		// watch 随后看到指针已换会自行收手，不会双重处理。
		r.cmd = nil
	}
	r.wanted = true
	r.args = append([]string{}, args...)
	r.dir = dir
	if err := s.startLocked(r); err != nil {
		// 启动失败别留 wanted=true：没有进程、没有 watch，
		// 留着它只会让面板误以为“想要但没起来”是正常态。
		r.wanted = false
		return err
	}
	return nil
}

func (s *Supervisor) startLocked(r *Runner) error {
	// Defensive: never run two generations of the same runner at once.
	if r.runningLocked() {
		s.stopLocked(r)
	}
	bin := s.mgr.BinPath(binFor(r.Name))
	logPath := s.mgr.LogPath(r.Name)
	// 重启时顺手控量：超过 10MB 只留最新 2000 行，不再像以前那样整文件清空。
	trimLogFile(logPath)
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if r.logFile != nil {
		r.logFile.Close()
	}
	r.logFile = lf
	cmd := exec.Command(bin, r.args...)
	cmd.Dir = r.dir
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		lf.Close()
		return err
	}
	r.cmd = cmd
	r.done = make(chan struct{})
	r.startedAt = time.Now()
	go s.watch(r, cmd, r.done)
	// 连续稳定运行 60 秒清零重启计数：一次偶发崩溃不应让
	// 退避永久停在 30 秒档。
	go func(done chan struct{}, started time.Time) {
		select {
		case <-done:
			return
		case <-time.After(60 * time.Second):
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.cmd == cmd && r.startedAt == started {
			r.restarts = 0
		}
	}(r.done, r.startedAt)
	return nil
}

func (s *Supervisor) watch(r *Runner, cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()
	// 先关 done（不持锁）：stop 正等着它，持锁关会死锁。
	close(done)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != cmd {
		// Superseded: a newer start already replaced this process (e.g. via
		// Restart). The new process has its own watch; do nothing here.
		return
	}
	r.cmd = nil
	if !r.wanted {
		return
	}
	// unexpected exit: restart with backoff
	r.restarts++
	delay := 3 * time.Second
	if r.restarts > 5 {
		delay = 30 * time.Second
	}
	_ = err
	go func() {
		time.Sleep(delay)
		r.mu.Lock()
		defer r.mu.Unlock()
		// Only restart if nothing took over meanwhile (e.g. a Restart
		// during the backoff window must not produce a second process).
		if !r.wanted || r.cmd != nil {
			return
		}
		_ = s.startLocked(r)
	}()
}

func (s *Supervisor) stopLocked(r *Runner) {
	r.wanted = false
	if r.cmd != nil && r.cmd.Process != nil {
		// kill whole process group; wait only for watch's done.
		// SIGKILL 之后也封顶 5 秒：僵在 D 状态的进程等多久都没用，
		// 不能把面板写操作无限期卡在这里；watch 随后收尾。
		done := r.done
		pid := r.cmd.Process.Pid
		syscall.Kill(-pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			syscall.Kill(-pid, syscall.SIGKILL)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
		r.cmd = nil
	}
	if r.logFile != nil {
		r.logFile.Close()
		r.logFile = nil
	}
}

// Stop halts a core.
func (s *Supervisor) Stop(name string) {
	r := s.get(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	s.stopLocked(r)
}

// Restart stops and starts a core with new args.
func (s *Supervisor) Restart(name string, args []string) error {
	return s.RestartWithDir(name, args, "")
}

// RestartWithDir is Restart with a working directory for the process.
func (s *Supervisor) RestartWithDir(name string, args []string, dir string) error {
	r := s.get(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	s.stopLocked(r)
	r.wanted = true
	r.args = append([]string{}, args...)
	r.dir = dir
	if err := s.startLocked(r); err != nil {
		r.wanted = false
		return err
	}
	return nil
}

type Status struct {
	Name      string    `json:"name"`
	Running   bool      `json:"running"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Restarts  int       `json:"restarts"`
}

func (s *Supervisor) Status(name string) Status {
	r := s.get(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{Name: name, StartedAt: r.startedAt, Restarts: r.restarts}
	if r.runningLocked() {
		st.Running = true
		st.PID = r.cmd.Process.Pid
	}
	return st
}

// Names returns all supervised runner names.
func (s *Supervisor) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.runners))
	for n := range s.runners {
		out = append(out, n)
	}
	return out
}

// StopAll halts every supervised core.
func (s *Supervisor) StopAll() {
	s.mu.Lock()
	names := make([]string, 0, len(s.runners))
	for n := range s.runners {
		names = append(names, n)
	}
	s.mu.Unlock()
	for _, n := range names {
		s.Stop(n)
	}
}
