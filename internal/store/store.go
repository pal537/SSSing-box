package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the panel's SQLite database.
type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	ddl := `
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS inbounds(id TEXT PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, address TEXT NOT NULL, sni TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, config TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, quota_mode TEXT NOT NULL DEFAULT '', quota_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS bnodes(id TEXT PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, link TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS chains(id TEXT PRIMARY KEY, name TEXT NOT NULL, inbound_id TEXT NOT NULL, list TEXT NOT NULL DEFAULT '', bnode_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_total(inbound_id TEXT PRIMARY KEY, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_daily(date TEXT NOT NULL, inbound_id TEXT NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(date, inbound_id));
CREATE TABLE IF NOT EXISTS cores(name TEXT PRIMARY KEY, version TEXT NOT NULL DEFAULT '', installed INTEGER NOT NULL DEFAULT 0, latest TEXT NOT NULL DEFAULT '', last_check INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_inbounds_port ON inbounds(port);
CREATE INDEX IF NOT EXISTS idx_daily_date ON traffic_daily(date);
`
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}
	// 老库升级：inbounds 表建于 quota 字段之前时，补两列。
	rows, err := s.db.Query("PRAGMA table_info(inbounds)")
	if err != nil {
		return err
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err == nil {
			cols[name] = true
		}
	}
	rows.Close()
	if !cols["quota_mode"] {
		if _, err := s.db.Exec("ALTER TABLE inbounds ADD COLUMN quota_mode TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !cols["quota_bytes"] {
		if _, err := s.db.Exec("ALTER TABLE inbounds ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	return nil
}

// ---- settings ----

func (s *Store) GetSetting(key string) string {
	v, _ := s.GetSettingErr(key)
	return v
}

// GetSettingErr 区分“确实不存在”与“读失败”：main 启动时只有确实不存在
// 才生成新订阅 token，读失败时绝不覆盖旧 token（否则已发出的订阅全失效）。
func (s *Store) GetSettingErr(key string) (string, error) {
	var v string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

// ---- users ----

func (s *Store) CreateUser(username, passHash string) error {
	_, err := s.db.Exec("INSERT INTO users(username,pass_hash,created_at) VALUES(?,?,?)", username, passHash, time.Now().Unix())
	return err
}

func (s *Store) GetUser(username string) (passHash string, err error) {
	err = s.db.QueryRow("SELECT pass_hash FROM users WHERE username=?", username).Scan(&passHash)
	return
}

func (s *Store) UserCount() int {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n
}

func (s *Store) UpdatePassword(username, passHash string) error {
	_, err := s.db.Exec("UPDATE users SET pass_hash=? WHERE username=?", passHash, username)
	return err
}

// RenameUser 改账号名。调用方先保证新名不存在；影响 0 行说明旧账号不存在。
func (s *Store) RenameUser(old, new string) error {
	res, err := s.db.Exec("UPDATE users SET username=? WHERE username=?", new, old)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("账号 %s 不存在", old)
	}
	return nil
}

// ListUsers 按创建时间列出全部账号（面板只有一个管理员时就是一个）。
func (s *Store) ListUsers() []string {
	rows, err := s.db.Query("SELECT username FROM users ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// ---- inbounds ----

type Inbound struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"` // vless | hy2 | mtg
	Port       int    `json:"port"`
	Address    string `json:"address"`
	SNI        string `json:"sni"`
	Enabled    bool   `json:"enabled"`
	Config     string `json:"config"` // protocol-specific JSON (raw)
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	QuotaMode  string `json:"quota_mode"`  // "" = 不限, "total" = 上下行合计, "down" = 仅下行
	QuotaBytes int64  `json:"quota_bytes"` // 限额字节数（面板 GB = 1024^3）
}

func (s *Store) UpsertInbound(in *Inbound) error {
	en := 0
	if in.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO inbounds(id,name,protocol,port,address,sni,enabled,config,created_at,updated_at,quota_mode,quota_bytes)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,port=excluded.port,address=excluded.address,sni=excluded.sni,enabled=excluded.enabled,config=excluded.config,updated_at=excluded.updated_at,quota_mode=excluded.quota_mode,quota_bytes=excluded.quota_bytes`,
		in.ID, in.Name, in.Protocol, in.Port, in.Address, in.SNI, en, in.Config, in.CreatedAt, in.UpdatedAt, in.QuotaMode, in.QuotaBytes)
	return err
}

func (s *Store) DeleteInbound(id string) error {
	// 四删放同一事务：以前分开执行、后两条错误被丢弃，节点行已删、
	// 流量行残留会出现无主节点的孤儿流量；链式以前在 handler 里
	// 事后删、失败也是静默丢弃，孤儿链只能靠 Apply 兜底——现在
	// 链式也进事务，删节点要么全清、要么全留。
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM inbounds WHERE id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM traffic_total WHERE inbound_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM traffic_daily WHERE inbound_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM chains WHERE inbound_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetInbound(id string) (*Inbound, error) {
	var in Inbound
	var en int
	err := s.db.QueryRow("SELECT id,name,protocol,port,address,sni,enabled,config,created_at,updated_at,quota_mode,quota_bytes FROM inbounds WHERE id=?", id).Scan(
		&in.ID, &in.Name, &in.Protocol, &in.Port, &in.Address, &in.SNI, &en, &in.Config, &in.CreatedAt, &in.UpdatedAt, &in.QuotaMode, &in.QuotaBytes)
	if err != nil {
		return nil, err
	}
	in.Enabled = en == 1
	return &in, nil
}

func (s *Store) ListInbounds() ([]*Inbound, error) {
	rows, err := s.db.Query("SELECT id,name,protocol,port,address,sni,enabled,config,created_at,updated_at,quota_mode,quota_bytes FROM inbounds ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Inbound
	for rows.Next() {
		var in Inbound
		var en int
		if err := rows.Scan(&in.ID, &in.Name, &in.Protocol, &in.Port, &in.Address, &in.SNI, &en, &in.Config, &in.CreatedAt, &in.UpdatedAt, &in.QuotaMode, &in.QuotaBytes); err != nil {
			return nil, err
		}
		in.Enabled = en == 1
		out = append(out, &in)
	}
	return out, rows.Err()
}

func (s *Store) PortInUse(port int, excludeID string) bool {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM inbounds WHERE port=? AND id!=?", port, excludeID).Scan(&n)
	return n > 0
}

// ---- bnodes (saved outbound nodes for chaining) ----

type BNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Link      string `json:"link"`
	Config    string `json:"config"` // parsed outbound JSON (raw)
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) UpsertBNode(b *BNode) error {
	_, err := s.db.Exec(`INSERT INTO bnodes(id,name,protocol,link,config,created_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,link=excluded.link,config=excluded.config`,
		b.ID, b.Name, b.Protocol, b.Link, b.Config, b.CreatedAt)
	return err
}

func (s *Store) DeleteBNode(id string) error {
	// B 节点与挂它的链式同一事务：以前 handler 事后删链、失败
	// 静默丢弃，孤儿链只能靠 Apply 兜底。
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM bnodes WHERE id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM chains WHERE bnode_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetBNode(id string) (*BNode, error) {
	var b BNode
	err := s.db.QueryRow("SELECT id,name,protocol,link,config,created_at FROM bnodes WHERE id=?", id).Scan(
		&b.ID, &b.Name, &b.Protocol, &b.Link, &b.Config, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) ListBNodes() ([]*BNode, error) {
	rows, err := s.db.Query("SELECT id,name,protocol,link,config,created_at FROM bnodes ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BNode
	for rows.Next() {
		var b BNode
		if err := rows.Scan(&b.ID, &b.Name, &b.Protocol, &b.Link, &b.Config, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// ---- chains ----

type Chain struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	InboundID string `json:"inbound_id"`
	List      string `json:"list"` // one domain/IP/CIDR per line
	BNodeID   string `json:"bnode_id"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) UpsertChain(c *Chain) error {
	en := 0
	if c.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO chains(id,name,inbound_id,list,bnode_id,enabled,created_at) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,inbound_id=excluded.inbound_id,list=excluded.list,bnode_id=excluded.bnode_id,enabled=excluded.enabled`,
		c.ID, c.Name, c.InboundID, c.List, c.BNodeID, en, c.CreatedAt)
	return err
}

func (s *Store) DeleteChain(id string) error {
	_, err := s.db.Exec("DELETE FROM chains WHERE id=?", id)
	return err
}

func (s *Store) ListChains() ([]*Chain, error) {
	rows, err := s.db.Query("SELECT id,name,inbound_id,list,bnode_id,enabled,created_at FROM chains ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Chain
	for rows.Next() {
		var c Chain
		var en int
		if err := rows.Scan(&c.ID, &c.Name, &c.InboundID, &c.List, &c.BNodeID, &en, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, &c)
	}
	return out, rows.Err()
}

// ---- traffic ----

func (s *Store) AddTraffic(inboundID string, up, down int64) error {
	now := time.Now()
	date := now.Format("2006-01-02")
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO traffic_total(inbound_id,up,down,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(inbound_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down, updated_at=excluded.updated_at`,
		inboundID, up, down, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO traffic_daily(date,inbound_id,up,down) VALUES(?,?,?,?)
		ON CONFLICT(date,inbound_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`,
		date, inboundID, up, down); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TotalTraffic() (map[string][2]int64, error) {
	rows, err := s.db.Query("SELECT inbound_id,up,down FROM traffic_total")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var id string
		var up, down int64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		out[id] = [2]int64{up, down}
	}
	return out, rows.Err()
}

func (s *Store) DailyTraffic(date string) (map[string][2]int64, error) {
	rows, err := s.db.Query("SELECT inbound_id,up,down FROM traffic_daily WHERE date=?", date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var id string
		var up, down int64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		out[id] = [2]int64{up, down}
	}
	return out, rows.Err()
}

func (s *Store) MonthlyTraffic(yearMonth string) (map[string][2]int64, error) {
	rows, err := s.db.Query("SELECT inbound_id,SUM(up),SUM(down) FROM traffic_daily WHERE substr(date,1,7)=? GROUP BY inbound_id", yearMonth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var id string
		var up, down int64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		out[id] = [2]int64{up, down}
	}
	return out, rows.Err()
}

// ---- cores ----

type Core struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Latest    string `json:"latest"`
	LastCheck int64  `json:"last_check"`
}

func (s *Store) UpsertCore(c *Core) error {
	ins := 0
	if c.Installed {
		ins = 1
	}
	_, err := s.db.Exec(`INSERT INTO cores(name,version,installed,latest,last_check) VALUES(?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET version=excluded.version,installed=excluded.installed,latest=excluded.latest,last_check=excluded.last_check`,
		c.Name, c.Version, ins, c.Latest, c.LastCheck)
	return err
}

func (s *Store) ListCores() ([]*Core, error) {
	rows, err := s.db.Query("SELECT name,version,installed,latest,last_check FROM cores")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Core
	for rows.Next() {
		var c Core
		var ins int
		if err := rows.Scan(&c.Name, &c.Version, &ins, &c.Latest, &c.LastCheck); err != nil {
			return nil, err
		}
		c.Installed = ins == 1
		out = append(out, &c)
	}
	return out, rows.Err()
}

// ---- helpers ----

func MustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func JSONErr(err error) string { return fmt.Sprintf("%v", err) }
