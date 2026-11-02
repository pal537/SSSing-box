package cores

// v1.1.8：手动“检查更新”必须绕过 1 小时 Release 缓存，否则刚发的新版查不到。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestListReleasesCacheAndFresh(t *testing.T) {
	var mu sync.Mutex
	tags := []string{"v1.1.5"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var out []ghRelease
		for _, tg := range tags {
			out = append(out, ghRelease{TagName: tg})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	// 第一次拉到 v1.1.5，写进缓存。
	rels, err := ListReleases("test/panel-cache")
	if err != nil || len(rels) == 0 || rels[0].Tag != "v1.1.5" {
		t.Fatalf("首次应拉到 v1.1.5，得到 %v 错误 %v", rels, err)
	}
	// 上游已出 v1.1.7，缓存期内普通查询仍应返回旧值（这就是用户遇到的现象）。
	mu.Lock()
	tags = []string{"v1.1.7", "v1.1.5"}
	mu.Unlock()
	rels, err = ListReleases("test/panel-cache")
	if err != nil || rels[0].Tag != "v1.1.5" {
		t.Fatalf("缓存期内普通查询应仍是 v1.1.5，得到 %v 错误 %v", rels, err)
	}
	// 强制刷新应拿到 v1.1.7，并且刷新缓存。
	rels, err = ListReleasesFresh("test/panel-cache")
	if err != nil || rels[0].Tag != "v1.1.7" {
		t.Fatalf("强制刷新应拿到 v1.1.7，得到 %v 错误 %v", rels, err)
	}
	rels, err = ListReleases("test/panel-cache")
	if err != nil || rels[0].Tag != "v1.1.7" {
		t.Fatalf("强制刷新后缓存应已是 v1.1.7，得到 %v 错误 %v", rels, err)
	}
}
