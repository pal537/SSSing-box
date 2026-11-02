package cli

// v1.1.4：改面板端口的纯函数测试（不碰真服务文件）。

import (
	"net"
	"strings"
	"testing"
)

func TestRewriteServicePort(t *testing.T) {
	src := "[Unit]\nDescription=sssingbox面板\n\n[Service]\nExecStart=/usr/local/bin/sssingbox -data /var/lib/sssingbox -port 18081\nRestart=always\n"
	got, err := rewriteServicePort(src, 19090)
	if err != nil {
		t.Fatalf("应改成功：%v", err)
	}
	if !strings.Contains(got, "-port 19090") {
		t.Fatalf("ExecStart 端口应改为 19090，得到：\n%s", got)
	}
	if !strings.Contains(got, "Description=sssingbox面板") || !strings.Contains(got, "Restart=always") {
		t.Fatalf("其他行应原样保留，得到：\n%s", got)
	}
	if strings.Contains(got, "-port 18081") {
		t.Fatal("旧端口不应残留")
	}
}

func TestRewriteServicePortNoFlag(t *testing.T) {
	src := "[Service]\nExecStart=/usr/local/bin/sssingbox -data /var/lib/sssingbox\n"
	if _, err := rewriteServicePort(src, 19090); err == nil {
		t.Fatal("ExecStart 里没有 -port 时应报错")
	}
}

func TestRewriteServicePortIgnoresNonExecStart(t *testing.T) {
	src := "# 注释里提 -port 18081 一嘴\n[Service]\nExecStart=/usr/local/bin/sssingbox -data /var/lib/sssingbox -port 18081\n"
	got, err := rewriteServicePort(src, 19090)
	if err != nil {
		t.Fatalf("应改成功：%v", err)
	}
	if !strings.Contains(got, "# 注释里提 -port 18081 一嘴") {
		t.Fatal("注释行不应被改")
	}
}

func TestPortAvailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占位监听失败：%v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if portAvailable(port) {
		ln.Close()
		t.Fatal("已被占用的端口应判为不可用")
	}
	ln.Close()
	if !portAvailable(port) {
		t.Fatalf("空闲端口 %d 应判为可用", port)
	}
}
