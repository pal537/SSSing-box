# SSSing-box

单页面代理面板：一个页面管全部节点，基于 sing-box 内核，支持 12 种协议。

**预设最佳配置，一键安装，一键配置，极简。** 节点默认就是最优档位（VLESS + Reality + TCP + xtls-rprx-vision 等），不用一个个参数调；装完就能用，不用再配。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | bash
```

装完直接打印面板地址、账号、密码（自动生成，不用打开初始化页面）。也可以自定义（环境变量写在 bash 前面）：

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | SSSINGBOX_USER=xxxx SSSINGBOX_PASS=xxxx SSSINGBOX_PORT=18081 bash
```

![节点列表](docs/screenshots/1-nodes.png)
![添加节点](docs/screenshots/2-add.png)
![订阅](docs/screenshots/3-sub.png)

## 支持的协议

VLESS、Hysteria2、MTProto、VMess、Shadowsocks、SOCKS5、HTTP、Trojan、WireGuard、TUIC、AnyTLS、Naive（含 Reality / WS / H2 / HTTPUpgrade / CF 等搭建方式）。

## SSH 菜单

```bash
sssingbox
```

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | bash -s uninstall   # 数据目录保留，彻底删除：rm -rf /var/lib/sssingbox
```

本地已有 install.sh 时，`bash install.sh uninstall` 也一样。

## 自己编译

```bash
go build -o sssingbox .
./sssingbox -data /var/lib/sssingbox -port 18081
```

不带版本号编译出来是 dev 版，在线更新会拒绝 dev 版；需要版本号时编译加 `-ldflags "-X sssingbox/internal/version.Version=<标签>"`。
