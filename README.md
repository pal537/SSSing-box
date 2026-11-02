# SSSing-box

单页面代理面板：一个页面管全部节点，基于 sing-box 内核，支持 12 种协议。

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

## 不用面板：SSH 命令行管理

直接运行一个命令就进交互菜单，所有功能都在里面，不用记一堆命令：

```bash
sssingbox
```

菜单里有：创建节点、节点列表、删除节点、启用/停用节点、面板状态、订阅链接、安装/更新内核、查看登录信息、修改登录账号、修改登录密码、修改面板端口、重置管理员密码。

装完就能用（安装器已写好 CLI 凭证）；面板里改账号密码后 CLI 凭证由面板同步更新。

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

