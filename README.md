# 驿站

单页面代理面板：一个页面管全部节点，基于 sing-box 内核，支持 12 种协议。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/yizhan/main/install.sh | bash
```

装完直接打印面板地址、账号、密码（自动生成，不用打开初始化页面）。也可以自定义：

```bash
YIZHAN_USER=admin YIZHAN_PASS=xxxx YIZHAN_PORT=18081 bash install.sh
```

![节点列表](docs/screenshots/1-nodes.png)
![添加节点](docs/screenshots/2-add.png)
![订阅](docs/screenshots/3-sub.png)

## 支持的协议

VLESS、Hysteria2、MTProto、VMess、Shadowsocks、SOCKS5、HTTP、Trojan、WireGuard、TUIC、AnyTLS、Naive（含 Reality / WS / H2 / HTTPUpgrade / CF 等搭建方式）。

## 不用面板：SSH 命令行管理

```bash
yizhan menu          # 交互菜单：选协议、填参数，自动建节点
yizhan node list     # 节点列表
yizhan node add -protocol vless -mode reality   # 命令行建节点
yizhan node rm <id/端口/名字>
yizhan node on|off <id/端口/名字>
yizhan status        # 面板状态
yizhan sub           # 订阅链接
yizhan admin reset   # 重置管理员密码
```

装完就能用 `yizhan` 命令（安装器已写好 CLI 凭证）；面板里改过密码后跑 `yizhan login` 重新保存。

## 卸载

```bash
bash install.sh uninstall   # 数据目录保留，彻底删除：rm -rf /var/lib/yizhan
```

## 自己编译

```bash
go build -o yizhan .
./yizhan -data /var/lib/yizhan -port 18081
```

