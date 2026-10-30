#!/bin/bash
# sssingbox面板一键安装脚本。
#
# 一键命令（默认自动生成面板账号密码，不用打开初始化页面）：
#   curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | bash
# 自定义（环境变量写在 bash 前面，不设则账号密码都随机生成）：
#   curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | SSSINGBOX_USER=xxxx SSSINGBOX_PASS=xxxx SSSINGBOX_PORT=18081 bash
# 本地安装包模式：
#   bash install.sh --from-file sssingbox-linux-amd64.tar.gz [--port 18081] [--data-dir /var/lib/sssingbox]
#   安装包是 tar.gz，根目录含一个 sssingbox 二进制。
# 卸载（保留数据目录，彻底删除见提示）：
#   curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | bash -s uninstall
#   本地已有 install.sh 时，bash install.sh uninstall 也一样。
#
# 重装 = 更新：已装过时脚本会备份旧二进制（sssingbox.bak-YYYYMMDDHHMMSS），
# 换上新二进制并重启服务；已有管理员时跳过初始化，不覆盖旧账号。
set -euo pipefail

BIN_DIR="/usr/local/bin"
BIN_PATH="$BIN_DIR/sssingbox"
SERVICE="sssingbox"
PORT="${SSSINGBOX_PORT:-18081}"
DATA_DIR="/var/lib/sssingbox"
FROM_FILE=""
REPO="${SSSINGBOX_REPO:-pal537/SSSing-box}"

if [ "${1:-}" = "uninstall" ]; then
	echo "正在卸载sssingbox..."
	systemctl stop "$SERVICE" 2>/dev/null || true
	systemctl disable "$SERVICE" 2>/dev/null || true
	rm -f "/etc/systemd/system/$SERVICE.service" "$BIN_PATH"
	systemctl daemon-reload 2>/dev/null || true
	echo "已卸载。数据目录 $DATA_DIR 已保留，彻底删除请执行：rm -rf $DATA_DIR"
	exit 0
fi

usage() {
	echo "用法：bash install.sh [--from-file 安装包.tar.gz] [--port 端口] [--data-dir 数据目录]"
	echo "  --from-file  本地安装包（tar.gz，根目录含 sssingbox 二进制）"
	echo "  --port       面板端口（默认 18081）"
	echo "  --data-dir   数据目录（默认 /var/lib/sssingbox）"
	echo "  环境变量 SSSINGBOX_REPO=owner/repo：默认 pal537/SSSing-box，不设就用默认仓库下载；--from-file 时用本地安装包，不走 GitHub。"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--from-file) FROM_FILE="$2"; shift 2 ;;
		--port) PORT="$2"; shift 2 ;;
		--data-dir) DATA_DIR="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "未知参数：$1"; usage; exit 1 ;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "错误：请用 root 运行（需要写 /usr/local/bin 与 systemd）"
	exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
	x86_64|amd64) ARCH="amd64" ;;
	aarch64|arm64) ARCH="arm64" ;;
	*) echo "错误：不支持的架构 $ARCH（只支持 amd64/arm64）"; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$FROM_FILE" ]; then
	echo "本地安装包模式：$FROM_FILE"
	tar xzf "$FROM_FILE" -C "$WORK"
else
	echo "GitHub 发布模式：$REPO（linux-$ARCH）"
	ASSET="sssingbox-linux-$ARCH.tar.gz"
	TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || true)"
	if [ -n "$TAG" ]; then
		echo "下载 $TAG/$ASSET ..."
		curl -fsSL -o "$WORK/$ASSET" "https://github.com/$REPO/releases/download/$TAG/$ASSET"
		# 有校验文件就验，没有就明说（不静默跳过校验这件事）
		if curl -fsSL -o "$WORK/$ASSET.sha256" "https://github.com/$REPO/releases/download/$TAG/$ASSET.sha256" 2>/dev/null; then
			(cd "$WORK" && sha256sum -c "$ASSET.sha256")
		else
			echo "注意：该发布没有提供 sha256 校验文件，跳过校验。"
		fi
	else
		# API 取不到 tag 时走 latest 重定向（不依赖 api.github.com）。
		echo "API 取不到最新 tag，改走 latest 下载 ..."
		curl -fsSL -o "$WORK/$ASSET" "https://github.com/$REPO/releases/latest/download/$ASSET"
	fi
	tar xzf "$WORK/$ASSET" -C "$WORK"
fi

if [ ! -x "$WORK/sssingbox" ]; then
	echo "错误：安装包里没有可执行的 sssingbox 二进制"
	exit 1
fi
echo "二进制自检：$("$WORK/sssingbox" -version)"

mkdir -p "$DATA_DIR"
if [ -x "$BIN_PATH" ]; then
	BAK="$BIN_DIR/sssingbox.bak-$(date +%Y%m%d%H%M%S)"
	cp "$BIN_PATH" "$BAK"
	echo "旧二进制已备份到 $BAK"
fi
install -m 0755 "$WORK/sssingbox" "$BIN_PATH"

cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=sssingbox面板
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH -data $DATA_DIR -port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 2
if ! systemctl is-active --quiet "$SERVICE"; then
	echo "错误：服务启动失败，看日志：journalctl -u $SERVICE -n 50"
	exit 1
fi
echo "等待面板端口就绪..."
for i in $(seq 1 30); do
	if curl -fs -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/"; then
		break
	fi
	sleep 1
	if [ "$i" = "30" ]; then
		echo "面板 30 秒还没起来，请看日志：journalctl -u $SERVICE -n 50"
		exit 1
	fi
done

# 初始化账号：已有管理员时（升级重装）跳过，不覆盖旧账号。
# 账号密码默认都自动生成（账号绝不默认 admin），不用打开初始化页面；
# CLI 凭证一并写好，sssingbox 命令开箱即用。
USER_NAME="${SSSINGBOX_USER:-}"
USER_GENERATED=""
if [ -z "$USER_NAME" ]; then
	USER_NAME="$(head -c 256 /dev/urandom | tr -dc 'abcdefghjkmnpqrstuvwxyz' | head -c 1)$(head -c 256 /dev/urandom | tr -dc 'abcdefghjkmnpqrstuvwxyz23456789' | head -c 7)"
	USER_GENERATED=1
fi
PASS="${SSSINGBOX_PASS:-}"
GENERATED=""
if [ -z "$PASS" ]; then
	PASS="$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)"
	GENERATED=1
fi
SETUP_OUT="$(curl -s --max-time 10 -X POST "http://127.0.0.1:$PORT/api/setup" \
	-H 'Content-Type: application/json' \
	-d "{\"username\":\"$USER_NAME\",\"password\":\"$PASS\",\"password2\":\"$PASS\"}")"
SETUP_OK=0
if echo "$SETUP_OUT" | grep -q '"ok":true'; then
	printf '{"username":"%s","password":"%s"}' "$USER_NAME" "$PASS" > "$DATA_DIR/.cli-credentials"
	chmod 600 "$DATA_DIR/.cli-credentials"
	SETUP_OK=1
else
	echo "面板已有管理员，跳过初始化（旧账号不变）"
fi

# 防火墙放行（尽力而为，失败不中断安装）
if command -v ufw >/dev/null 2>&1; then ufw allow "$PORT/tcp" >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; fi

IP="$(curl -s --max-time 5 ifconfig.me || true)"
if [ -z "$IP" ]; then IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
if [ -z "$IP" ]; then IP="服务器IP"; fi
echo ""
echo "================ SSSing-box安装完成 ================"
echo "面板地址：http://$IP:$PORT/"
if [ "$SETUP_OK" = "1" ]; then
	echo "面板账号：$USER_NAME"
	echo "面板密码：$PASS"
	if [ -n "$GENERATED" ] || [ -n "$USER_GENERATED" ]; then echo "（账号/密码为自动生成，请保存好）"; fi
else
	echo "面板账号：沿用旧账号（CLI 凭证没动过的话，sssingbox 命令仍可用；改过密码请跑 sssingbox login）"
fi
echo "SSH 管理：sssingbox menu（交互菜单，不用打开面板就能建节点）"
echo "卸载：curl -fsSL https://raw.githubusercontent.com/pal537/SSSing-box/main/install.sh | bash -s uninstall（数据目录保留）"
echo "=============================================="
