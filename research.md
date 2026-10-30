# sssingbox面板调研：配置细节

> 调研日期：2026-10-29
> 目的：给新做的极简多协议代理面板（暂名「sssingbox」）提供可落地的配置字段与命令，供开发时直接照抄。
> 资料来源：XTLS 官方文档（xtls.github.io）、sing-box 官方文档（sing-box.sagernet.org）、Hysteria 官方文档（hysteria.network / v2.hysteria.network）、9seconds/mtg 官方文档（pkg.go.dev 镜像的仓库 README）、3x-ui 入站结构（以 3x-ui API 兼容层 go-x3ui / gox-ui 的结构体为准，与 3x-ui 入站表单一一对应；3x-ui 官方前端源码未逐行通读，个别面板语义标注「未确认」）。
> 原则：凡是没查到的写「未确认」，不编。示例里的密钥、UUID、IP 均为占位。

---

## 1. 3x-ui 入站表单：VLESS + Reality 全部字段

### 1.1 入站级字段（3x-ui 的 AddInbound / Inbound）

| 字段 | 说明 | 简单 / 高级 |
|---|---|---|
| remark | 备注，即节点名。面板默认自动生成短名，可手动改 | 简单 |
| enable | 是否启用（true/false） | 简单 |
| listen | 监听地址，默认空（= 0.0.0.0）。填 127.0.0.1 则只本机可连 | 高级 |
| port | 监听端口。面板默认自动建议（443 能用推 443） | 简单 |
| protocol | 协议名，`vless` | 固定 |
| tag | 入站 tag，面板自动生成（xray 路由/统计用），用户不用填 | 内置 |
| expiryTime | 入站级到期时间，毫秒时间戳，0 = 不限 | 高级（3x-ui 表单有，sssingbox可默认不限） |
| up / down / total | 面板维护的流量计数（字节），不是 xray 配置项 | 面板字段 |
| settings | JSON 字符串，见 1.2 | — |
| streamSettings | JSON 字符串，见 1.3 | — |
| sniffing | JSON 字符串，见 1.5 | 高级 |
| allocate | JSON 字符串，见 1.6 | 高级（基本不用） |
| clientStats[] | 每客户端统计：email、up、down、expiryTime、total、enable、reset | 面板字段 |

### 1.2 settings（VLESS）

| 字段 | 说明 |
|---|---|
| clients[] | 客户端列表，见 1.3 |
| decryption | 固定 `"none"`（Reality + Vision 不再做协议内加密） |
| fallbacks[] | VLESS fallback 列表。3x-ui 一般不用，sssingbox高级配置里保留入口即可 |

### 1.3 客户端字段（InboundClient，即 3x-ui 表单里的「客户」）

| 字段 | 说明 | 简单 / 高级 |
|---|---|---|
| id | UUID，即 VLESS 用户标识。面板自动生成 | 内置（高级可查看） |
| flow | 流控。Reality 固定 `xtls-rprx-vision`；空 = 不用 Vision | 内置（固定 vision） |
| email | 面板内标识（常被用作用户名/备注），同时是 xray `user>>>email>>>traffic` 统计的 key | 简单（默认自动生成） |
| limitIp | 限设备/IP 数，0 = 不限 | 高级 |
| totalGB | 流量上限（GB），0 = 不限 | 高级 |
| expiryTime | 客户端到期，毫秒时间戳，0 = 不限 | 高级 |
| enable | 是否启用该客户端 | 简单 |
| tgId | 关联的 Telegram ID（3x-ui 的 TG 机器人用），sssingbox没有 TG 机器人可不做 | 可不做 |
| subId | 订阅 ID（3x-ui 订阅功能用），sssingbox订阅链接用自己的规则即可 | 可不做 |
| reset | 面板侧流量统计字段，具体语义（疑似按月重置日）**未确认** | 面板字段 |

> sssingbox一键建节点时，客户端只保留一个（单用户），其余多用户管理是 3x-ui 的复杂来源之一，sssingbox不做。

### 1.4 streamSettings（VLESS + TCP + Reality）

```
network = "tcp"
security = "reality"
tcpSettings.acceptProxyProtocol = false
tcpSettings.header.type = "none"
externalProxy = []   // 3x-ui 结构里的保留字段，sssingbox不用
```

realitySettings（服务端，3x-ui 表单暴露的全部项）：

| 字段 | 说明 | 简单 / 高级 |
|---|---|---|
| dest | 探测回落地址，格式 `域名:443`，必须与 serverNames 之一一致。未通过鉴权的握手会被原样转发到这里 | 简单（= 伪装域名 + :443） |
| serverNames[] | 接受的 SNI 列表。面板默认只放一个，即用户选的伪装域名 | 简单（= 伪装域名） |
| privateKey | 服务端 x25519 私钥，`xray x25519` 生成，绝不下发给客户端 | 内置 |
| shortIds[] | 允许的 shortId 列表。面板默认生成一个 16 字符 hex，或放 `[""]` 表示不校验 | 内置 |
| settings.publicKey | 由 privateKey 派生的公钥，写进客户端链接（pbk） | 内置 |
| settings.fingerprint | uTLS 指纹，即客户端 TLS 握手模仿的浏览器：chrome / firefox / safari / ios / android / edge / 360 / qq / random / randomized。面板默认 chrome | 高级（默认 chrome） |
| settings.serverName | 客户端侧 SNI，= serverNames[0] | 内置 |
| settings.spiderX | Reality 爬虫起始路径，默认 `"/"` | 内置 |
| show | 调试开关，生产固定 false | 内置 |
| xver | PROXY protocol 版本，0 = 关闭，1 / 2 = 开启。面板固定 0 | 内置 |

xray-core 新版 realitySettings 还有以下字段（3x-ui 表单未必暴露，sssingbox高级配置应一并支持，避免缺项）：

| 字段 | 说明 |
|---|---|
| minClientVer / maxClientVer | 客户端版本范围限制，如 `"1.8.0"` / `""` |
| maxTimeDiff | 客户端与服务端时间差容忍（秒），0 = 不限制 |
| target | dest 的旧别名，二者填一个即可，sssingbox只用 dest |
| mldsa65Seed / mldsa65Verify | ML-DSA 后量子签名（xray-core v25.x+ 新引入），旧版没有 |
| limitFallbackUpload / limitFallbackDownload | 回落流量的限速 |
| masterKeyLog | 调试用密钥日志路径，生产不用 |

### 1.5 关于 alpn、allowInsecure、uTLS——特此说明

- **uTLS = fingerprint 字段**（见上表），不是独立字段。3x-ui 表单里的「uTLS」下拉框就是 fingerprint。
- **alpn：xray-core 的 realitySettings 里没有这个字段**（以 `infra/conf` 的 REALITYConfig 结构为准）。ALPN 是 tlsSettings 的字段，Reality 不用。3x-ui 在 security=reality 时不展示 ALPN。
- **allowInsecure：xray-core 的 realitySettings 里也没有这个字段**。它只出现在部分客户端示例/旧文档的 realitySettings 里，服务端不用填；Reality 的信任锚是 publicKey，不是证书链，所以不存在「跳过证书验证」这个概念。
- **TLS 侧字段（仅当 security=tls 时出现，与 Reality 互斥）**：certs[]（证书文件路径或证书内容）、alpn[]、minVersion / maxVersion、cipherSuites[]、fingerprint、allowInsecure、rejectUnknownSni、ECH（echServerKeys / echConfigList / echForceQuery）。sssingbox只做 Reality 时可以不做 TLS 入站，但高级配置清单里应知道它们的存在，避免日后补 TLS 入站时缺项。

### 1.6 sniffing（流量嗅探，链式域名分流必须开）

| 字段 | 说明 |
|---|---|
| enabled | true。域名分流靠它识别目标域名（TLS SNI / HTTP Host），不开则域名规则不生效 |
| destOverride | `["http", "tls"]`（可加 `"quic"`）。嗅探到域名后是否覆盖目标地址 |
| metadataOnly | 只嗅探元数据，不改目标。链式场景一般 false |
| routeOnly | true = 只把嗅探结果用于路由，不改目标地址。域名分流推荐 true（避免改写目标） |

> 注意：VLESS + Vision 入站开 sniffing 不影响 Vision 工作，二者可共存。

### 1.7 allocate（端口分配，3x-ui 保留项）

| 字段 | 说明 |
|---|---|
| strategy | `always` / `random` 等（具体取值**未确认**） |
| refresh | 刷新间隔 |
| concurrency | 并发数 |

sssingbox固定端口场景用不到，列为保留项，高级配置里可隐藏。

### 1.8 客户端订阅链接格式（VLESS + Reality + Vision）

```
vless://<UUID>@<节点地址>:<端口>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<伪装域名>&fp=chrome&pbk=<公钥>&sid=<shortId>&spx=%2F&type=tcp#<节点名>
```

注意点：`spx` 默认 `/`，URL 里必须编码为 `%2F`；`sid` 取 shortIds[0]；`fp` 默认 chrome；`pbk` 是公钥不是私钥；节点地址（客户端连哪里）和 sni（伪装成谁）是两个字段，别混淆。

---
## 2. xray-core JSON 配置

### 2.1 入站完整示例：VLESS + TCP + Reality + xtls-rprx-vision

下面是一份可直接落地的服务端 config.json（含统计 API 与链式出站位，`<>` 为占位）：

```json
{
  "log": { "loglevel": "warning", "access": "none", "error": "" },
  "stats": {},
  "policy": {
    "levels": {
      "0": { "statsUserUplink": true, "statsUserDownlink": true }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "api": { "tag": "api", "services": ["StatsService"] },
  "inbounds": [
    {
      "tag": "vless-reality",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "<UUID>", "flow": "xtls-rprx-vision", "email": "<节点名或标识>" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "<伪装域名>:443",
          "xver": 0,
          "serverNames": ["<伪装域名>"],
          "privateKey": "<xray x25519 生成的私钥>",
          "shortIds": ["<16字符hex 或空字符串>"]
        },
        "tcpSettings": { "header": { "type": "none" } }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"],
        "routeOnly": true
      }
    },
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
```

要点：
- `clients[].email` 必须填，否则没有 `user>>>email>>>traffic` 的分用户统计；面板按节点统计时用入站 tag 即可，email 是按用户统计的备用口径。
- `flow` 只在 Vision 时填 `xtls-rprx-vision`；不填则是不带 Vision 的纯 Reality（8443 那种无流控节点就是 flow 为空）。
- `shortIds` 放 `[""]` 表示客户端可不带 shortId；放具体 hex 则客户端 sid 必须匹配其中之一。
- `dest` 的域名必须真实存在且 443 能 TLS 握手（见第 6 节），且与 `serverNames` 之一一致。
- 入站不写 `listen` 即监听全部地址（含 IPv6，如需只 v4 可写 `"listen": "0.0.0.0"`）。
- 校验命令：`xray run -c /path/to/config.json -test`（只测语法不启动）；启动：`xray run -c /path/to/config.json`。

### 2.2 出站客户端配置（链式代理的 B 节点用）

通用规则：每个出站必须有唯一的 `tag`（路由规则靠它定位）；`streamSettings` 描述该出站的传输与安全层；B 节点是「客户端」视角，所以用各协议的 OutboundConfigurationObject。

#### VLESS（出站）

```json
{
  "protocol": "vless",
  "tag": "B-vless",
  "settings": {
    "vnext": [
      {
        "address": "<B节点地址>",
        "port": 443,
        "users": [{ "id": "<UUID>", "encryption": "none", "flow": "xtls-rprx-vision" }]
      }
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "fingerprint": "chrome",
      "serverName": "<B的伪装域名>",
      "publicKey": "<B的公钥>",
      "shortId": "<B的shortId>",
      "spiderX": "/"
    }
  }
}
```

- 另有简写形式：`settings` 直接写 `{ "address", "port", "id", "encryption": "none", "flow": "xtls-rprx-vision", "level": 0 }`，与 vnext 等价，面板生成时统一用 vnext 形式即可。
- B 是 TLS（非 Reality）时，streamSettings 改为 `"security": "tls"` + `tlsSettings: { "serverName", "allowInsecure": false, "alpn": ["h2", "http/1.1"], "fingerprint": "chrome", "minVersion": "1.2", "maxVersion": "1.3" }`。
- B 是纯 TCP 无加密时 `security` 可为 `"none"`，但此时 VLESS 只能连私网地址（官方限制），公网 B 节点必须配 TLS 或 Reality。
- VLESS 出站的 flow：Vision 场景填 `xtls-rprx-vision`；与 Vision 不兼容的传输（如 WS）不填 flow。

#### VMess（出站）

```json
{
  "protocol": "vmess",
  "tag": "B-vmess",
  "settings": {
    "vnext": [
      {
        "address": "<B节点地址>",
        "port": 443,
        "users": [{ "id": "<UUID>", "alterId": 0, "security": "auto", "level": 0 }]
      }
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": { "serverName": "<B的SNI>", "allowInsecure": false }
  }
}
```

- `alterId` 建议 0（新版 AEAD 模式，alterId > 0 是旧兼容模式）。
- `security` 可选：`auto`（默认，跟随）、`aes-128-gcm`、`chacha20-poly1305`、`none`、`zero`。
- VMess 的 streamSettings 与 VLESS 通用（tcp/ws/grpc/h2 + tls/reality/none）。

#### Trojan（出站）

```json
{
  "protocol": "trojan",
  "tag": "B-trojan",
  "settings": {
    "servers": [
      { "address": "<B节点地址>", "port": 443, "password": "<密码>", "email": "", "level": 0 }
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": { "serverName": "<B的SNI>", "allowInsecure": false }
  }
}
```

- `flow`（xtls-rprx-direct / splice）只属于已废弃的 XTLS 时代，现代 TLS 场景不填。
- Trojan 必须配 TLS（或 Reality），`security: "none"` 时只能连私网地址。

#### Shadowsocks（出站）

```json
{
  "protocol": "shadowsocks",
  "tag": "B-ss",
  "settings": {
    "address": "<B节点地址>",
    "port": 8388,
    "method": "aes-256-gcm",
    "password": "<密码>",
    "email": "",
    "level": 0
  }
}
```

- 另有 `servers[]` 形式（多服务器），与上面 flat 形式等价，面板统一用 flat 形式即可。
- 方法列表（官方文档）：推荐 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`；另有 `aes-128-gcm`、`aes-256-gcm`、`chacha20-poly1305`（= chacha20-ietf-poly1305）、`xchacha20-poly1305`。
- 2022 系列的密码是预共享密钥（类似 WireGuard），生成：`openssl rand -base64 <长度>`，长度：128 位方法 16 字节、256 位方法 32 字节（Go 实现里 32 字节通用）。
- SS 出站一般不配 streamSettings（协议自带加密）；如需套 TLS 则另加 streamSettings（少见）。

#### SOCKS（出站）

```json
{
  "protocol": "socks",
  "tag": "B-socks",
  "settings": {
    "servers": [
      {
        "address": "<B节点地址>",
        "port": 1080,
        "users": [{ "user": "<用户名>", "pass": "<密码>", "level": 0 }]
      }
    ]
  }
}
```

- 无账号时省略 `users`（即匿名 SOCKS5）。字段以 `infra/conf` 的 SocksRemoteConfig 为准：address / port / users[{user, pass}]。
- 注意：SOCKS 本身不加密，只适合链式中转的可信内网段或套 TLS 的场景，面板里应对此给出提示。

#### HTTP（出站）

```json
{
  "protocol": "http",
  "tag": "B-http",
  "settings": {
    "servers": [
      {
        "address": "<B节点地址>",
        "port": 8080,
        "users": [{ "user": "<用户名>", "pass": "<密码>", "level": 0 }]
      }
    ]
  }
}
```

- 与 SOCKS 同形（servers[{address, port, users[{user, pass}]}]）；无账号省略 users。HTTP 代理出站同样不加密，面板里同样提示。

### 2.3 路由规则（链式分流：域名/IP 清单 → B 节点，默认直连）

```json
"routing": {
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
    {
      "type": "field",
      "domain": ["example.com", "full:exact.example.com", "domain:sub.example.com", "regexp:^.*\\.example\\.org$"],
      "outboundTag": "B-vless"
    },
    {
      "type": "field",
      "ip": ["203.0.113.0/24", "198.51.100.7", "geoip:private"],
      "outboundTag": "B-vless"
    },
    { "type": "field", "network": "tcp,udp", "outboundTag": "direct" }
  ]
}
```

- **规则顺序 = 优先级**：先匹配先用。api 规则必须放最前面；链式规则放中间；默认直连规则放最后（或干脆不写最后一条，靠「无规则匹配时走 outbounds[0]」兜底——但面板显式写一条 direct 更稳）。
- **domain 匹配写法**：
  - 裸域名 `example.com`：匹配该域名及其所有子域名（即 `domain:example.com` 的简写）。
  - `full:exact.example.com`：精确匹配，不含子域名。
  - `domain:sub.example.com`：显式子域名匹配。
  - `regexp:...`：正则匹配。
  - `geosite:cn` / `geosite:geolocation-!cn`：查 geosite.dat（需要 dat 文件在位，面板默认不依赖它，清单用裸域名即可）。
  - `ext:custom.dat:tag`：外部规则文件（高级，面板不用）。
- **ip 写法**：单个 IP、CIDR 段、`geoip:private`（内网）、`geoip:cn`（需 geoip.dat 在位）。
- **domainStrategy**：`AsIs`（只按域名原文匹配）、`IPIfNonMatch`（域名没匹配上时解析成 IP 再按 IP 规则匹配，推荐）、`IPOnDemand`（按需解析）。
- **链式生效前提**：入站必须开 sniffing（见 1.6），否则 xray 不知道目标域名，域名规则永远不命中；IP 规则不受 sniffing 影响。
- **B 节点 tag 命名**：面板自动生成（如 `chain-B-<id>`），保证唯一；删除链式时同步删除该出站与规则。

### 2.4 statsService 开启与 statsquery 命令

开启三件套（见 2.1 示例）：

1. 顶层 `"stats": {}`（空对象即开启统计收集）。
2. `policy`：`levels.0.statsUserUplink / statsUserDownlink = true`（分用户统计）；`system.statsInboundUplink / statsInboundDownlink / statsOutboundUplink / statsOutboundDownlink = true`（分入站/出站统计）。
3. `api` + api 入站 + api 路由规则：
   - `"api": { "tag": "api", "services": ["StatsService"] }`（如需动态改配置可再加 `"HandlerService"`，面板初期只开 StatsService）。
   - api 入站：`dokodemo-door`，`listen 127.0.0.1`，端口自选（常用 10085，面板内定一个不冲突的，如 10085 被占则换），`tag: "api"`。
   - 路由规则：`{ "type": "field", "inboundTag": ["api"], "outboundTag": "api" }`（必须在规则最前面）。

查询命令（面板用 exec 调用，或走 gRPC 直连，效果相同）：

```bash
# 查全部统计（pattern 为空 = 全部）
xray api statsquery --server=127.0.0.1:10085 --pattern=''

# 只查某个入站（pattern 语义未完全确认，建议空 pattern 拉全量后本地过滤）
xray api statsquery --server=127.0.0.1:10085 --pattern='inbound'

# 查完并清零（返回的是清零前的值；面板不要用这个做月结，见下）
xray api statsquery --server=127.0.0.1:10085 --reset=true

# 查单条（xray help api stats 可看用法；--name 标志名未确认）
xray help api statsquery
```

输出示例（JSON）：

```json
{
  "stat": [
    { "name": "inbound>>>vless-reality>>>traffic>>>uplink", "value": "1176" },
    { "name": "inbound>>>vless-reality>>>traffic>>>downlink", "value": "2040" },
    { "name": "outbound>>>direct>>>traffic>>>uplink", "value": "0" },
    { "name": "user>>>someone@example.com>>>traffic>>>uplink", "value": "2520" },
    { "name": "inbound>>>api>>>traffic>>>uplink", "value": "14247" }
  ]
}
```

- **name 格式**：`前缀>>>标识>>>traffic>>>方向`，前缀三类：`inbound`（按入站 tag）、`outbound`（按出站 tag）、`user`（按 clients[].email）。
- **方向口径（面板展示必须搞对）**：
  - 入站计数：`uplink` = 客户端上传（用户上行），`downlink` = 客户端下载（用户下行）。面板的「节点上行/下行」直接用入站计数。
  - 出站计数方向是反的：`outbound>>>direct>>>uplink` 是 xray 发往目标的字节（≈用户下行），`downlink` 是目标返回的字节（≈用户上行）。汇总面板总流量时不要把入站和出站简单相加，会 double count；以入站为准。
  - `inbound>>>api>>>traffic` 是 API 自身的流量，汇总时排除 tag=api。
- **计数器是进程内累计，xray 重启即清零**。面板必须定时（如每分钟）拉取并落库：增量 = 本次值 - 上次值（若本次值小于上次值，说明重启过，增量 = 本次值）。月用量 = 当月累计增量，总用量 = 历史累计增量。不要用 `--reset=true` 做月结（会丢数据且与重启语义冲突）。

### 2.5 密钥与 ID 生成命令

```bash
# Reality 密钥对（输出两行，见下）
xray x25519

# UUID
xray uuid
# 或：cat /proc/sys/kernel/random/uuid

# shortId（16 字符 hex；也可直接用空字符串 "" 表示不校验）
openssl rand -hex 8
```

`xray x25519` 输出格式（多方资料一致，经典格式）：

```
Private key: gKFJqmBjRWRlQjg5N0M4M2U3NjQwNzE4MWU3NTY0NzA=
Public key: yN0M3U1M2E3NjQwNzE4MWU3NTY0NzBnKFJqbUJqUldSb=
```

- `Private key` 进服务端 realitySettings.privateKey；`Public key` 进客户端链接 pbk。二者都是 base64（43 字符，含 `=` 填充）。
- 注意：有资料称个别新版/衍生工具的输出格式不同（出现 `PrivateKey / Password / Hash32` 三行），**未确认**。面板实现时应兼容两种解析：优先匹配 `Private key:` / `Public key:`，解析不到则按所用版本实测调整，不要硬编码行号。
- 配置校验：`xray run -c <config.json> -test`。

---
## 3. hysteria2 服务端 config.yaml（官方二进制）

官方二进制用 YAML（也支持 JSON / TOML，面板统一生成 YAML）。启动：`hysteria server -c /etc/hysteria/config.yaml`。最小可用配置只有 4 项：listen（可省，默认 :443）、tls 或 acme 二选一、auth、masquerade（可省）。

### 3.1 完整示例（自签证书 + 密码认证 + 混淆 + 限速 + 流量统计）

```yaml
listen: :443

# 证书二选一：自有证书（tls）或自动申请（acme），不能同时写
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
# acme:
#   domains:
#     - hy.example.com
#   email: admin@example.com
#   # type: letsencrypt  # 默认；另有 zerossl 等，细节未确认
#   # disableHTTP: false
#   # disableTLSALPN: false

auth:
  type: password
  password: <强密码>

# 混淆（可选，强烈建议开）
obfs:
  type: salamander
  salamander:
    password: <混淆密码，与认证密码不同>

# 限速（可选；字符串，如 "100 mbps"；不写则不限速走 BBR）
bandwidth:
  up: 100 mbps
  down: 100 mbps

# 伪装（masquerade，可选）：非 hy2 流量（浏览器直接访问）返回什么
masquerade:
  type: proxy
  proxy:
    url: https://example.com
    rewriteHost: true
  # listenHTTP: :80
  # listenHTTPS: :443
  # forceHTTPS: true

# QUIC 调优（可选；不写用默认值即可）
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

# 流量统计 API（面板用量必须开；只监听本机）
trafficStats:
  listen: 127.0.0.1:9999
  secret: <统计API密钥>

# 高级（可选）
# resolver:
#   type: udp
#   udp:
#     addr: 1.1.1.1:53
# acl:
#   file: /etc/hysteria/acl.txt
# ignoreClientBandwidth: false
```

### 3.2 字段说明

| 字段 | 说明 |
|---|---|
| listen | 监听地址，默认 `:443`。注意是 UDP 端口（QUIC），防火墙要放 UDP 不是 TCP |
| tls.cert / tls.key | 自有证书路径。与 acme 二选一 |
| acme.domains / acme.email | 自动向 Let's Encrypt 申请证书的域名与邮箱；证书续期自动处理 |
| auth.type | 认证方式。常用 `password`；官方还支持多认证后端（userpass / http / 外部命令，见官方 Full Server Config，具体字段**未确认**，面板初期只做 password） |
| auth.password | 认证密码。客户端链接里 `hysteria2://<密码>@...` 的 userinfo 部分 |
| obfs.type | 混淆类型，官方：`salamander`。sing-box 出站 1.14+ 另有 `gecko`，官方二进制以文档为准 |
| obfs.salamander.password | 混淆密码，必须与客户端一致，否则连不上 |
| bandwidth.up / down | 每客户端限速，字符串如 `"100 mbps"`、`"1 gbps"`。不写 = 不限速 |
| masquerade.type | `proxy`（反代真实网站）/ `string`（返回固定文本）/ `file`（返回本地文件目录）。面板默认 proxy + rewriteHost: true |
| masquerade.proxy.url | 伪装目标网址，如 `https://example.com` |
| masquerade.proxy.rewriteHost | 是否把 Host 改写为伪装目标，true |
| masquerade.listenHTTP / listenHTTPS / forceHTTPS | masquerade 自己的 HTTP/HTTPS 监听与强制跳转（高级） |
| quic.* | QUIC 窗口与超时（见示例值；不写用默认即可，面板高级配置里保留） |
| trafficStats.listen / secret | 统计 API 监听地址与密钥（见 3.3） |
| resolver | 出站 DNS 解析器（类型 udp/tcp/https/tls；面板默认不写，走系统 DNS） |
| acl | 访问控制：file（文件路径）或 inline（内联规则，如 `reject(suffix:example.com)`）。面板初期不用 |
| ignoreClientBandwidth | true = 服务端忽略客户端声明的带宽，用服务端 bandwidth 为准 |

### 3.3 流量统计接口：有，官方 Traffic Stats API（HTTP）

开启：config.yaml 里写 `trafficStats: { listen: 127.0.0.1:9999, secret: <密钥> }`。不设 secret 则任何能访问该地址的人都能看统计、踢用户，必须设 secret 或只监听 127.0.0.1。

| 接口 | 说明 |
|---|---|
| `GET /traffic` | 返回 `{"<用户标识>": {"tx": 514, "rx": 4017}}`。用户标识 = auth 的用户名（password 模式下是密码本身？官方示例用 `wang` 这种名字，password 模式的 key 语义**未确认**，面板按实际返回的 key 原样展示） |
| `GET /traffic?clear=1` | 返回后服务端清零，拿到的是增量。面板定时拉增量落库（与 xray 同理） |
| `GET /online` | 返回 `{"wang": 2, "joe": 1}`，即用户 → 客户端实例数。官方原话：这里的连接数指 Hysteria 客户端实例（设备）数，不是代理连接数 |
| `POST /kick` | body 为裸 JSON 数组 `["wang", "joe"]`，踢掉指定用户（客户端会重连，彻底封禁需同时在认证后端拉黑） |

鉴权：请求头 `Authorization: <trafficStats.secret>`（老版本兼容 `?secret=` 查询参数）。

**tx / rx 方向口径：未完全确认。** 第三方库（hysteria2-api）把 tx 标注为 upload_bytes、rx 标注为 download_bytes，但不同资料对「以服务端还是客户端视角」说法不一致。面板接入时必须实测一对上下行再定展示方向，不要直接假定 tx=上行。

### 3.4 客户端链接格式（面板生成用）

```
hysteria2://<密码>@<地址>:<端口>?sni=<SNI域名>&insecure=0&obfs=salamander&obfs-password=<混淆密码>&upMbps=100&downMbps=100&alpn=h3#<节点名>
```

- 自签证书时 `insecure=1`（跳过验证）；ACME/正规证书时 `insecure=0`，sni 填证书域名。
- `alpn=h3` 是 Hy2 默认，可省略。
- 注意与 sing-box 的区别：sing-box 用 `up_mbps / down_mbps`（整数），官方链接用 `upMbps / downMbps`。

---

## 4. 9seconds/mtg（MTProto 代理，TG 专用）

### 4.1 定位与限制（面板设计必须知道）

- mtg 是**纯 TG 代理**：它只把客户端流量中继到 Telegram 数据中心（L3 TCP 中继），不是通用代理。**不能做链式代理的 B 节点**（B 节点是通用出站，mtg 不具备该能力）；反过来，mtg 支持经 SOCKS5 出站（proxy chaining），即 mtg 可以挂在别的代理后面，但那是 mtg 自身的出站选项。
- 无用户管理：单 secret，不分用户。因此**没有按用户的流量统计**，面板的 mtg 用量只能按整个实例汇总。
- v2 为当前主线（v1 进入维护模式，v1 支持 adtag，v2 已移除 adtag）。

### 4.2 配置方式：TOML 文件（`mtg run <config.toml>`）

只有 `secret` 和 `bind-to` 必填，其余全有默认值。最小配置：

```toml
secret = "ee<32字符hex密钥><伪装域名的hex>"
bind-to = "0.0.0.0:443"
```

完整常用字段（simple-run 的 flags 与配置文件同名项对应）：

| 字段 | 默认值 | 说明 |
|---|---|---|
| secret | 必填 | 见 4.3 |
| bind-to | 必填 | 监听地址，如 `0.0.0.0:443` |
| concurrency | simple-run 默认 8192；mtglib 默认常量 4096（两者不一致，面板显式填写，以实测为准） | 最大并发连接数 |
| prefer-ip | `prefer-ipv6` | 连接 TG 服务器时的 IP 偏好（另有 prefer-ipv4 等取值，完整取值**未确认**） |
| domain-fronting-port | 443 | 域名前置（伪装）回落用的端口 |
| doh-ip | v2 CLI 默认 `9.9.9.9`（v1 文档示例用 `1.1.1.1`） | DNS-over-HTTPS 解析用 IP |
| timeout | `10s` | 网络超时 |
| antireplay-cache-size | `1MB` | 防重放缓存大小，设为 0 可关闭 |
| tcp-buffer | `4KB`（simple-run flag） | TCP 缓冲大小 |
| tolerate-time-skewness | `3s` | FakeTLS 时间偏差容忍 |
| blocklist / allowlist | — | IP 黑白名单（ProxyOpts 里有 IPBlocklist / IPAllowlist，配置文件字段名**未确认**） |
| [defense.doppelganger] urls | 默认内置 ok.ru 的统计 | 伪装统计学习用的 URL 列表：2-3 个、HTTPS、同伪装域名、轻重内容搭配；不确定就别动，默认即可 |
| use-test-dcs / allow-fallback-on-unknown-dc | false | 测试 DC / 未知 DC 回落（ProxyOpts 字段，配置文件字段名**未确认**） |

常用命令：

```bash
mtg generate-secret <伪装域名>          # 生成 base64 形式 secret
mtg generate-secret --hex <伪装域名>    # 生成 ee 开头的 hex 形式 secret
mtg run /etc/mtg.toml                   # 配置文件模式
mtg simple-run 0.0.0.0:443 <secret>     # 无配置文件模式（flags 见上表）
mtg access /etc/mtg.toml                # 输出 tg:// 与 t.me 链接、二维码链接、secret 两种形式
mtg doctor /etc/mtg.toml                # 配置自检：密钥、时间偏差、各 DC 连通性、伪装域名可达、SNI-DNS 匹配
```

### 4.3 secret 结构与伪装域名（FakeTLS）

- 当前只有 `ee` secret（FakeTLS + 长度统计防护）：`ee`（1 字节 0xee）+ 16 字节随机密钥 + 伪装域名（latin1/ASCII 编码）。
- 两种序列化形式内容相同：hex（`ee...` 开头）与 base64，TG 客户端都接受。
- 伪装域名 = secret 里内嵌的 hostname，即 FakeTLS 的 SNI 与域名前置目标。官方原话：不要用与服务器 ASN 无关的大厂域名（如 google.com），因为提供商的 IP 段一看就不是 Google 的；建议选与服务器归属相关的域名。这是 TG 代理的选法，与 Reality 的 SNI 选法不同（Reality 只要求域名真实存在且 443 可握手，不要求 ASN 匹配）。
- 链接格式：`tg://proxy?server=<地址>&port=<端口>&secret=<secret>`，或 `https://t.me/proxy?server=<地址>&port=<端口>&secret=<secret>`。
- mtg 严格按 secret 定模式：FakeTLS secret 的实例只能用 FakeTLS 客户端连，别的模式连不上（这是设计，不是 bug）。

### 4.4 流量统计接口：有，但只有 Prometheus / statsd，没有 HTTP JSON API

官方文档原话：开箱即用 statsd 与 Prometheus，具体接入看 example.config.toml（配置文件的 stats 段字段名**未确认**，面板接入时以仓库 example.config.toml 为准）。

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| telegram_traffic | counter | telegram_ip, dc, direction | 与 TG 往来的字节数。direction = `to_client` / `from_client`，面板双向用量就取它（按 direction 分组求和） |
| domain_fronting_traffic | counter | direction | 与伪装域名的往来字节数（探测回落流量） |
| client_connections | gauge | ip_family | 当前客户端连接数 |
| telegram_connections | gauge | telegram_ip, dc | 当前到 TG 的连接数 |
| domain_fronting_connections | gauge | ip_family | 当前到伪装域名的连接数 |
| iplist_size | gauge | ip_list | 黑白名单大小 |
| domain_fronting | counter | — | 域名前置事件数 |
| concurrency_limited | counter | — | 因并发上限被拒的次数 |
| ip_blocklisted | counter | ip_list | 因黑名单被拒的次数 |
| replay_attacks | counter | — | 检测到的重放攻击数 |

- 面板接入方式：给 mtg 配 Prometheus（或 statsd），面板定时抓取 `telegram_traffic` 按 direction 累加落库；或面板直接读 mtg 的 Prometheus 端点做增量累计。没有像 xray statsquery / hy2 /traffic 那样的「按节点一键拉取」接口，面板要为 mtg 单独写一个采集器。
- 注意：v1 文档提到「自有 stats server 已移除，Prometheus 端点移至默认 stats 端点」，v2 沿用此设计。

---

## 5. sing-box 的 Hy2 出站配置（链式代理的 B 节点是 Hy2 时用）

> 前提：xray-core 没有 Hy2 出站，B=Hy2 的链式不能只靠 xray 实现。面板的做法是另起 sing-box 进程承载链式（入站接 A 节点的流量 → 路由 → Hy2 出站），或整条链都用 sing-box。sing-box 需以 `with_quic` 构建才含 QUIC/Hy2（官方 release 默认含）。

### 5.1 出站完整结构（sing-box 官方文档）

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "server_ports": ["2080:3000"],
  "hop_interval": "30s",
  "hop_interval_max": "",
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "cry_me_a_r1ver",
    "min_packet_size": 512,
    "max_packet_size": 1200
  },
  "password": "goofy_ahh_password",
  "network": "tcp",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "insecure": false,
    "alpn": ["h3"]
  },
  "bbr_profile": "standard",
  "brutal_debug": false,
  "disable_chrome_parrot": false,
  "realm": {
    "server_url": "https://realm.example.com",
    "token": "",
    "realm_id": "",
    "stun_servers": [],
    "ip_version": 0,
    "port_mapping": { "enabled": false, "timeout": "10s", "lifetime": "10m" },
    "http_client": {}
  }
}
```

### 5.2 字段说明

| 字段 | 说明 |
|---|---|
| server / server_port | 必填。B 节点地址与端口；与 realm 互斥 |
| server_ports | 端口跳跃范围列表（如 `["2080:3000"]`），sing-box 1.11+；与 server_port 互斥，设置后 server_port 被忽略 |
| hop_interval | 跳 port 间隔，默认 `30s`（sing-box 1.11+） |
| hop_interval_max | 最大跳 port 间隔（1.14+），设置后实际间隔在二者之间随机 |
| up_mbps / down_mbps | 带宽（Mbps）。为空 = 用 BBR 而非 Brutal CC。注意：官方 hy2 链接用 upMbps/downMbps，sing-box 用 up_mbps/down_mbps，别混 |
| obfs.type | `salamander` 或 `gecko`（gecko 为 sing-box 1.14+ 新增）；为空 = 关闭混淆 |
| obfs.password | 混淆密码；设了 type 但密码为空会报错 |
| obfs.min_packet_size / max_packet_size | gecko 专用，默认 512 / 1200 字节（1.14+） |
| password | 认证密码。注意：官方 hy2 的 userpass（用户名:密码）认证在 sing-box 里没有别名，须把 `用户名:密码` 拼成 password 填 |
| network | `tcp` / `udp`，默认两者都启用 |
| tls | 必填。通用 TLS 段：enabled、server_name、insecure、alpn、min_version / max_version、cipher_suites、certificate_path / key_path、utls 指纹等（见 sing-box TLS 通用文档） |
| bbr_profile | BBR 档位：`conservative` / `standard`（默认）/ `aggressive`（1.14+） |
| brutal_debug | Brutal CC 调试日志开关 |
| disable_chrome_parrot | true = 关闭 Chrome QUIC 指纹模仿（1.14+）。默认开启模仿，此时 idle_timeout 固定 30s 等参数会被 Chrome 值覆盖；服务端用 Ed25519 证书时模仿会失败，须用 ECDSA/RSA 证书 |
| realm | Hysteria Realm 中继服务（1.14+），与 server/server_port/server_ports 互斥；含 server_url（必填）、token、realm_id（必填）、stun_servers（必填）、ip_version（4/6）、port_mapping、http_client |
| QUIC Fields | initStreamReceiveWindow / maxStreamReceiveWindow / initConnReceiveWindow / maxConnReceiveWindow / maxIdleTimeout / keepAlivePeriod / disablePathMTUDiscovery 等（见 sing-box QUIC 通用文档，高级项） |
| Dial Fields | connect_timeout、tcp_fast_open、domain_resolver、interface、routing_mark 等（见 sing-box Dial 通用文档，高级项） |

### 5.3 链式最小骨架（sing-box 承载整条链，仅示意字段名）

```json
{
  "inbounds": [
    { "type": "vless", "tag": "A-in", "listen": "::", "listen_port": 443,
      "users": [{ "uuid": "<A的UUID>", "flow": "xtls-rprx-vision" }],
      "tls": { "enabled": true, "server_name": "<A的伪装域名>",
        "reality": { "enabled": true, "private_key": "<A的私钥>", "short_id": ["<shortId>"] } } }
  ],
  "outbounds": [
    { "type": "hysteria2", "tag": "hy2-out", "server": "<B地址>", "server_port": 443,
      "password": "<B密码>", "tls": { "enabled": true, "server_name": "<B的SNI>" } },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "outbound": "hy2-out" },
      { "ip_cidr": ["203.0.113.0/24"], "outbound": "hy2-out" }
    ],
    "final": "direct"
  }
}
```

- sing-box 路由字段名与 xray 不同：`outbound`（不是 outboundTag）、`domain_suffix`（后缀匹配）、`domain_keyword`、`domain_regex`、`ip_cidr`、`final`（默认出站）。
- sing-box 的 VLESS 入站 Reality 字段在 `tls.reality` 里（enabled / private_key / short_id / handshake 等），与 xray 的 realitySettings 平级结构不同，面板生成时不要直接复用 xray 的 JSON。

---
## 6. 伪装域名（Reality SNI）筛选标准与候选清单

### 6.1 筛选标准（缺一不可）

1. **真实存在**：是真实运营的网站，不是编造的域名。
2. **443 能正常 TLS 握手**：从服务器视角（境外）可达，且 443 端口提供有效 TLS 服务——因为未通过鉴权的探测流量会被原样转发到 dest，dest 必须真的能回真实网站内容，否则探测者一眼识破。
3. **支持 TLS1.3 + X25519**：Reality 要求目标站支持 TLS1.3 和 X25519 密钥交换（现代大站基本都满足，但必须逐个验证，不能想当然）。
4. **证书 SAN 覆盖该域名**：serverNames 里填的域名必须在目标站证书的 SAN 列表里（`www.` 前缀与裸域是两个名字，填哪个就验证哪个）。
5. **长期稳定**：大站、长期运营，不会突然关停或换证书体系。
6. **中国可直连**（面向中国用户时）：该域名在中国大陆不被墙、直连能打开，否则 GFW 对该 SNI 的流量会格外注意，伪装意义打折。
7. **不是代理圈热门 SNI**：避开人人都在用的域名。同一 SNI 被海量代理共用时，特征反而明显；且热门 SNI 一旦被重点关照，所有用它的节点一起遭殃。
8. **流量够大、特征普通**：高流量站点的 TLS 流量本身就是背景噪声，更易混入；小众冷门站反而显眼。
9. **dest 与 serverNames 一致**：`dest` 填 `域名:443`，`serverNames` 填同一域名；多 SNI 时 dest 须是其中之一。
10. **SNI ≠ 节点地址**：客户端实际连的是服务器 IP，SNI 只是握手里声称要访问的网站；换 SNI 不用换密钥对、不用换 shortId，只改 dest + serverNames 并重启 xray、重新生成链接。

### 6.2 明确排除的热门 SNI（不要用）

`www.microsoft.com`、`learn.microsoft.com`、`www.oracle.com`、`www.amazon.com`、`www.apple.com`、`www.google.com`、`www.cloudflare.com`、`www.bing.com`、`dl.google.com` 等——要么是代理圈人人都在用的高频 SNI，要么在中国不可直连（Google 系），要么两者都是。

### 6.3 候选域名清单（16 个）

> **诚实标注：中国可达性一栏凭公开知识判断，未经实测，必须在实际使用中验证；TLS1.3 支持情况部署前必须逐个用 6.4 的命令验证，不能直接采信本表。** 排序不分先后，面板内置时建议每次建节点从中随机推荐一个，不要全网默认同一个。

| # | 域名 | 是什么网站 | 为什么合适 | 中国可达性（凭公开知识判断，需验证） |
|---|---|---|---|---|
| 1 | www.samsung.com | 三星全球官网（消费电子） | 全球大厂、流量大、证书体系稳定；三星在中国有完整业务，域名本身不敏感 | 可直连（判断，需验证） |
| 2 | www.intel.com | 英特尔官网（芯片） | 全球大厂、技术文档站流量稳定；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 3 | www.nvidia.com | 英伟达官网（GPU/AI） | 全球大厂、开发者流量大；代理圈极少用 | 可直连（判断，需验证） |
| 4 | www.adobe.com | Adobe 官网（软件） | 全球大厂、创意软件用户量大；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 5 | www.lenovo.com | 联想全球官网（PC） | 中国公司全球站，在中国业务大、访问自然；知名度适中，不属代理热门 | 可直连（判断，需验证） |
| 6 | www.asus.com | 华硕官网（PC/硬件） | 全球硬件大厂、流量稳定；多家中文教程曾提及但不算代理圈高频 | 可直连（判断，需验证） |
| 7 | www.cisco.com | 思科官网（网络设备） | 全球网络设备大厂、技术文档流量大；企业站特征普通 | 可直连（判断，需验证） |
| 8 | www.dell.com | 戴尔官网（PC/服务器） | 全球大厂、商用流量稳定；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 9 | www.hp.com | 惠普官网（PC/打印） | 全球大厂、流量大；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 10 | www.sony.com | 索尼全球官网（消费电子） | 全球大厂、娱乐+电子流量大；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 11 | www.tesla.com | 特斯拉官网（电动车） | 全球大厂、在中国业务大、访问自然；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 12 | www.ubuntu.com | Ubuntu / Canonical 官网（开源操作系统） | 开源社区站、开发者流量大、证书稳定；知名度适中，不属代理热门 | 可直连（判断，需验证） |
| 13 | www.mozilla.org | Mozilla 官网（Firefox） | 开源浏览器组织、全球流量大；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 14 | www.speedtest.net | Ookla Speedtest（测速站） | 中国用户自己就经常直连测速，流量特征极其普通；中文教程曾列为 dest 例子但不算代理圈高频 SNI | 可直连（判断，需验证） |
| 15 | www.python.org | Python 官网（编程语言） | 开发者高频站、文档流量大；不是代理圈常用 SNI | 可直连（判断，需验证） |
| 16 | www.stackoverflow.com | Stack Overflow（程序员问答） | 开发者高频站、全球流量大；不是代理圈常用 SNI | 可直连（判断，需验证） |

补充说明：
- 以上均为 `www.` 主站；部署时以 `www.` 域名为准验证证书 SAN，不要擅自换成裸域（裸域与 www 域的证书 SAN 可能不同）。
- 个别厂商有地区子站（如 `*.cn`），SNI 仍用全球 `www.` 主站，不要用地区子站（地区子站的 CDN 与证书行为可能不同）。
- 面板内置清单后，应支持用户自加域名，并对新域名跑 6.4 的验证，验证失败要明确提示失败项（不是「域名不可用」一句话带过）。

### 6.4 验证方法（部署前逐个跑，不要跳过）

```bash
# 1. 测 443 是否通、是否支持 TLS1.3、证书是否覆盖该域名
openssl s_client -connect <域名>:443 -servername <域名> -tls1_3 -brief

# 期望看到：Protocol : TLSv1.3、Verify return code: 0 (ok)
# 并在证书输出里确认 subject / SAN 包含该域名

# 2. 看完整证书链与 SAN（确认 serverNames 填的名字在 SAN 里）
openssl s_client -connect <域名>:443 -servername <域名> -tls1_3 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 3. 测 443 真实可达（应返回 200 或 301/403 等正常 HTTP 状态，不是超时/拒绝）
curl -sv -o /dev/null https://<域名>/ --max-time 10

# 4. 上线后验证 Reality 回落：用错误密钥/无 shortId 握手一次，应返回该域名的真实网站内容
# （或临时把 realitySettings.show 设为 true 看 xray 日志里的握手信息，验证完改回 false）
```

- 以上 1-3 步只能验证「域名真实、443 通、TLS1.3、证书对」；「中国可直连」无法从境外服务器验证，**必须靠中国境内的实际使用反馈**（或国内测速点），面板不要宣称自己测过。
- 若某域名 TLS1.3 验证失败，立即从清单剔除，不要抱着「也许能用」的心态上线。

---

## 附：资料来源

- XTLS 官方文档：xtls.github.io —— config（outbound / api / transport）、outbounds（vless / shadowsocks / socks / freedom）、document（traffic_stats、routing 教程、xray-clients）。
- Xray-core 源码结构：`infra/conf`（REALITYConfig、SocksRemoteConfig 等，pkg.go.dev 镜像）。
- 3x-ui 入站结构：go-x3ui / gox-ui 的 Inbound / InboundClient / AddInboundRealitySettings / AddInboundStreamSettings / AddInboundTCPSettings（与 3x-ui 入站表单一一对应）；alireza0/x-ui 的 TLS 表单（tls_settings.html）与 Reality 弹窗（inbound_modal.html）。
- Hysteria 官方文档：hysteria.network（Full Server Config、Traffic Stats API）与 v2.hysteria.network（Traffic Stats API）；sing-box 内部文档（Hy2 协议实现细节）。
- sing-box 官方文档：sing-box.sagernet.org —— configuration/outbound/hysteria2（1.14 版字段，含 realm / obfs gecko / bbr_profile 等）。
- 9seconds/mtg 官方文档：仓库 README（pkg.go.dev 镜像）——配置、simple-run flags、secret 结构、Metrics 表、doppelganger、doctor / access 命令。
- 其余佐证：Xray-script 的 traffic.sh（statsquery 用法）、xctl 的 Docker 集成（`--pattern ''`）、Hi_Hysteria 的服务端配置整理、hysteria2-exporter / hysteria-traffic-collector（trafficStats 接口细节）。

## 附：未确认事项汇总（开发时必须实测，不可直接采信）

1. `xray api statsquery` 的 `--pattern` 精确匹配语义（前缀/包含/正则）；面板实现：空 pattern 拉全量、本地过滤。
2. `xray api stats`（单条查询）的标志名；用 `xray help api stats` 现场确认。
3. `xray x25519` 在个别新版/衍生工具上的输出格式差异（`PrivateKey / Password / Hash32` 三行说法的真实性）；面板解析要兼容两种格式。
4. 3x-ui 客户端字段 `reset` 的精确语义；`allocate`（strategy / refresh / concurrency）的完整取值。
5. hysteria2 `trafficStats` 的 tx / rx 方向口径（服务端视角还是客户端视角）；password 模式下 /traffic 返回的 key 语义。
6. hysteria2 官方二进制 auth 除 password 外的后端（userpass / http / 外部命令）的具体字段；`disableUDP` 等小众字段是否存在。
7. mtg 配置文件里 stats（Prometheus / statsd）段的字段名；blocklist / allowlist、use-test-dcs、allow-fallback-on-unknown-dc、SOCKS5 出站链的配置文件字段名；prefer-ip 的完整取值。
8. 第 6 节全部 16 个候选域名的中国可达性与 TLS1.3 支持情况（凭公开知识判断，需按 6.4 逐个实测）。
9. sing-box QUIC Fields 与 Dial Fields 的完整字段（以 sing-box 通用文档为准，本文只列出类别）。
10. xray-core 新版 realitySettings 的 mldsa65Seed / mldsa65Verify、limitFallbackUpload / limitFallbackDownload 在各发行版中的可用版本下限。
