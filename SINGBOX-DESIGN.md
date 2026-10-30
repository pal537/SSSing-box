# sing-box 主导设计（Phase 1，甲骨文 only）

对应迁移计划 ~/workspace/yizhan/MIGRATION-SINGBOX.md。设计先行，代码按此文档实现。

**2026-10-30 已对 sing-box 官方文档逐项核对**（TUIC / TLS / Naive / WireGuard endpoint / Rule Action 五页原文 + AnyTLS 实现源码 + VLESS 选项结构多方印证）。核对后修正了初版 6 处，见各节“已核对”标注；最终兜底是实现时 `sing-box check` 逐份校验生成配置，文档核对代替不了这一步。

## 架构变化

- 删 ApplyXray、ApplyHy2、ApplySingBox（翻译版）；新增 ApplySingBox（全量）：一个 singbox.json 含全部入站 + 全部链式出站 + 路由规则 + WireGuard 端点。
- ApplyMTG 不动；ApplyAll = ApplySingBox + ApplyMTG。
- 监管：supervisor 只管 sing-box 单进程（run -c singbox.json）+ mtg 各进程；xray / hysteria 进程名从监管里去掉。
- 面板 UI：内核卡片去掉 xray / hysteria，sing-box 卡片文案改（不再是“只做中转”）；添加页签加 TUIC / AnyTLS / Naive。

## 入站映射（tag 沿用 in-<id>）

- vless（已核对：VLESSInboundOptions = users / tls / transport / multiplex）：users [{uuid, flow: xtls-rprx-vision}]，tls {enabled, server_name: SNI, reality {enabled, handshake {server: 伪装域名, server_port: 443}, private_key, short_id}}，transport tcp（TCP+Reality 不用写 transport）。**另有 WS / H2 / HTTPUpgrade-TLS 三档（对标 233boy，见对标节），走通用 TLS 证书流程。**
  - **Reality 关键格式差**：sing-box 的 short_id 是**数组**，xray 的单个 short_id 平移时必须包成 [short_id]（官方 TLS 页 + 现成脚本 `.tls.reality.short_id[0]` 双重印证）。private_key 格式与面板现有 genRealityKeypair（base64url 无填充）一致，直接复用。
- vmess TCP：users [{uuid, alterId: 0}]，transport tcp。WS+CF：transport {type: ws, path, headers Host} + tls {enabled, server_name: 域名, certificate_path / key_path}（复用现有 vmesscf 自签证书）。**另有 HTTP（http 传输明文）、QUIC（quic 传输 + TLS）、H2 / HTTPUpgrade-TLS（新增，对标 233boy，见对标节），走通用 TLS 证书流程。**
- trojan Reality：users [{password}]，tls reality 同 vless。WS+CF：transport ws + tls（复用 trojancf 证书）。**另有 H2 / HTTPUpgrade-TLS 两档（新增，对标 233boy，见对标节），走通用 TLS 证书流程。**
- ss：type shadowsocks，method 2022-blake3-aes-128-gcm，password 复用。
- socks：type socks，users [{username, password}]。
- http：type http，users [{username, password}]。
- hy2（已核对）：type hysteria2，users [{password}]，tls {enabled, alpn: [h3], certificate_path / key_path}（复用 hy2-*.pem / key 自签证书），up_mbps / down_mbps 沿用面板现有值。hysteria 二进制不再需要。
- tuic v5（已核对，官方 TUIC 页原文）：
  - users [{uuid, password}]（name 可选）。
  - congestion_control：官方**默认是 cubic，不是 bbr**（初版写错，已修正）——生成配置里显式写 `"congestion_control": "bbr"`。
  - zero_rtt_handshake：官方强烈建议关闭（重放攻击），显式写 false。
  - heartbeat 默认 10s、auth_timeout 默认 3s：不用写，用默认。
  - tls 必填：{enabled, alpn: [h3], certificate_path / key_path}（面板生成自签证书，客户端 insecure=1，与 Hy2 同款做法）。
  - **没有 udp_relay_mode**：官方入站页无此字段，它是客户端出站字段，入站不要写。
- anytls（已核对：AnyTLSInboundOptions = users / padding_scheme / tls；实现源码确认 TLS 在入站可选、padding 有默认）：
  - users [{name, password}]（name 可省，脚本实例只写 password 也能跑；面板写 name + password）。
  - padding_scheme：不写，用 sing-anytls 默认方案（不要自创方案）。
  - tls：面板一律启用 + 自签证书（fscarmen 脚本同款做法，客户端 allowInsecure=1）。Reality 可作后续选项，v1 不做。
- naive（已核对，官方 Naive 入站页原文）：
  - users [{username, password}]，**必填**。
  - network：v1 只写 `"tcp"`（HTTP/2 only，不依赖 QUIC；UDP/HTTP3 以后再加）。
  - tls 必填，且**必须用真域名 + CA 证书**（官方明言自签会破坏 Naive 的设计目的，生产不用自签）。
  - quic_congestion_control 默认 bbr（只与 UDP 有关，v1 tcp-only 不用写）。
  - 证书来源：v1 = 上传证书 + 私钥；sing-box 1.14+ 的 certificate_provider（ACME）是后续选项（旧 tls.acme 块已废弃，实现时再查 Certificate Provider 页）。**此流程泛化为“TLS 档通用证书流程”，供下面对标节全部 -TLS 档复用；CF 自签档保持原样（CF Full 接受自签）。**

## WireGuard：不是入站，是端点（已核对，官方 Endpoint 页原文）

- sing-box 1.11+ 起 WireGuard 是 `endpoints` 段的端点，不是 `inbounds`。生成配置里 WG 节点单独进 `endpoints` 数组，tag 用 `wg-<id>`。
- 映射（面板 WGConfig 字段全复用，客户端交付文本不变）：
  - {type: wireguard, tag: wg-<id>, system: false（gVisor 用户态，不用内核模块）, mtu: 1420（沿用面板现有值，不用 sing-box 默认 1408）, address: ["10.0.0.1/32"], private_key: ServerPriv, listen_port: 节点端口, peers: [{public_key: ClientPub, allowed_ips: [ClientIP]}]}
  - **address 是新增项**：xray 的 WG 入站不需要服务端隧道地址，sing-box 端点必填。取 10.0.0.1/32，与客户端 10.0.0.2/32 配对（面板注释：每节点独立设备，ClientIP 可复用，所以服务端地址也可按节点复用）。
  - peers 的 address / port 是服务端主动拨号才用的，面板服务端不写。
  - WG 流量走路由 final direct，不进链式规则（WG 从不是链式 A，inbound 匹配器对端点无效，正好互不干扰）。
  - 待沙盒验证：官方 release 二进制是否含 with_wireguard（`sing-box check` 验端点配置即见分晓）。

## 出站映射（B 节点 → sing-box outbound）

- B 节点源链接不变，用现有 ParseBLink 解析后按协议生成 sing-box 出站：vless（tls reality）、vmess（tcp / ws）、trojan（reality / ws）、shadowsocks、socks、http、hysteria2（原生直连，不再经过翻译层）。

## 链式路由（已核对，官方 Rule Action 页原文）

- 规则顺序（按数组顺序评估，sniff 是非终结动作）：
  1. `{inbound: [全部链式 A 的 in-<id>], action: "sniff"}` 一条，置于全部域名规则之前。sniff 动作只有 sniffer / timeout 两个字段（timeout 默认 300ms），**没有 override_destination**。
  2. 每条链式一条：`{inbound: [in-<A>], domain_suffix / ip_cidr（复用现有 SingBoxRule 的清单解析）, action: "route", outbound: "chain-<id>"}`。
  3. 末尾 final direct。
- **初版“sniff_override_destination”已废弃**：那是旧入站选项，官方已标 deprecated；而且新架构不需要它——旧问题是 xray 经 SOCKS 把 IP 传给翻译层 sing-box 导致域名规则失效，新架构里 sing-box 自己嗅探、自己决策、自己转发到 B 出站，没有中间一跳丢域名。
- 隔离：每条规则绑各自入站，防偷渡复发；复测沿用老办法：非链式节点（如 VMESS-TCP）访问清单域名必须走直连。

## 用量统计（Phase 2 研究项，设计先定方向）

- 现状：xray stats API（inbound>>>tag>>>traffic）+ Hy2 /traffic + MTG /metrics → Poller 算 delta → db + 限额。
- sing-box：已核对 Clash API——/traffic 只是实时速率流，/connections 只是当前连接快照，**没有按入站累计接口**，替代不了 xray stats API。nftables 按端口计数仍是主方案。
- nft 方案：每个节点端口唯一 → 端口 INPUT + OUTPUT 字节 = 节点用量；面板定时采集，复用现有 Poller 的 delta / db / 限额逻辑，只换数据源。
- 待验证：Oracle 是否有 nft 命令、规则持久化、面板 systemd 服务用户权限、计数器重启清零处理（与 xray 重启清零同一套 delta 逻辑）。
- 实时速率：两次采集差值 / 间隔算出（与 Poller.realtime 同款）。
- Hy2Online（在线数）：查 server.go 用处后定（/connections 快照无入站标签保证，大概率砍掉或只作总数参考）。
- MTG：不动（/metrics 照旧）。

## 数据平移

- 入站记录：协议字段不变，密钥类字段复用（UUID、密码、密钥、SNI、端口都不变）；Hy2 的 password / 证书复用；新增协议走新建流程。
- 迁移脚本：逐条读旧记录 → 生成 sing-box inbound JSON → 校验（端口、UUID、SNI、Reality 公钥与旧 xray 配置逐项 diff，short_id 包数组）→ 写新配置；不改 db 主键与用量表。
- B 节点记录：config 从 xray 格式转 sing-box 格式（重建出站 JSON，源链接不变）。
- 链式记录：id、A、B、list 不变，路由由新引擎生成。
- 订阅：链接生成函数按协议分支改写（vless / vmess / trojan / ss / socks / http / wg / hy2 链接格式不变；tuic / anytls / naive 新增格式并逐客户端核对）。
- dokodemo：sing-box 无对应入站，砍掉。甲骨文现有 14 节点里没有 dokodemo 节点，零影响；迁移时如遇 dokodemo 记录直接报错拦截，不静默丢弃。

## 对标 233boy/sing-box（2026-10-30，用户要求：她支持的，驿站也要支持）

来源：[233boy/sing-box README](https://github.com/233boy/sing-box) 特点清单 + 驿站代码实测。

- **已覆盖（不用补）**：VLESS-REALITY、TUIC、Trojan、Hysteria2、AnyTLS、Shadowsocks 2022、VMess-TCP、VMess-WS+TLS（CF 自签档）、Trojan-WS+TLS（CF 自签档）。
- **新增缺口（补进设计）**：
  - VLESS + WS / H2 / HTTPUpgrade-TLS 三档。
  - VMess + HTTP（明文）、QUIC、H2 / HTTPUpgrade-TLS 四档。
  - Trojan + H2 / HTTPUpgrade-TLS 两档。
  - sing-box 传输类型对照（官方 V2Ray Transport 页）：WS = `ws`、H2 = `http` + TLS、HTTPUpgrade = `httpupgrade`、QUIC = `quic`（必须配 TLS）、明文 HTTP = `http`（不配 TLS）。sing-box 无 TCP 传输（裸 TCP = 不写 transport）、无 mKCP。
  - 证书：233boy 的 -TLS 档走 Caddy 自动真证书；驿站的 CF 档是自签（CF Full 接受）。新增的直连 -TLS 档必须走真证书，复用上面“TLS 档通用证书流程”（上传 / ACME），不引入 Caddy。
- **驿站已超集（233boy 没有）**：Naive、WireGuard、SOCKS、HTTP、MTProto、链式代理。按原计划保留，不砍。
- **不跟的项**：BBR（一键启用 BBR 是主机内核调优，不是协议，不进面板；真要开给他一条命令即可）；DNS 设置（服务端直连出站不依赖面板 DNS，不需要）；导入配置（脚本形态 vs 面板结构化节点，形态不同）；gRPC（233boy 清单里没有，sing-box 原生支持 type grpc，官方构建为 lite 实现——传输层通用能力随同实现，但不进首批档位，后续可选）。

## 实施顺序

1. sing-box 入站生成器（proxy 包新增 singbox.go：SingBoxInbound、SingBoxConfig、SingBoxRule、出站 builders）；生成 JSON 用 sing-box check 校验（本地下载 amd64 sing-box 到 /tmp 校验，或用 Oracle 上的 sing-box 只读校验，不启动服务）。
2. 链式路由 + B 出站生成。
3. nft 计数采集器（替代 stats.Poller 的 xray 部分），与现有 Poller 接口对齐。
4. 面板 UI：内核卡片、添加页签、Naive 证书流程。
5. 迁移脚本 + 新旧对照校验。
6. Oracle 沙盒验证：先用测试端口跑新 sing-box 配置（不碰生产端口），逐协议测通后再割接。
7. 割接（报用户定时间）→ 验收（对标 45 项）→ 观察期 → 删旧核心（经用户确认）。

## 待核对清单（已核对项打勾，剩余项实现/沙盒时验）

- [x] TUIC v5 inbound 字段（congestion_control 默认 cubic、zero_rtt 建议关、heartbeat/auth_timeout 默认、tls 必填、无 udp_relay_mode）
- [x] AnyTLS inbound 字段（users name/password、padding_scheme 默认、tls 入站可选但面板一律启用）
- [x] Naive inbound 字段（users 必填、network tcp/udp、tls 必填且生产不用自签）
- [x] sing-box reality handshake 字段（handshake.server / server_port）与 short_id 数组格式
- [x] sing-box WG 是端点（endpoints 段、address 必填、peers 字段、system false 用户态）
- [x] sing-box clash_api 无累计统计端点（/traffic 实时流、/connections 当前快照）
- [x] 链式嗅探机制（sniff 规则动作、inbound.sniff 已废弃、无 override_destination）
- [ ] VLESS / VMess / Trojan 各传输档的 sing-box transport 字段（ws path/headers、http host/path、httpupgrade host/path、quic）以 V2Ray Transport 官方页为准，实现时 sing-box check 验
- [ ] 官方 release 二进制含 with_wireguard（沙盒 `sing-box check` 验）
- [ ] Hy2Online 在 UI 里的用处（查 server.go 后定去留）
- [ ] Naive 证书走 certificate_provider（ACME）细节（实现时查 Certificate Provider 页；v1 先用上传证书）
- [ ] 全部生成配置过 `sing-box check`（实现时逐份验，这是最终兜底）

## 2026-10-30 补记（test4 已落地）
- nft 表：按数据目录哈希区分实例（yizhan-<hash>），双面板同机不再互删规则；旧版生产不走 nft，不受影响。
- Hy2 在线人数：sing-box 无按入站在线数，面板 online 恒 0，已知缺口，非 bug。
- Naive：面板侧全验（建节点禁用→传证书→自动启用→监听→TLS 1.3 握手→非 naive 请求被拒），真客户端全程因标准 sing-box 二进制缺 cronet 库而无法验证，留待真 naive 客户端。
