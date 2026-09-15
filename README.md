# dnsss —— 域名资源所有权风险态势感知系统(Go 重写)

按《Go 重写技术方案 v1.0》将原 Python/Django 2.2 系统重写为 Go。
本仓库当前交付 **Phase 0-2 + HTTP prober**;后续阶段按第 10 章路线图迭代。

## 当前已交付(对照技术方案)

| Phase | 内容 | 状态 |
|---|---|---|
| P0 | 脚手架:config(env 注入)/ envelope / recover / CORS / JWT 中间件 / zap 风格 slog 日志 | ✅ |
| P1 | oauth 三接口(login/refresh/info)、users 表、admin 种子、netprobe meta | ✅ |
| P2 | DNS 引擎(miekg/dns:EDNS/DNSSEC/UDP-TCP/权威模式/AXFR/泛解析/trace/延迟采样)、单任务创建→异步执行→详情全链路、executions 契约结构 | ✅ |
| P3 | HTTP(httptrace 四段计时)+ PING(pro-bing 原生 ICMP,特权→非特权降级)+ MTR/Traceroute(exec 系统命令 + 输出解析);五协议 detail 契约字段 | ✅ |
| P4 | Asynq 队列(default/netprobe)+ 独立 worker 二进制;批量创建(multipart + normalizer)+ goroutine 池执行引擎(256 并发/200 条缓冲落库/stop 语义);批量全套接口(列表/详情/结果分页/单条/停止/重跑);日聚合定时任务 | ✅ |
| P5 | risk-board 五接口(meta/overview/globe-layers/node-distribution/batch-risk-overview,30s 缓存)+ passive-alerts(preset 演示数据 + 空骨架) | ✅ |
| P6 | dnsrisk 可信库:domains/hosts CRUD+分页(ids_only/无分页/分页三形态)、import-manifest(JSON/YAML 子集,apex 自动补齐+升级式 upsert)、discover-candidates(apex/NS/子域三类查询计划,NS 主机自动扩散)、候选审批(单机/批量,diffStatus 状态机,baseline 重建)、baseline/snapshots 接口、build-jobs(异步分片+进度+断点 retry) | ✅ |
| P7-P9 | 扫描器、MQTT 探针、报告 | ⬜ |

## 快速开始

```bash
# 1. 准备 MySQL 8 与依赖
export DNSSS_DB_DSN='root:pass@tcp(127.0.0.1:3306)/dnsss?parseTime=true&loc=Local'
export DNSSS_JWT_SECRET='<≥32 字符随机串>'
export DNSSS_ADMIN_PASSWORD='<初始 admin 密码>'

# 2. 构建 + 迁移 + 种子
make build
make migrate-up
make seed

# 3. 启动(生产形态:API + 独立 worker,需 Redis)
export DNSSS_REDIS_ADDR=127.0.0.1:6379
./bin/dnsss-server &
./bin/dnsss-worker -concurrency 8 &

# 开发形态(无 Redis):仅启动 server,单次/批量在进程内执行
./bin/dnsss-server

# 4. 冒烟
curl -s localhost:8000/healthz
TOKEN=$(curl -s -X POST localhost:8000/api/oauth/login/ -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<密码>"}' | jq -r .data.token)
curl -s localhost:8000/api/netprobe/meta -H "Authorization: Bearer $TOKEN" | jq .code
```

本地测试 resolver(不打公网,兼作压测口径):

```bash
go run ./scripts/testresolver   # 127.0.0.1:8053,example.test 本地域,其余 NXDOMAIN
```

## 目录结构

```
cmd/server/            HTTP API(批量/单次经 Asynq 派发;未配 Redis 时进程内执行)
cmd/worker/            Asynq 消费者 + 周期任务(心跳/日聚合,replaces Celery beat)
internal/config/       DNSSS_* 环境变量配置(零硬编码凭据)
internal/database/     GORM MySQL 连接
internal/apitime/      契约时间类型(微秒 6 位无时区后缀)
internal/dto/          统一响应包裹 {msg,errors,code,data}
internal/middleware/   recover / 日志 / CORS / JWT(白名单豁免)
internal/model/        GORM 模型(全新 Go schema)
internal/auth/         JWT(HS256,drf-jwt payload 兼容)+ bcrypt
internal/engine/       dnsclient(miekg/dns 封装)+ prober(DNS/HTTP)
internal/service/      任务编排:校验/节点选择/执行/汇总/DTO
internal/seed/         8 地区 + default-node + admin
internal/httpapi/      路由与 handler
migrations/            golang-migrate SQL(up/down 成对)
scripts/testresolver/  本地测试 DNS 服务器
scripts/loadtest/      压测工具(2.10 口径:创建/执行/吞吐分档)
```

## P4 性能验收(本地 resolver 口径,scripts/loadtest)

| 档位 | 创建 | 执行 | 吞吐 | 红线 |
|---|---|---|---|---|
| 100 | 67ms | 1.08s | 92/s | —(原版 7/s) |
| 1000 | 72ms | 1.08s | 928/s | —(原版 27/s) |
| 10000 | 214-638ms | 3.2s | **3110-3134/s** | **≥1000/s ✅(3.1×)** |

- 10k 档创建 ≤1s ✅;结果无丢失(completed==expected==DB 行数)✅;stop 后立即 cancelled ✅
- worker 内存 ~20MB(红线 ≤512MB)
- 原版基线:109/s(20 线程池);Go 版批量引擎为原版 **28×**

## P5 验收记录(方案 11.2 #11/#13)

- **KPI 自洽**:totalRiskCount(5) == protocolAnomalyCount(5) + dnsHighConfidenceCount(0);impactedRegionCount 与事件流地区一致;successRate24h 覆盖单目标+批量双源
- **协议异常判定阈值**(与原版一致):HTTP 失败/5xx→high、延迟≥1500ms→medium;PING 失败→high、丢包≥20%/延迟≥300ms→medium;MTR 未达→high、丢包≥20%/延迟≥500ms→medium;Traceroute 未达→high、跳≥20/延迟≥800ms→medium
- **DNS 批量结果不产生协议异常事件**(与原版一致,DNS 风险事件流待 P7 扫描器接入)
- **drilldownUrl**:单次 `/network-probe/result/{id}`、批量 `/network-probe/batch-result/{id}?resultId=&keyword=`
- **30s 缓存**:冷查询 15ms → 命中 0.4ms
- **passive-alerts**:`?preset=public` 返回 6 条演示数据(类型/时间线/榜单/分页齐全);无 preset 返回空骨架
- 已知边界:globe 的 arcs/hotspots 需目标 IP 地理坐标(IP2Location BIN,P9 geoip 接入),当前返回空数组——前端空态渲染正常

## P6 验收记录(方案 Phase 6:导入→发现→审批→baseline 就位)

- **导入**:3 域名 JSON manifest → 3 域名 + 4 主机(www + apex 自动补齐),upsert 计数正确
- **发现**:5 主机处理(含 NS 主机自动扩散 ns1.example.test)、10 条候选(dig 行解析入三 section)
- **审批**:单机 approve → 4 条 baseline 就位、host 转 trusted;bulk-approve → 4 主机 6 记录、批次转 approved
- **diff 状态机**:重新发现后 baseline 命中显示 `unchanged`,移除记录显示 `removed`
- **build-jobs**:2 域名 chunk=1 → 进度 2/2=100%、trusted_hosts=7;文件缺失 → failed + last_error;retry 断点续跑幂等
- 候选记录唯一键采用 rr_hash(sha256) 列规避 utf8mb4 索引 3072 字节上限
- dns-trust 全部接口要求登录(安全修复项,原系统部分匿名可写)

## 契约回归要点(11.5 已落地项)

1. envelope 结构(前端拦截器解包依赖)——dto + 测试覆盖
2. 时间格式微秒 6 位无时区——apitime + 测试覆盖
3. once 任务 id 即 executionId、resultUrl 返回
4. 403 `请先登录` / 400 `用户名或密码错误` 文案
5. answers dig 格式(`name. TTL IN TYPE VALUE`)——dnsclient + 测试覆盖
6. 匿名 once 可创建、匿名 schedule 拒绝、任务归属 token 用户
7. 空数组输出 `[]` 而非 `null`
8. 默认地区回退(global 兜底)、无效地区报 `无效地区: xxx`

## 已知差距(后续 Phase)

- risk-board 聚合、passive-alerts 骨架(P5)
- dnsrisk 可信库 + 扫描器 + 14 类风险判定(P6-7)
- MQTT bridge + agent(P8);PDF/XLSX 报告(P9)
- compare_with_trust 依赖可信库表,P6 接入后开放
