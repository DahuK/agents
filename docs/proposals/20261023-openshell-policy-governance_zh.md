---
title: OpenShell 策略治理框架接入（行为约束能力）
authors:
  - "@DahuK"
reviewers:
  - "@TBD"
creation-date: 2026-10-23
last-updated: 2026-10-27
status: provisional
see-also:
  - "/docs/proposals/20260727-agent-dynamic-identity-spiffe-token-exchange_zh.md"
  - "OpenShell 实现对齐与演化路线（2026-10-26 评审输入）"
---

# OpenShell 策略治理框架接入（行为约束能力）

> 本提案不引入 Feature gate。当前阶段（M0/M1）只交付可预览、可验证的核心库与治理骨架，
> 不启用生产 enforcement。发布路径默认拒绝任何无法完整执行的 OpenShell 语义；
> 文档中的“已交付”只描述源码与单测事实，不等同于数据面已接通或已生效。

## 概要

在不改变本仓库沙箱运行时与 guest 架构（Pod + sidecar 注入模型）的前提下，引入
[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) 的策略治理模型，作为 AI Agent
行为约束能力的控制面。接入分两种模式，不能混为一谈：

- **社区治理兼容模式**：OKA 的 PolicyProposal controller 是提案裁定与发布的唯一权威；
  Agentio/EPE 是有限 HTTP 网络策略的执行者。支持范围由显式、版本化契约
  `endpoint-rest-v1` 定义：精确 host:port、显式 `protocol: rest`、显式
  `enforcement: enforce`、无重叠端点、精确或 `/**` 路径规则。
- **原生运行时模式**：OpenShell gateway 是原生策略与 review-token 的唯一权威，
  supervisor/runtime 提供 binary 身份、文件策略与 syscall broker；OKA 只供给 Sandbox
  与 workload Pod，并把提案代理到上游。该模式尚未实现，需要合格的 runtime 与内核。

本分支交付的是社区模式的**预览层与治理骨架**：解析、诊断求值、有损投影、完整文档
候选合并、决策 artifact 编译、人工裁定与崩溃恢复。真正的执行链（payload → filter →
ext-proc → 结构化 403 → ACK）尚未交付，见 M3/M4。

## 动机

Agent 沙箱需要的是“最小权限 + 可申诉”的运行期约束：Agent 的越权请求被结构化拒绝
（`policy_denied` + `rule_missing`），Agent 提交窄化提案，人（或治理规则）审批后热生效。
OpenShell 已实现该循环与原生治理语义；本仓库具备 Kubernetes 原生的沙箱供给与
TrafficPolicy/SecurityProfile 数据面，但缺少提案审批闭环与治理控制面。复用而非重写。

## 术语表

- **OpenShell SandboxPolicy**：OpenShell 的沙箱策略文档（YAML）。`network_policies`
  为 host:port 端点集合，端点带 `access`（full/read-only/read-write）、`enforcement`
  （enforce/audit，缺省按 audit）、L7 `rules`（allow/deny 的 method+path）与
  `binaries` 绑定；另有 `filesystem_policy`、`landlock`、`process`、middleware 等段。
- **PDP / PEP**：原生模式下 PDP 是 OpenShell gateway；社区模式下 OKA 只持有提案裁定
  与发布权，不冒充原生 PDP。PEP 是 EPE/Envoy 数据面。Go 求值器是诊断与过渡实现，
  不是 OpenShell 原生 oracle。
- **Prover**：OpenShell 的 Z3 增量分析。OKA 的 `CheckProposalRisk` 是有限诊断，
  只覆盖 link-local 字面量等可判规则；不得命名为完整 Prover。
- **损失项（Loss Item）**：目标运行时无法表达的语义。损失项必须显式记录；严格发布
  模式下，任何损失项或未知安全字段都会阻止发布，而不是降级为 allow。
- **候选（Candidate）**：基线文档 + 操作批次 + 执行契约经本包合并、复验后得到的
  完整文档及哈希。批准只针对一次候选，不适用于新 generation 或目标重建。

## 基线（当前状态）

- 沙箱 = Pod（Sandbox/SandboxSet/SandboxClaim CRD，`RuntimeConfig` 注入 csi /
  agent-runtime（e2b envd）/ traffic-proxy sidecar）；无独立 guest kernel，无
  landlock/seccomp 使用。
- 出口治理 = TrafficPolicy/GlobalTrafficPolicy CRD（有序 allow/reject 规则，FQDN/CIDR/
  Service/Workload peer + L4 端口）+ Envoy 数据面；`SecurityProfile` 承载入口 L7 匹配。
- 已新增 `PolicyProposal` CRD、`openShellPolicy` action、`pkg/openshellpolicy` 库与
  `okactl policy` 运维入口；这些对象尚未在集群中启用生产执行。

## 方案

### 架构：三个平面

```
OpenShell 治理集群（仅原生模式；独立部署，二进制复用）
  openshell-server（PDP：SubmitPolicyAnalysis/chunk/approve）+ openshell-prover（Z3）
        │  ①策略下发（审批后的合并策略，proto/gRPC）
        ▼
决策适配层（本仓库新增，Go）
  pkg/openshellpolicy：解析 / 诊断求值 / 有损投影 / 候选合并（当前交付，默认仅预览）
        │  ②有限 REST 子集：与方法/路径规则对齐，不宣称与 rego 逐字等价
        ▼
OpenKruise Agents 数据面（PEP）
  TrafficPolicy CR（L4 host:port 白名单 + reject 兜底）+ Envoy 出口路径
  （未交付：ext-proc 钩子调用 ②，返回结构化 403；见 M3）
```

### 当前交付：`pkg/openshellpolicy`

分层合规：仅依赖 `api/v1alpha1` 与 `sigs.k8s.io/yaml`，controller 与 sandbox-manager
两侧均可引用，不构成新的跨层依赖。

1. **解析**（`ParsePolicy`）
   - 仅接受 `version: 1`；更高版本拒绝。显式 `version: 1` 且无 `network_policies`
     是有效的 deny-all 策略，不是解析错误。
   - 记录 `UnsupportedFields`（process、middleware、endpoint 的 tls/ports/query、
     rule 的 query/params 等）。这些字段保留在原文中；任何经裁剪模型的重写都会被
     拒绝，避免静默删除权威文档内容。
   - 拒绝跨策略或同策略内重复的 host:port：本数据面按唯一端点判决，而 upstream
     会联合所有匹配端点并让任一 deny 生效，重叠输入不能近似。
   - `access` 支持 full/read-only/read-write；`none` 不属于 OpenShell preset，已移除。

2. **诊断求值**（`Evaluate`/`EvaluateWithNextSteps`）
   - host:port 端点匹配，host 大小写与结尾点归一化；显式 deny 规则优先于 allow；
     有 allow 规则时必须精确命中（精确路径或 `/**` 前缀）。
   - read-only = GET/HEAD/OPTIONS（**不含 TRACE**）；read-write 另含 POST/PUT/PATCH；
     full = 全部方法。无规则且无 `access` 时按 upstream 的默认拒绝处理，不再隐式放行。
   - `enforcement` 缺省或 `audit`：放行并标记 `AuditOnly`，与 upstream 缺省 audit 一致；
     严格发布模式会拒绝此类端点，不把观察态伪装成执行态。
   - 非 `rest` 协议不按 REST 近似，直接拒绝求值；需要协议专用 provider 的能力属于
     原生模式。
   - 请求路径先规范化：拒绝 `..`/`.` 段、重复斜杠、反斜杠、fragment、控制字符、
     `%2F`/`%5C`/`%25` 与双重编码。不能保证与实际转发目标一致时 fail-closed。
   - 拒绝体保持 OpenShell 线格式：`error=policy_denied`、`rule_missing`、`next_steps`
     （空时序列化为 `[]`）；`next_steps` 指向治理集群的提案端点。

3. **投影**
   - `MapToTrafficPolicy`：每个端点 → 一条 FQDN+TCP allow 规则，去重、排序、可选
     reject-all 兜底。所有 L4 层放大的语义都进 `Losses`：binaries、L7 rules、
     read-only/read-write/无 access、audit、非 rest 协议、filesystem、landlock。
   - `MapToSecurityProfile`：校验后把原文整体内嵌到 `openShellPolicy` action，
     单条 `domains: ["*"]` 规则交由数据面做端点选择。内嵌文档不裁剪。
   - 两个投影默认 `RequireEnforceable: true`：存在任何 Loss 或 `EnforceBlockers`
     命中时拒绝发布；预览调用方可显式关闭并读取 Losses/Blockers。L4 allow 只能在
     L7 门禁就绪后开放，不能先放量再补检查。

### 当前交付：`PolicyProposal` 提案闭环

对应 OpenShell 的 Policy Advisor（deny → propose → review → merge）循环，以 K8s
原生资源落位。它对齐 OpenShell `PolicyMergeOperation` 的六类用户操作，但不是
protobuf 的逐字镜像；字段与合并语义的差异在下方“分歧修正状态”中列明。

1. **CRD**（`api/v1alpha1/policyproposal_types.go`）：六类操作
   （addNetworkRule / removeNetworkRule / removeNetworkEndpoint / addDenyRules /
   addAllowRules / removeNetworkBinary）。enum marker 已修正为
   `enforce;audit`、`full;read-only;read-write`，生成物已重新生成并加入
   `config/crd/kustomization.yaml`。
2. **候选准备**（`pkg/openshellpolicy/prepare.go`）：`PrepareCandidate` 接收完整源
   文档、操作批次与执行契约，按序在完整文档模型上合并并规范化复验；未知段
   （`process`、`filesystem_policy`、middleware 等）逐字保留，不再经裁剪模型重写。
   操作批次是原子的：任一操作失败都不产出部分候选。`addNetworkRule` 遇到同名 policy
   直接拒绝：upstream 会合并同名条目，本实现不做近似合并。只持有解析模型的旧调用方
   走 `ApplyMergeOperations`，它内部委托 `PrepareCandidate`，对未建模文档直接拒绝。
   `PolicyHash` 仍保留为裁剪模型的哈希，治理路径改用 `PrepareCandidate` 的语义
   identity。
3. **风险检查**（`pkg/openshellpolicy/risk.go`）：只对基线→候选增量做可判诊断；
   `link_local_reach` 可判，凭证域三类检查显式记为 `unchecked`。这是诊断，不是
   Prover，也不替代人工审批。
4. **控制器**（`pkg/controller/policyproposal`）
   - admit：校验操作，计算候选，**执行 `EnforceBlockers` 门禁**，记录 findings、
     unchecked、基线/候选哈希。新 generation 重新准入时清空旧 Decision 与执行字段，
     旧批准绝不沿用到新内容。门禁可用 `--enforce-blocks-enabled=false` 关闭，仅用于
     预览：准入仍成功但会发 `UnenforceablePolicy` warning 事件，且批准后会把数据面
     无法执行的文档写入 profile。
   - 上游语义基线：`openshellpolicy.VersionBaseline` 固定 OpenShell 源码 commit，
     controller 启动日志输出该基线；升级必须同时重新验证 parse/merge/求值一致性。
   - approve：先检查 profile 上的 apply credential（崩溃恢复）；再校验活文档哈希
     等于准入基线（review-token 语义）；重新计算候选哈希必须等于准入候选；在同一
     次 profile Update 中写入候选、revision 与 credential；最后用乐观锁写 status。
   - reject / fail：拒绝原因与执行错误分离；失败不冒充拒绝。
   - 已知边界：`Applied` 只表示 profile 已写入，**不表示 EPE 已加载或所有副本已受
     保护**；消费者 ACK 属于 M4。

### 分歧修正状态（相对 2026-10-26 路线评审）

| 分歧 | 修正 | 状态 |
|---|---|---|
| enum marker 生成 `;full`/`;enforce`，合法值被 schema 拒绝 | 修 marker，`make generate manifests`，补 kustomization | 已完成 |
| CRD 未进标准安装 | `config/crd/kustomization.yaml` 增加 PolicyProposal | 已完成 |
| 有损投影仍产出 allow | 默认 `RequireEnforceable`，Losses/Blockers 阻止发布 | 已完成 |
| 裁剪模型重写会丢权威字段 | 合并改为完整文档模型，未知字段逐字保留；`UnsupportedFields` 仍用于执行门禁 | 已完成 |
| 空 network_policies 被当错误 | `version: 1` 空文档 = 有效 deny-all；TrafficPolicy 需显式 deny 尾 | 已完成 |
| TRACE 被 read-only 放行 | read-only 改为 GET/HEAD/OPTIONS | 已完成 |
| 无 access/无规则被隐式放行 | 按 upstream 默认拒绝 | 已完成 |
| enforcement 缺省被当作 enforce | 缺省 = audit；严格发布要求显式 enforce | 已完成 |
| 非 REST 协议按 REST 近似 | 求值拒绝；严格发布阻止 | 已完成 |
| 多策略同 host:port 首命中近似 | 解析阶段拒绝重叠端点 | 已完成 |
| `/safe/../admin` 前缀匹配可绕过 | 非规范路径 fail-closed；拒绝编码分隔符 | 已完成 |
| 同名 addNetworkRule 覆盖 | 拒绝同名，不近似 upstream merge | 已完成 |
| 旧批准可复用于新 generation | 重新准入清空 Decision/执行字段 | 已完成 |
| profile/status 双写无恢复 | apply credential + 候选哈希复验 + 恢复路径 | 已完成 |
| status 写回无并发保护 | `MergeFromWithOptimisticLock` | 已完成 |
| 文档宣称数据面已接通 | 改为未交付，列入 M3/M4 | 已完成 |
| 上游语义基线未固定 | `VersionBaseline` 固定 OpenShell commit，不随 HEAD 漂移 | 已完成 |
| 门禁无法显式确认/关闭 | `--enforce-blocks-enabled`（默认 true）→ controller `AllowUnenforceable` | 已完成 |
| Rust 完整管理语义 | Go 参考 `PrepareCandidate` 已无损保留未知字段并分离三类身份；Rust helper 与差分语料未构建 | **部分完成（M1）** |
| 审批身份来自服务端、`--by` 不可信 | CLI 仍接受 `--by` | **未完成（M2/M5）** |
| 候选完整 diff / 不可变快照 | 只有哈希与当前文档 | **未完成（M2）** |
| Applied ≠ Effective、消费者 ACK | 尚无 ACK/发布状态聚合 | **未完成（M3/M4）** |
| 原生 binary/filesystem/process 执行 | 无 supervisor/runtime | **未完成（M6）** |

## 演进路线（对齐 M0-M7）

### M0：修正可安装性与能力声明（当前分支）

- [x] 修 enum marker，重新生成 CRD，补 kustomization。
- [x] 发布路径阻止 Losses/未知安全字段被静默放宽；映射默认仅预览。
- [x] 修正提案文档的 PDP/Prover 用词、“逐字镜像”和“数据面已接通”声明。
- [x] 修补输入边界：版本、端点重叠、空策略、路径规范化、同名 merge、非规范协议。
- [x] 在代码中固定 OpenShell 上游语义基线（`VersionBaseline`）；OKA、agents-api、
  Agentio 与测试语料的版本清单仍待补。
- [ ] 显式限定治理 controller 的启用范围，不以“CRD 没装”作为安全开关。
  - 已有准入门禁开关 `--enforce-blocks-enabled`（默认 true）；它只控制门禁，不是
    controller 的注册/启用开关。

退出标准：标准 manifest 包含 CRD；显式 enum 可通过真实 schema；未支持策略不能产生
enforce-ready 发布；文档与源码状态一致。

### M1：完整策略管理语义与有限执行契约

- [x] Go 参考实现 `PrepareCandidate`（`pkg/openshellpolicy/prepare.go`）：源文档 + 操作
  批次 + 执行契约 → 完整候选、warnings、支持/不支持项、三类身份。合并直接作用于完整
  文档模型，未知段（`process`、`filesystem_policy`、middleware 等）逐字保留。
- [x] 输入预算与错误分类：文档 256 KiB、嵌套 32 层、单批 64 个操作、每策略 256 个
  端点、每端点 256 条规则；错误类别为 `syntax`、`duplicate_field`、`version`、
  `invalid_policy`、`limit_exceeded`、`unsupported_contract`、`merge_conflict`、
  `internal`，并携带失败操作下标。重复 key 在合并前拒绝；批次失败不产出部分候选。
- [x] 身份分离：`SourceDigest`（原始字节）、源/候选 `SemanticIdentity`（规范化完整
  文档）、`ArtifactDigest`（编译后 artifact）。review token 与 apply 复验都使用语义
  identity，因此未建模字段的改动同样会被发现。
- [x] `DecisionArtifact` v1（`pkg/openshellpolicy/artifact.go`）：schema/契约/上游版本、
  源身份、按 host/port 排序的有限端点；预设只在作者未写规则时展开，deny 优先，空规则
  端点编译为 deny-all；binaries、audit、非 REST 一律拒绝编译。
- [x] controller 的准入与批准都经 `PrepareCandidate`；批准写回的 `Raw` 就是评审时的
  完整候选文档。
- [ ] 小型原生 Rust helper 与差分语料：当前环境没有 `cargo`，也没有锁定 commit 的
  OpenShell 源码 checkout，无法构建或运行 Rust 参考。Go 参考实现的单测
  （`prepare_test.go`、`artifact_test.go`）已覆盖字段保留、身份分离、预算与错误分类。
- [ ] 社区模式的支持面校验仍由 Go 参考承担；Rust helper 落地后需要在同一语料上做正负
  例差分。消费者绑定/ACK 属于 M4。

退出标准：完整文档修改不丢字段（已满足，见 `TestPrepareCandidatePreservesUnmodeledSections`）；
源 digest、语义 identity、artifact digest 分离（已满足，见 `TestPrepareCandidateSeparatesIdentities`）；
典型正负例与锁定版本的 Rust 参考一致（**未满足**：无 Rust 构建环境与上游 checkout）。

### M2：可审计且可恢复的人工审批

- spec 创建后不可变（或先盘点部署使用情况再迁移）。
- 服务端绑定目标 Profile UID、稳定 action/rule 身份、scope digest、源/候选 identity、
  执行契约与 credential descriptor 版本；namespace/name + hash 不足以防同名重建。
- 审批者只能写 Decision 字段；身份来自认证上下文；租户没有 Profile 发布权与
  Proposal status 写权；Decision 不可被第二个操作覆盖。
- 取消/过期、批准有效期、写 Profile 与 credential 的同一 CAS、status 失败恢复。
- 用不可变完整快照保存审阅候选（优先评估 ControllerRevision）。

退出标准：旧批准、新 generation、并发 approve/reject、目标重建、selector 修改、
profile 成功/status 失败、controller 重启均有针对性测试。

### M3：跨仓真实执行链

- 发布包含新 action/载荷契约的 agents-api，Agentio 升级依赖。
- 同一可验收切片完成 payload 映射、filter 注册、artifact 校验/编译、判决与
  extproc 响应翻译；只加 action 类型不算接通。
- EPE 只接受声明支持的 artifact 版本；受治理请求设置不可绕过的必需门禁
  （无身份/无匹配/bypass/坏 payload 一律拒绝）。
- 明确 HTTP/TLS 可见性、SNI/Host/端口与 upstream 绑定；阻止 opaque TLS、CONNECT、
  直接 IP/DNS/IPv6/UDP 绕过。

退出标准：真实 `SecurityProfile → watch → payload → filter → extproc wire response`
集成测试通过；真实 Envoy/网络 E2E 是发布门槛。

### M4：发布、生效确认与回滚

- 可信绑定：目标 scope、执行契约、预期 revision/artifact digest；应用不能自批 ACK。
- 发布状态区分 Desired/Published/Observed；保留既有 Applied 含义。
- 新副本/重启副本必须加载正确 snapshot 后才能服务受治理流量；单 EPE ACK 不代表
  所有消费者。
- 首次坏配置拒绝；无效更新保留 LKG 但报告 stale；删除策略先发布明确 deny。
- 跨 L4/L7 无原子事务：新授予先 L7 后 L4；撤销先拒绝门禁后收 L4。
- 撤销语义受快照切换与连接生命周期约束，不能承诺即时撤销。

退出标准：批准→发布→各执行者加载可追溯；新副本、watch 断连、坏更新、删除、
回滚、撤销及旧连接测试通过。

### M5：Agent 申请闭环与检查能力扩展

- Agent 身份从受信认证推导，只能针对自身 Sandbox/允许的 scope 提案。
- traffic-token JWT 不等于 OpenShell sandbox credential；issuer/audience/expiry/
  scope/Sandbox UID 需校验或受控交换。
- 返回结构化拒绝、申请入口、裁定与实际生效状态；去重、限频、配额、取消、过期。
- Prover 的 unsupported/inconclusive/error 保持独立结果；当前 link-local 检测
  只是诊断。凭证检查传递 descriptor，不复制 Secret；proof 绑定上下文。
- 企业上限显式校验合成后的 effective policy；检查能力完整前禁用自动批准。

退出标准：Agent 只能申请自身未授权目标；跨租户、旧 token、重建 Sandbox、重复
请求、能力上下文变化与未完成 proof 都不能误授权。

### M6：原生运行时接入

- 在一次性环境资格验证 Landlock ABI ≥3、NEW_LISTENER、ADDFD+SEND、外层
  seccomp/UID、网络 fence；版本号只用于预筛。
- 实现 `openshell-driver-kruise` 或复用 upstream K8s driver 的资源适配点；
  保持 OKA controller 是 Pod 唯一 owner/writer。
- 第一版只支持创建、受控主命令、受控 exec、stop/start、删除；非受控入口限制
  给运维；checkpoint/resume/热升级先拒绝。
- Native 模式由 gateway 唯一批准与合并；OKA 使用上游 draft/review-token 接口，
  不再把本地 hash 当上游 review_token。

退出标准：guest 正反向文件/网络/信号、binary 身份变化、控制面断连、重复
start/delete、owner UID 更换与非受控执行入口均有验证；明确支持的
driver/内核/镜像/协议组合。

### M7：规模化与可选增强

M4/M6 稳定后评估共享 supervisor、更多 L7 协议、自动审批、更广平台与 checkpoint。
每增加一个能力都更新能力契约、负例、回归语料与回滚资格。

## 推荐 PR 切片

| PR | 改动范围 | 前置 | 合并验收 |
|---|---|---|---|
| 01 | 文档状态、enum/生成物、安装清单、显式启用范围 | 无 | 标准安装含 CRD；schema 正常；不宣称 EPE 已接通 |
| 02 | 有损/未知字段发布隔离、输入边界与反例测试 | 01 | 未支持策略不可 enforce；预览仍展示 Losses |
| 03 | Rust 管理语义 helper、完整文档身份与差分语料 | 02 | parse/merge/hash 无损、失败原子、超时失败关闭 |
| 04 | 严格 REST 契约与有限 artifact compiler | 03 | 固定参考上下文正负例一致，拒绝未支持语义 |
| 05 | 提案不可变、可信审批、候选/目标/scope 绑定 | 01、03；04 接口先冻结 | 并发与越权字段写入均不误批 |
| 06 | 目标应用凭据、幂等恢复、完整历史、CLI review | 05 | profile/status 双写故障后正确收敛 |
| 07 | agents-api 发布 + Agentio payload/filter/wire 接线 | 04 | 跨仓真实输入到 403；不以本地 replace 发布 |
| 08 | 必需治理门禁、身份/旁路/opaque 协议防护 | 07 | 无 Profile/无身份/bypass/坏配置不放行 |
| 09 | 消费者绑定、ACK、stale 契约、L4/L7 发布与回滚 | 06、08 | 人审→发布→受保护的最小可上线闭环 |
| 10 | Agent 自助 API、身份/配额/去重、Prover/descriptor 检查 | 09 | deny/propose/review/effective 可验收；仍默认人审 |
| 11 | 原生资格 PoC 与 driver 资源映射 | 隔离环境与锁定上游版本 | 资格探测不依赖 03 helper，不在生产试装 |
| 12 | 原生生命周期、gateway 审批代理、迁移与回滚 | 11、05/06 契约 | 单写权威、原生执行闭环 |

最小可发布版本是 PR01-09，不是“先把 Go evaluator 注册进 EPE”。若只验证设计，可在
PR07 后做隔离环境 demo，但必须标明非生产、尚无完整旁路防护与 ACK。

### 首个生产切片进一步收窄

固定 guarded listener、精确 host/path、无重叠 endpoint、显式 REST/enforce、单个目标
Profile 串行发布，切换期间允许短暂隔离。首批只开放经过差分验证的操作（例如新增
不重叠网络规则）；其余拒绝执行发布。保留完整快照、故障恢复与紧急拒绝所需能力；
可信批准、未知字段拒绝、旁路防护、消费者就绪与实际加载证据不能后置。

## 备选方案

- **整体替换为 OpenShell k8s driver**：需注入 `openshell-sandbox` PID1 + seccomp
  listener + initContainer + NetworkPolicy fence，改变 guest 架构；仅作为原生模式的
  演进方向，不在社区模式启用。
- **仅在治理集群侧做 L4 投影（无 L7 求值器）**：丢失结构化拒绝与方法级约束，
  Agent 无申诉路径，否决。
- **Go 嵌入 OPA 执行同一份 rego**：可作为 L7 语义扩张后的过渡；当前先以显式
  受限契约收敛支持面，不宣称逐字等价。

## 未交付与后续

1. 数据面接线：Envoy ext-proc 出口钩子调用 `Evaluate`，返回结构化 403
   （`next_steps` 指向提案端点），并上报 artifact 版本与加载状态。见 M3。
2. 策略分发与生效确认：artifact 快照、消费者 ACK、Desired/Published/Observed
   状态聚合、回滚。见 M4。
3. 可信审批：服务端身份、Decision 字段隔离、不可变提案与完整候选快照。见 M2/M5。
4. 完整策略管理语义：Rust helper 与锁定版本的差分语料；Go 参考实现已交付。见 M1。
5. `openshell-driver-kruise`：实现 OpenShell `compute_driver.proto`，纳管沙箱生命
   周期与原生 runtime。见 M6。
