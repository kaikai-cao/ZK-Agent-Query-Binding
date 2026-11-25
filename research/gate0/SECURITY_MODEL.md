# SECURITY_MODEL.md — Gate 0 统一安全模型

**任务：** ZKQ-00-G0 + ZKQ-00-G0.1（有限文档校正：ACL 保密对象与查询覆盖范围）
**日期：** 2026-11-25
**性质：** 研究模型定义，**不是**安全证明，也**不是**任何系统已满足该模型的结论。G0.1 仅校正威胁模型口径与裁决措辞，不新增实验、不新增相关工作。
**证据等级：** 沿用旧仓库冻结基线口径——R0 定义 / R1 源码静态核对 / R2 上阶段实测 / R3 本阶段新实验。本文件主体为 **R0 定义**；引用旧仓库事实时标注其原始等级。

---

## 0. 本文要防的概念混淆（Gate 0 核心）

Gate 0 的任务不是论证候选方向可行，而是判断它是否只是已有两类工作的拼接。因此必须先固定三类**互不等价**的性质（与 CVA §4.5–§6、旧 MVP `security-properties-v0.1.md` 一致）：

| 性质 | 含义 | 形式化记号 |
|---|---|---|
| **A. Authorization Binding** | 证明请求符合指定主体、策略、上下文和有效期的授权关系 | `VerifyAuth(pp, x_q, π)=1` |
| **B. Query Result Correctness** | 证明输出是某指定 Query 在某已承诺数据快照上的正确、完整计算结果（含无插入 / 无遗漏） | `VerifyQuery(..., root, Q, R)=1` |
| **C. Runtime Execution Binding** | 证明授权声明与运行时**实际执行行为**（实际读取了哪些记录、实际执行了什么查询）之间的对应关系 | `q_exec = q_auth` 且 `actual_rows = authorized_rows` |

**CVA §4.5 原文（本次核验，R1）**：

> `VerifyAuth(pp,xq,π)=1 ⇏ qexec=qauth` ... "Authorization Request Binding ≢ Runtime Execution Binding."

> "A ZK circuit is evaluated at proof generation time over a committed representation of the intended request; it has no access to the runtime state at execution time ... Closing this gap requires a trust anchor that operates at execution time rather than at proof generation time."

**必须分开记录的五个不等价（任务包 §2.1 + CVA §6）**：

1. 查询结果正确 **≠** 服务器没有额外读取其他数据。
2. 结果正确证明 **≠** 数据库数据本身真实（garbage-in-garbage-out）。
3. 数据快照承诺 **≠** 该快照是最新快照。
4. 证明某输出正确 **≠** 工具没有执行其他未授权操作。
5. Adapter 自签回执 **≠** 独立的实际执行证明（旧 MVP E2.2 已实证，见 §6）。

---

## 1. 系统角色与信任假设

| 角色 | 记号 | 信任级别 | 持有物 | 在本模型中的职能 |
|---|---|---|---|---|
| Agent / Planner | `A` | **不可信** | 私有授权属性 `attrs_i`（角色、部门、ACL 成员）、签发后的授权证明 | 产生查询请求 / 查询计划；可能受 prompt injection 或被主动攻破；**不持有**签发私钥 |
| 授权签发方 / Issuer | `I` | **可信** | 策略 `P`、策略版本 `pid`、签名私钥 `sk_I` | 验证 `attrs_i` 与策略后签发 Grant；策略治理 / 版本化属其职责 |
| 数据所有者 | `DO` | **可信（对数据真实性）** | 原始数据 `D`、承诺随机数 | 产生承诺的数据快照 `[D]` 与 `database_root`；快照是否"最新"不由承诺保证 |
| 查询服务 / Prover | `S` | **不可信（核心对手）** | 数据快照副本 / 索引、查询执行环境；**是否可见 ACL / 是否持私有 ACL witness 为 G0.1 核心阻断项** | 执行 Query、返回 `R` 与查询证明；可能返回错误结果或虚假声明执行行为 |
| 结果验证方 / Verifier | `V` | **验证逻辑可信，状态可能有限** | `agent_id`、`query_hash`、`policy_id/version`、`database_root`、`R` 的承诺；目标是不见具体 ACL 规则 | 验证授权证明 + 查询证明 + 公共输入一致性，决定接受 / 拒绝结果 |
| 策略 / ACL 权威 | `PA` | 可信（可与 `I` 合并） | ACL 规则、策略版本历史、撤销状态；可作为候选 ACL witness holder，但职责未闭合 | 定义行级 / 字段级访问约束；撤销操作的时间点影响 H2；能否在不向 `S` 暴露 ACL 的前提下支撑证明生成未定 |

---

## 2. 攻击者能力（按角色分层）

### 2.1 不可信 Agent `A`
- 构造越权查询 / 扩大过滤条件 / 提升 LIMIT / 越界投影字段（旧 MVP 的 ATK-A1、filter-widening、row-limit-escalation）。
- 替换执行上下文（tenant/session）、重放旧 Grant、伪造身份属性声明。
- **不能**伪造 Issuer 签名、不能破坏 SNARK soundness（否则模型失效，属排除项）。

### 2.2 恶意查询服务 `S`（本模型最关心的对手）
按能力由弱到强：

| 能力 | 具体行为 | 对应性质 |
|---|---|---|
| S1 结果伪造 | 返回与 Query 不符的结果（插入不符合条件的行 / 漏掉符合条件的行） | B |
| S2 条件篡改 | 扩大 / 缩小 WHERE、篡改 ORDER BY / LIMIT、越界投影字段 | B / H3 |
| S3 快照替换 | 用另一个（非承诺的或旧版本的）数据库计算并返回结果 | B + H2 |
| S4 执行行为虚假声明 | **实际执行越权查询，却声明执行的是授权查询**（合法密钥持有者对真实执行作不真实声明） | C / H1 / H3 |
| S5 选择性遗漏 | 仅返回部分授权记录，声称结果完整 | B / H1 |

### 2.3 网络与状态攻击者
- 窃听 / 重放传输中的 Grant 与结果；篡改传输中的结果或证明。
- 攻击者**不能**攻破 Verifier 的验证逻辑（排除项，见 §5）。

---

## 3. 受保护资产与泄露对象

### 3.1 受保护资产
1. 未授权记录的内容（机密性）。
2. 授权属性 / ACL 规则本身（私有 ACL 隐藏目标，H1）；**必须先指定隐藏对象：Agent / Verifier、Query Service / Prover，或双方**。
3. 查询结果的正确性与完整行集合（完整性）。
4. 授权的新鲜性 / 未撤销性（H2）。

### 3.2 对各方泄露 / 可见的信息
| 对象 | 对 `S`（查询服务）可见 | 对 `V`（验证方）可见 |
|---|---|---|
| Query 明文 | 通常可见（本模型不假设查询隐私） | 可见或仅见 `query_hash`，视构造而定 |
| 访问模式 / 读取了哪些记录 | **可见**（`S` 自己执行） | 需 B/C 证明间接约束 |
| Agent 私有属性 `attrs_i` | 不应可见 | 目标：隐藏，仅验证满足关系 |
| ACL 规则 / 行级授权集合 | **G0.1 核心模型分叉**：本模型希望隐藏；但 SIGMOD'18 中 SP 明确接收并使用 `Υ_i` | 目标：隐藏，仅验证约束成立；若 `V == 查询用户`，SIGMOD'18 仅对不可访问记录隐藏 ACL，对可访问记录会返回 `Υ` |
| `agent_id` / `policy_id` / version / nonce / expiry | 依实现 | 公共输入，可见（CVA §5.2 的 `x_PoC`） |
| `database_root` / `result_commitment` | 可见 | 可见 |

> 查询明文是否对 `S` 隐藏属于**查询隐私**问题（A1/A2/A3 执行模型）。PA-VFANN 的 R0.2.1 审计已独立确认：ASQ 默认是 A1 本地明文检索，`NO VERIFIED QUERY-PRIVATE RETRIEVAL BACKEND`。本 Gate 0 **不重新审计查询隐私**，并明确不把"查询明文对服务不可见"当作本模型已给的前提。若候选方案需要该前提，必须单列阻断项。

### 3.3 ACL 保密对象的三分法（G0.1 修正，必须区分）

"私有 ACL"不是一个单一性质。以下三类不等价，不能互相替证：

| 类型 | 目标 | 含义 | 与 SIGMOD'18 的关系（[原文] + [推论]） |
|---|---|---|---|
| **H1-U** | ACL 隐藏于 Agent / 查询用户 / 若 `V` 与用户合并则隐藏于 `V` | 用户不能从 VO 推断不可访问记录的内容、数量或具体失败角色 | **[原文] 支持**。§3 明确威胁是"users are curious"；§3 机密性定义写 "the users ... not know ... specific role(s)"、"the users can gain nothing about D\D+"；§7 Definition 7.5 形式化的是恶意用户区分真实/模拟数据库的能力。 |
| **H1-S** | ACL 隐藏于 Query Service / Prover | 不可信服务端在生成查询结果与证明时不获知行级 ACL，也不持有 ACL 私有 witness | **[原文] 不支持，且相反**。§3 记录为 `⟨o_i, v_i, Υ_i⟩`，全部记录外包给 SP；Algorithm 1 明示 `Outsource all records ⟨o_i,v_i,Υ_i,σ_i⟩ to the SP`，VO 构造按 `if Υ_oq(A)=1` 分支并以用户角色集 `A` 构造 relaxed proof。SP 可见并使用 ACL。 |
| **H1-Both** | ACL 同时隐藏于 Agent / Verifier 与 Query Service / Prover | 双方都不见 ACL，同时仍能验证授权约束结果完整性 | **[未核实 / 模型阻断]**。本轮未在已核验来源中发现一个可执行的架构证据；不得把 H1-U 的原文结论改写成 H1-S 或 H1-Both。 |

> **关键勘误：** SIGMOD'18 的 "Zero-Knowledge Confidentiality" 保护的是**用户不获知可访问记录之外的信息**，而不是让 Service Provider 自己对 ACL 不可见。把前者写成"服务端 ACL 隐藏"会改变威胁模型，属于 G0.1 必须纠正的口径错误。

### 3.4 若 `S` 不知道 ACL：证明生成者必须闭合（G0.1 核心模型阻断项）

当前 `SECURITY_MODEL.md` §3.2 要求 ACL 对 `S` 不可见，同时 §1 又把 `S` 设为查询证明的 Prover。二者尚未闭合：

| 架构变体 | 谁持有 ACL / 私有 witness | 谁生成查询完整性证明 | 能否独立由 `S` 生成 | 信任与范围变化 |
|---|---|---|---|---|
| **SIGMOD'18 原式** | DO 把 `Υ_i` 随记录交给 SP；用户持角色集 `A` | SP 使用 `Υ_i` 与 `A` 构造 VO | 能，但**因为 SP 看得见 ACL** | 只覆盖 H1-U，不覆盖 H1-S |
| **S-as-Prover 且 ACL 对 S 隐藏** | 必须由 DO / PA / Issuer 或安全计算环境私下持有 ACL witness | 若仍由 `S` 出证明，需要一种无需看见 ACL 即可满足行级授权约束的证明机制 | **未证可行** | 本轮无原文/源码证据；需说明 witness 如何进入证明而不泄露给 `S`，以及状态新鲜性如何可信获得 |
| **DO / PA-as-Prover** | DO / PA 持有 ACL 与快照 | DO / PA 生成查询证明；`S` 只传递或执行查询 | 否，`S` 不再是独立 Prover | 信任边界从"不可信查询服务"移到 DO / PA；不再等价于任务包的朴素组合，也不自动覆盖运行时执行行为 |
| **Issuer-as-Prover / 联合见证** | Issuer 或部分持Attrs/ACL，DB 端仍持快照 | 需要跨方证明生成协议 | **未证可行** | 属新架构问题；本轮只标 UNKNOWN，不声称增量成立 |

### 3.5 G0.1 角色持有数据核对表

| 角色 | 当前 Gate 0 模型持有 | SIGMOD'18 对照 | G0.1 状态 |
|---|---|---|---|
| `S` Query Service | 数据快照副本 / 索引、查询执行环境；H1-S 下目标为**不见 ACL** | 接收完整 `⟨o_i,v_i,Υ_i,σ_i⟩`，VO 构造使用 `Υ_i` 与用户角色集 `A` | 与当前模型冲突；不可把 SIGMOD 写成 H1-S 证据 |
| `V` Verifier | `agent_id`、`query_hash`、`policy_id/version`、`database_root`、`R` 承诺；目标不见具体 ACL | 无独立 `V`；用户验证，且可访问记录的 VO 含 `Υ` | 若 `V` 与用户合并，仅 H1-U 有覆盖；独立 `V` 不可直接套用 |
| `DO` Data Owner | 原始数据 `D`、承诺随机数；可视为 ACL/策略来源之一 | 生成 ADS/APP 签名并把含 `Υ_i` 的记录外包给 SP | 若改由 DO 出证明，信任边界改变；未在本轮设计为可行方案 |
| `I` Issuer | 策略 `P`、`pid`、签名私钥 `sk_I`；验证属性并签发 Grant | 无对应 Agent 授权签发方 | 默认不等于行级 ACL witness holder；若兼任需重新定义 trusts |
| `Prover` | 原模型与 `S` 合并；H1-S 下需说明是否仍为 `S` | SP 是 Prover/VO 生成者，因可见 `Υ_i` 才能工作 | S-as-Prover + ACL 隐藏未证；DO/PA-as-Prover 改变原模型 |

结论：`ACL 对 S 隐藏`与`S 独立生成查询完整性证明`目前不能同时从已核验来源推出。若选择 DO / PA 作为证明者，系统已经不是"不可信查询服务自证查询结果"的原模型；若仍要求 `S` 出证明，则必须补充私有 ACL witness 的持有者、进入证明的路径和相应信任假设。

---

## 4. 信任假设（模型成立的前提）

1. Issuer 正确执行策略、私钥不泄露；策略治理与电路编码的一致性由 Issuer / PA 负责（CVA §6 Gap 2：proof correctness ≠ policy correctness）。
2. 数据所有者提供的承诺快照在承诺时刻与其数据一致；**快照真实性 / 最新性不由本模型保证**。
3. 密码学原语安全：SNARK 可靠性、承诺的绑定性与隐藏性、哈希抗碰撞；trusted setup 外部信任假设（CVA §7 明确承认）。
4. Verifier 的验证逻辑被正确执行，公共输入由 V 独立指定（不可由 `S` 自行填入后自证）。
5. 假设存在可核验的执行时信任锚（TEE / 远程证明 / 可验证回执）——**这正是 CVA 明确保留的开放问题**，本 Gate 0 不假设它已经存在；若候选方案依赖它但不提供，须标为阻断项。

---

## 5. 明确不在范围内的攻击

- Gateway / Verifier 被完全攻破（旧 MVP 排除项 2；一旦不成立所有性质失效）。
- 数据源本身造假（承诺时数据即错误）——数据真实性不在 ZK 查询证明的保证内。
- "快照是否最新"的绝对判定；本模型只处理"策略版本与快照版本的联合一致性"（H2），不处理外部世界的真实时间。
- 多智能体委托链的范围保持（CVA §6 Gap 4，CVA 作者明确未形式化）。
- 查询隐私 / ORAM / PIR 层面的访问模式隐藏（见 §3.2 边界说明）。
- 可用性 / DoS、物理攻击、后量子安全（CVA §7 承认 Groth16 非后量子）。
- 策略本身"是否正确"的规范性问题（CVA §6 Gap 2；属治理，不是密码学绑定）。

---

## 6. 已有实证反例（来自旧仓库，非本阶段新实验，**R2**）

旧仓库 `agent-exec-binding-mvp` 分支 `experiment/independent-execution-proxy`（SHA `e327a9444ed8cea17baefbac01587b7fa77e8d39`）的 `research/e-stage-results-v0.1.md` 已冻结以下结果（引用，不冒充本阶段结论）：

- **E2.1**（10/10）：Adapter 实际执行越权 Finance 查询但**如实**报告，`request_hash` 失配被检测，`DR=1.0`——但数据已被查询，检测 ≠ 阻止。
- **E2.2**（10/10）：Adapter 实际执行 Finance 查询，丢弃诚实回执，用**同一把合法 `tool_sk`** 自签 `request_hash=H_authorized` 的回执，`output_hash` 取真实越权结果。Gateway 八项绑定失配项恒为 `[]`，返回越权数据，`DR=0`、`UER=1.0`。审计链 `AuditChain.verify()` 10/10 通过——**结构完整但语义错误**。

该反例证明：仅靠签名回执 + 审计链，**无法**得到性质 C（Runtime Execution Binding）。这是朴素 CVA 授权证明在"运行时实际读取了哪些记录"这一维度上的实质性缺口，也是判断候选方向是否仍有增量的关键锚点——如果新增的 ZK 查询证明仍无法覆盖 S4/S5，则该方向只得到"查询结果正确"而得不到"实际执行被约束"。

旧仓库 README（`R1`）已明确写出其边界：
> "The tool server is a mock process and is trusted to sign truthful execution receipts. A signature authenticates the server's assertion; it does not independently prove that external data are true."
> "This MVP isolates the authorization-to-execution binding problem rather than claiming novelty for generic 'LLM + ZKP' integration."
> "A recent CVA study explicitly lists context-binding implementation and runtime execution binding as open problems."

---

## 7. 本模型下待判定的三个缺口（任务包 H1/H2/H3，**尚未成立为研究贡献**）

- **H1 私有 ACL 约束下的结果完整性**：必须先拆为 H1-U（对 Agent / Verifier 隐藏）、H1-S（对 Query Service / Prover 隐藏）与 H1-Both（双方隐藏）。SIGMOD'18 覆盖 H1-U 的 equality / range / join 场景，但**不覆盖** H1-S，因为 SP 接收并使用 `Υ_i`；H1-S 的证明生成者架构未闭合，不能自动认定为研究增量（见 §3.3–§3.4）。
- **H2 策略版本与数据快照的联合一致性**：Grant 绑定 `policy_id/version`，查询证明绑定 `database_root`；授权时刻 `t_auth` 与执行时刻 `t_exec` 之间 ACL / 数据变化时，旧证明能否仍被接受？须对照已有数据库版本 / 撤销机制。若 `V` 已可信持有当前策略版本、数据根与撤销表，则版本比较与撤销表检查属常规状态机制；仍需证明该当前状态如何可信获得。
- **H3 授权约束查询的输出完整性**：必须按算子拆分——查询条件、行集合 soundness/completeness、字段投影、LIMIT / 排序、聚合各自标注，不得用"任意 SQL 已覆盖"概括。SIGMOD'18 明确支持 equality / range / join，并把 aggregation 列为 future work；TruthTable / PoneglyphDB / ZkChainDB 的 Query Correctness 也不自动等同于私有 ACL 强制。

三者是否构成"不能由简单组合得到的新性质"，由 `COMPOSITION_ANALYSIS.md` 与 `DECISION.md` 裁决；本文件不预先假定任何一个是真缺口。
