# PROTOCOL_FEASIBILITY.md — ZKQ-ARCH-01 Agent-bound Private Query 的 MPC 协议可行性判定

**任务：** ZKQ-ARCH-01（独立研究分支，只读研究 + 新增一份报告）  
**日期：** 2026-11-25  
**仓库：** `kaikai-cao/ZK-Agent-Query-Binding`  
**基线：** `research/g0-privacy-audience-correction` @ `524fc7a60afd4598c0940a34eb3ad9565a06565e`  
**新分支：** `research/g0.2-architecture-feasibility`  
**边界：** 不写代码，不改 G0/G0.1 文件，不新增 benchmark/demo，不进入 Gate 1，不声称完成形式化安全证明。  
**最终决策：** **HOLD**。

---

## 0. 结论先行

**HOLD：最小协议模型在结构上可行，但尚不能批准进入 Halo2 电路实现，也不能宣称已有独立密码学增量。**

本轮核查的六篇工作中：

- Jain & Prabhakar 2013 与 SIGMOD'18 已覆盖“ACL 约束下的查询结果验证”，但服务端可见 ACL 元数据或策略；
- QShield 已把 ACL 放入 enclave，并用硬件信任根提供执行轨迹证明，但查询明文可见、验证依赖 SGX；
- Vizard 已用 DPF 在两台非串通服务器间隐藏策略与匹配集，并给出概率式完整性检查与“可验证 MPC”扩展方向；
- TVA 已在诚实多数 MPC 中隐藏谓词值、时间区间和访问模式，恶意安全为 up-to-abort，但无 ACL 与公开第三方证明；
- Gu et al. 2026 已把查询类型、谓词、请求属性、聚合函数、策略版本、数据库状态标识绑定进查询摘要，并用 nonce/counter 与法定人数授权证书处理重放和准入；但其服务器仍是 honest-but-curious，且 QC₂ 被原文明确限定为 result-confirmation certificate，**不是** verifiable-computation proof。

因此，当前最值得继续检验的并不是“再加一层 ZK 查询证明”，而是一个更窄的问题：

> 能否在**没有任何单一 Prover 重构完整 D、ACL 和私密查询参数**的前提下，由多个计算方联合产生一个外部 Verifier 可独立检查的证明，证明：外部签发的 Agent Grant 对应到 MPC 内部实际使用的秘密共享查询；该查询满足当前策略版本；结果是指定数据快照上的正确且完整结果？

若这个问题最终只是调用现有 publicly verifiable MPC / distributed proving，再把 Grant digest、policy epoch、snapshot root 放进公共输入，则应按 **NO-GO** 结案。当前证据不足以证明它可归因于一个新构造，也不足以证明它不可能，所以本轮判 **HOLD**。

---

## 1. 精确系统模型与威胁模型

### 1.1 参与方

| 参与方 | 持有 / 职责 | 本轮明确假设 |
|---|---|---|
| Data Owner（DO / 多所有者集合） | 持有数据集 `D`、行级 / 字段级 ACL 策略 `P`；承诺快照 `root_t`；把 `D`、`P` 秘密共享给计算服务器 | 承诺时刻数据真实性由 DO 负责；本模型不证明外部世界真实值 |
| Authorization Authority（AA） | 持有签名私钥 `sk_AA`、策略版本登记 `policy_epoch`；签发 Agent Grant | AA 对签名与版本登记可信；默认不持有完整行级 ACL witness |
| Agent | 持有 Grant、purpose/context、查询描述 `Q_desc` 与私密谓词参数 | 可伪造上下文、扩大查询、跨查询/跨快照重放；不能伪造 AA 签名 |
| Compute Servers | 持有 `D`、`ACL`、`Q` 的秘密份额或 DPF key；执行 MPC / DPF 查询 | 见第 2 节两种模型，不得混用 |
| Verifier | 持有 Grant 摘要、`policy_epoch`、`snapshot_id`、`root`、结果承诺与证明 | 验证逻辑可信；当前版本与撤销状态来自可信状态锚点，否则 H2 无法闭合 |

### 1.2 Grant 结构

本轮按任务包给定结构建模：

```text
Grant = Sign_AA(
  subject, purpose, context_hash, tool_schema_hash,
  query_hash, policy_epoch, snapshot_id, expiry, nonce
)
```

`query_hash` 必须绑定规范化查询描述：

```text
Q_desc = (
  op_type, projection, predicate_template, private_param_commitment,
  aggregation, order_by, limit, policy_epoch, snapshot_id
)
query_hash = H(Q_desc || nonce)
```

**边界：** 若谓词参数取值空间很小，公开 `query_hash` 会遭受字典攻击；因此实现层需要考虑 hiding commitment `C_Q = Com(Q_desc; r_Q)` 与“承诺等于秘密共享输入”的 MPC 内相等性证明。仅把 `query_hash` 加进 Grant 不构成任何新密码学性质。

### 1.3 威胁边界

- Agent 可恶意构造或重放查询，但不能伪造 AA 签名，也不能破坏底层密码学可靠性。
- Compute Servers 的腐败能力按第 2 节分别定义。
- Verifier 是否被完全攻破不在范围内。
- 不证明数据源真实性（garbage-in-garbage-out）。
- 不证明基于查询结果的推断攻击不可行。
- 不由结果正确性自动推出“服务没有额外读取”。

---

## 2. 两种 MPC 计算模型（必须分开）

### 2.1 模型 A：两台非串通服务器，秘密共享 / DPF

参照：Vizard 的两服务器非合谋模型；DPF 编码策略，服务器评估 DPF key 并使用加法秘密共享 / S2PC。

| 维度 | 边界 |
|---|---|
| 隐私 | 最多一台服务器被攻陷时不泄露完整 ACL、数据值与匹配集；两台串通即可重构秘密，模型失效 |
| 查询可见性 | Vizard 中查询描述串 `σ` 作为 DPF.Eval 明文输入；因此“私密查询参数完全隐藏”不是该模型默认性质 |
| 恶意执行 | 朴素 DPF/S2PC 只适用于 semi-honest / lazy-but-honest；Vizard 的 ringer 是概率式完整性检查，恶意场景下 publicly verifiable MPC 仅为作者提出的扩展方向 |
| 掉线 / DoS | 通常导致 abort；Vizard 与多数两方协议不把 DoS 作为已解决性质 |
| 第三方公开验证 | 默认没有；需要额外 distributed proving 或 publicly verifiable MPC |
| 适用判定 | 可作为“隐藏策略 + 隐藏哪些 owner 被使用”的基线，但不能直接满足外部 Verifier 公开验证与恶意服务器正确性 |

### 2.2 模型 B：三台及以上服务器，恶意安全 MPC / honest-majority

参照：TVA 的 replicated secret sharing；TVA 明文给出 3PC semi-honest 与 4PC malicious（Fantastic Four）实例化。

| 维度 | 边界 |
|---|---|
| 隐私 | honest majority；精确阈值取决于协议。TVA 4PC 容忍一个恶意方；超过阈值串通会破坏隐私 / 正确性 |
| 查询可见性 | TVA 隐藏过滤谓词值与时间区间，但查询结构、窗口长度、schema、记录数等公开元数据仍可见 |
| 恶意执行 | MPC 恶意安全通常给出 up-to-abort：诚实方停止并报错；这不等于外部第三方可验证证明 |
| 掉线 / DoS | 可触发 abort 或 liveness 失败；需协议级投诉 / 追责机制，不是本报告已解决内容 |
| 第三方公开验证 | TVA 没有；需公开可验证 MPC 或联合 ZK 证明 |
| 适用判定 | 更适合“恶意服务器正确性”的内部保证，但仍缺 ACL/Agent 绑定与公开验证 |

**严禁混用：** Vizard 的两方非串通 + DPF 隐私，不等于 TVA 的 honest-majority malicious MPC 安全；TVA 的谓词隐藏，不等于 ACL 策略隐藏；MPC 内部正确性，不等于外部 Verifier 可验证性。

---

## 3. 信息可见性表

| 对象 | DO / PA | AA | Agent | 模型 A 单个服务器 | 模型 B 单个服务器 | Verifier |
|---|---|---|---|---|---|---|
| 完整数据集 `D` | 是 | 否 | 否 | 否（仅份额） | 否（仅份额） | 否 |
| 完整行级 ACL `P` | 是 | 默认否（可持 `policy_epoch` 承诺） | 否 | 否（DPF key 或份额） | 否（仅份额） | 否 |
| 查询结构（op / projection / limit） | 视部署 | 通过 `query_hash` 绑定，不保证见明文 | 是 | Vizard 中部分可见；TVA 类可公开 | 通常可见 | 仅摘要 / 承诺 |
| 私密谓词参数 | 否（除非兼任 Agent） | 否 | 是 | 否（秘密共享） | 否（秘密共享） | 否 |
| 匹配记录集合 / 访问模式 | 否（除非本地查询） | 否 | 可由结果推断 | Vizard 设计目标为隐藏 | TVA 数据无关执行隐藏 | 不直接可见 |
| 中间结果 | 否 | 否 | 否 | 否 | 否 | 否 |
| Grant 明文与 `query_hash` | 否 | 是 | 是 | 可验证签名 | 可验证签名 | 是 |
| 最终结果 `R` | 视部署 | 否 | 是 | 仅份额 / 密文 | 仅份额 / 指定揭示 | 结果承诺或揭示结果 |
| 公开可验证证明 | 不生成 | 不生成 | 不生成 | 需额外构造 | 需额外构造 | 是（目标） |

---

## 4. 最小协议消息流程

以下为**判定用伪流程**，不是已实现协议，也不构成形式化安全证明。

```text
Setup
  1. DO/PA commit(D) -> root_t；对 root_t 与 policy_epoch 签名。
  2. DO/PA secret-share D 与 ACL 给 Compute Servers；AA 发布当前 policy_epoch。
  3. Verifier 从可信状态锚点获得 (current_policy_epoch, current_root, revoked_set)。

Grant issuance
  4. Agent 构造 Q_desc 与随机数 r_Q，计算 query_hash / C_Q。
  5. AA 验证 subject/purpose/context/tool_schema 后签发 Grant。

Query submission
  6. Agent -> Compute Servers: Grant, C_Q, query_hash, shares(Q_desc), shares(private_params), nonce。
  7. Servers 验证 AA 签名、expiry、nonce 格式与 tool_schema_hash。

MPC / DPF binding
  8. Servers 在 MPC 内检查 C_Q / query_hash 与份额化查询输入一致。
  9. Servers 在 MPC 内用份额化 ACL 计算授权谓词，仅公开 auth_bit。
 10. 若 auth_bit=0，abort；否则继续。

Execution
 11. Servers 在指定 snapshot_id / root_t 上执行 oblivious query operator set。
 12. Servers 得到结果份额 R_shares 与结果承诺 d=H(R)。

Proof / verification
 13. 路径 P1：MPC 内部认证标签，仅参与方信服（up-to-abort）。
 14. 路径 P2：Servers 联合产生分布式证明 π_dist，外部 Verifier 检查：
       Verify(π_dist, Grant, h_q, policy_epoch, root_t, nonce, d)=1
 15. Verifier 检查 nonce 未用、policy_epoch/root_t 与当前状态一致，接受/拒绝。
```

**关键约束：** 路径 P2 中不允许某个 Prover 为生成 SNARK 而重构完整 `D`、`ACL`、`Q`。如果必须重构，则该方案违反 H1-S（ACL 对服务端保密）和私密查询参数目标，除非重构发生在明确可信的 DO / TEE 中，而这已经改变信任模型。

---

## 5. 授权凭证与秘密共享查询之间的绑定方式

拟议检查如下：

1. **签名有效**：Verifier 用 `pk_AA` 验 `Grant`，检查 subject / purpose / context_hash / tool_schema_hash。
2. **实际 MPC 查询输入对应 `query_hash`**：Servers 在 MPC 内由 `shares(Q_desc)` 重算 `C_Q` / `H(Q_desc||nonce)`，与 Grant 中的 `query_hash` 做相等性检查。若查询空间低熵，必须用 hiding commitment + 相等性证明，避免公开哈希字典攻击。
3. **查询满足相应策略版本**：ACL 以秘密共享或 DPF key 形式存在；MPC 内计算 `Adm_π(Q, ACL)`，只公开 `auth_bit`，并绑定 Grant 中的 `policy_epoch`。
4. **结果等于指定快照上的查询结果**：oblivious operator set 在 `snapshot_id/root_t` 上执行，输出 `R_shares` 与 `d=H(R)`。
5. **正确性与完整性**：正确性指返回行满足查询；完整性指没有遗漏满足查询且被授权的行。二者需由 operator 结构与证明语句共同约束，不能由 `query_hash` 推出。
6. **不可跨查询 / 跨快照 / 跨策略重放**：`nonce`、本地 counter、签名上下文 `AUTH||qid||H(q)`、Verifier 侧 nonce 集合与当前 `policy_epoch/root_t` 共同检查；这一部分与 Gu 2026 接近。

**谁持有什么：**

- `D`：DO 原始持有；计算服务器持份额；任何单个服务器不应重构全量明文。
- `ACL`：DO/PA 原始持有；计算服务器持份额或 DPF key；AA 默认只签 `policy_epoch`。
- 查询参数：Agent 原始持有；计算服务器持份额；Verifier 只见承诺 / 摘要。
- 证明生成者：必须是 servers 联合 prover 或明确可信的 DO/TEE prover；不能默认“某个 server 拿全部 witness 跑 SNARK”。

---

## 6. 五项性质的分别判定

| 性质 | 模型 A（两服务器 DPF / SS） | 模型 B（honest-majority MPC） | 判定 |
|---|---|---|---|
| **1. 查询结果正确性** | 若 DPF key 正确且服务器按协议执行，可内部成立；恶意偏离需概率 ringer 或未实现的 verifiable MPC | 恶意 MPC 可在参与者内部给出 up-to-abort 正确性 | **内部条件成立；外部公开验证未证** |
| **2. 结果完整性（无遗漏）** | Vizard ringer 是概率式，不是通用 completeness proof；DPF dummy 填充隐藏匹配集但不能证明无遗漏 | TVA 的 oblivious operators 可避免中间结果泄露，但没有第三方 completeness proof；SIGMOD'18 的 completeness 依赖 SP 可见 ACL | **条件成立；公开可验证构造未证** |
| **3. 授权正确性** | 策略编译进 DPF key，可隐藏策略；外部 Grant 到秘密查询的绑定需 commitment-equality | 份额化 ACL 可在 MPC 内评估；同样需 commitment-equality | **结构上可做，但主要是标准组件组合；低熵 query_hash 泄露需处理** |
| **4. 实际访问约束（无额外读取）** | 若所有操作都在 DPF/MPC 内且不暴露访问模式，服务器不观察匹配集；若服务器在协议外访问外包存储，结果证明无法发现 | 数据无关执行隐藏访问模式；但外部 Verifier 无法从结果证明推出服务器没有做协议外读取 | **不由前三项推出；必须先定义架构边界** |
| **5. 数据新鲜性** | 需要 DO 签名的 `snapshot_id/root_t` 与当前状态锚点；nonce/counter 防重放 | 同左 | **可由可信状态锚点 + 版本/撤销 checks 实现；若状态锚点不可信则未闭合** |

### 6.1 三个不同的“正确性”不得混同

- **MPC 协议内部恶意安全**：保证参与者之间在阈值内计算正确，通常 up-to-abort。
- **多方协议输出正确性**：输出份额重构后与函数值一致；仍可能只对参与者成立。
- **外部 Verifier 公开可验证证明**：第三方无需参与 MPC 即可检查正确/完整结果。本报告认为这是目前最关键的未证环节。

---

## 7. 与六篇指定工作的逐项比较

| 工作 | 实际实现 / 证明的性质 | 明确假设 | 作者提出但未实现 / 限制 | 与候选协议的重叠与缺口 |
|---|---|---|---|---|
| Jain & Prabhakar 2013（DBSec，全文） | MHT/MB-tree + access bitmap 验证查询结果正确性与完整性；key regression 做懒撤销 | 不可信 DB，通常至少 semi-honest；无硬件 | MB-tree 作为 B+ index 内部维护列为 future work | 重叠：ACL 约束下正确性/完整性。缺口：ACL bitmap、规则、user id、range 边界对服务端可见；无 Agent Grant、无第三方公开验证 |
| Xu et al. SIGMOD'18（全文） | APP 签名 + ABS + CP-ABE + ADS；用户侧 soundness/completeness + Zero-Knowledge | SP 不完全可信但可见 `Υ_i`；用户好奇；SP 与用户不合谋 | aggregation、multi-source distributed 为 future work；无 Agent/版本/撤销/独立 V | 重叠：行级 ACL 下结果完整性。缺口：SP 明文使用 `Υ_i` 构造 VO，不覆盖 ACL 对服务端隐藏 |
| Chen et al. QShield TPDS 2021（终稿正文 BLOCKED；以同团队 arXiv v1 作技术来源，差异 UNKNOWN） | SGX enclave 内检查 ACL；AES-GCM + 双线性对秘密共享；签名 trust proof；4 个查询算子 | SGX/attestation/DBDH；用户与云不合谋、DoS、物理攻击除外 | range/order 仅理论扩展；coarse-grained ACL；分布式 broker/worker 为扩展未实现 | 重叠：策略在 enclave 内对 host 隐藏，执行轨迹签名。缺口：查询表达式明文可见；验证依赖硬件信任根，不是无硬件公开 ZK；无 Agent Grant |
| Vizard CCS 2022（ePrint 全文直下 BLOCKED；基于原文全文索引片段，PARTIAL） | DPF 隐藏策略与哪些 owner 被使用；两服务器非串通；ringer 概率式完整性；RRC release policy | 最多攻陷一台服务器；owners 诚实；RRC 2/3 honest；服务器为 lazy-but-honest / rational | publicly verifiable MPC 仅为恶意场景扩展方向，未声明实现；提交阶段元数据不隐藏；查询描述串 `σ` 明文 | 重叠：隐藏 ACL/策略与匹配集。缺口：无 Agent 凭证；查询描述可见；公开可验证与完整无遗漏证明未建立 |
| TVA USENIX Security 2023（全文） | replicated secret sharing；oblivious filter/group-by/window；隐藏谓词值、时间区间、时间戳；恶意设置 up-to-abort | honest majority、非串通计算方、认证网络；查询结构公开；不防结果推断 | DP、相似度查询、FSS 窗口扩展为 future work；无 ACL | 重叠：私密查询参数 + MPC 内部正确性 + 隐藏访问模式。缺口：无 ACL/策略隐藏、无 Agent Grant、无外部公开证明 |
| Gu et al. 2026（Springer 开放全文） | `H(q)` 绑定 type/predicate/requested attributes/aggregation/policy version/DB state id；`qid=H(pk_i||ctr_i||r_i||H(q))`；2N/3 quorum 授权证书；QC1/QC2 | malicious owners `f<N/3`；servers honest-but-curious、non-colluding；静态腐败；DoS 除外 | QC₂ 明确不是 verifiable-computation proof；无公开执行证明；无 access pattern / extra reads 机制；cross-field、FK、多属性谓词、记录级策略未直接支持 | 重叠：查询摘要/版本/快照/nonce/法定准入，最接近 H2。缺口：服务器诚实假设过强；QC₂ 只确认结果摘要一致性；无 Agent、无恶意服务器公开正确性证明 |

**来源状态声明：** Jain2013、SIGMOD'18、TVA、Gu2026 为全文可核验；QShield 的 TPDS 终稿正文被拦截，只以同团队公开预印本提取技术细节，终稿差异标 UNKNOWN；Vizard ePrint PDF 直下被 Cloudflare 拦截，结论基于原文全文索引片段，标 PARTIAL，未用二手博客替代原文。

---

## 8. 哪些内容只是现有组件的直接组合

下列内容单独看都不是本轮可主张的新构造：

1. **Grant 签名 + query_hash / context_hash / policy_epoch / snapshot_id 绑定**：标准签名与承诺/哈希字段绑定；Gu 2026 已覆盖更强的多字段摘要与 quorum 准入。
2. **DPF / 秘密共享隐藏 ACL 或谓词**：Vizard 与 TVA 已分别给出策略隐藏与谓词值隐藏。
3. **秘密共享上的 oblivious query execution**：TVA 已实现多类数据无关算子。
4. **nonce / counter / 授权证书防重放**：Gu 2026 已给出接近构造。
5. **查询结果 soundness/completeness**：SIGMOD'18 已有不同信任模型下的方案；ZK SQL 系统提供查询侧证明。
6. **TEE 内 ACL + 执行轨迹证明**：QShield 已有，但信任根是 SGX。
7. **把上述证明交给外部 Verifier 检查**：若 Verifier 只验签名、版本、哈希相等性与标准 zk/SNARK 证明，仍是常规组合。

因此，不能把“Agent 授权 + Vizard 式策略隐藏 + TVA 式 MPC + Gu 式查询摘要”打包成新密码学贡献。

---

## 9. 真正需要新构造的技术环节（若存在）

当前只有一个环节可能构成非平凡技术核心：

### T1. 秘密共享 witness 上的分布式公开可验证证明

目标语句可写为：

```text
Statement:
  public: pk_AA, Grant, h_q, policy_epoch, root_t, nonce, d
  witness: shares(D), shares(ACL), shares(Q_desc), shares(private_params), randomness

Proves:
  VerifySig(pk_AA, Grant)=1
  ∧ Grant.query_hash = h_q
  ∧ committed_shared_query(Q_desc) = h_q
  ∧ Adm_policy_epoch(ACL, Q_desc)=1
  ∧ snapshot_commit(D)=root_t
  ∧ R = Eval(Q_desc, D)
  ∧ Completeness(Q_desc, ACL, D, R)=1
  ∧ d = H(R)
```

**必须同时满足：**

- 没有任何单个 Prover 重构完整 `D`、`ACL` 或 `Q_desc`；
- Verifier 不需要参与 MPC；
- 证明不仅覆盖最终结果，还覆盖授权谓词、版本、快照与完整性；
- 恶意服务器偏离协议时，要么被公开证明拒绝，要么产生可追责 abort；
- 低熵查询参数不能因公开 `query_hash` 被字典攻击恢复。

若该能力可由现有 publicly verifiable MPC / distributed proving 直接实例化，并通过工程参数证明可用，则它只是组件选择与组合，应判 **NO-GO**。若现有公开可验证 MPC 无法在不重构 witness 的前提下支持上述承诺一致性、ACL 谓词与完整性语句，而需要新的承诺格式、联合证明协议或新的安全定义，才构成 GO 候选。

### T2. 实际访问约束的协议语义

如果所有查询操作都在数据无关 MPC 内完成，服务器看不到访问模式；如果服务器仍持有可自行访问的外包存储，则结果证明无法证明它没有额外读取。必须先固定架构语义，否则“没有额外读取”是无法判定的口号。这是**模型定义问题**，本身不是新原语；模型定义错误会使任何 GO 声明失效。

---

## 10. 最终决策

# **HOLD**

**理由：**

- **不是 GO_TO_GATE1**：没有给出一个已完成、可检验、且明确不属于现有组件组合的协议构造；关键证明机制 T1 与证明者信任边界尚未确定。
- **不是 NO_GO（尚不）**：T1 仍是一个具体、可判定的技术问题；现有六篇工作均未同时给出“Agent Grant 绑定 + ACL/查询参数秘密共享 + 外部公开可验证正确/完整结果 + 无单方重构 witness”的完整构造。也不能把 HOLD 当成“方向必然可行”。
- **停止条件**：本轮到此结束，不再追加修订轮次，不进入 Gate 1，不实现 Halo2 电路，不新建 benchmark/demo。

**若后续允许一次有界判定，唯一应被追问的问题是：**

> 现有 publicly verifiable MPC / distributed proving 是否已经能在不重构秘密共享 witness 的条件下证明 T1 的完整语句？  
> 若答案是“是”，判 NO_GO；若答案是“否且能指出具体缺口并给出新构造”，才具备 GO 条件。

---

## 11. 来源证据索引

证据标签：`[全文]` = 原文可核验；`[PARTIAL]` = 仅部分原文 / 受限获取；`[推论]` = 本轮基于原文的分析，不是作者声称。

1. Jain & Prabhakar, *Access Control and Query Verification for Untrusted Databases*, DBSec 2013, LNCS 7964, pp.211–225, DOI `10.1007/978-3-642-39256-6_14`。[全文]  
   - 作者公开 PDF：`https://www.cs.purdue.edu/homes/sunil/pub/dbsec13.pdf`  
   - 关键定位：§3.1 系统模型；§3.2 MHT/MB-tree；§4.1 access bitmap；§4.2 key regression / bucketization；§5 Table 4。

2. Xu et al., *When Query Authentication Meets Fine-Grained Access Control: A Zero-Knowledge Approach*, SIGMOD'18, DOI `10.1145/3183713.3183741`。[全文]  
   - 作者主页 PDF：`https://xuc.me/file/paper/SIGMOD18.pdf`  
   - 关键定位：§3 Problem Definition / Threat Model；Algorithm 1；Definition 7.4/7.5；Theorem 7.6；§11 Conclusion。

3. Chen et al., *QShield: Protecting Outsourced Cloud Data Queries with Multi-User Access Control Based on SGX*, IEEE TPDS 32(2):485–499, 2021, DOI `10.1109/TPDS.2020.3024880`。[元数据全文 / 技术部分 PARTIAL]  
   - Aaltodoc / IEEE 终稿正文被反爬或付费墙拦截；同团队公开预印本 arXiv:1912.08454v1 用于机制核对，终稿差异 UNKNOWN。  
   - 关键定位（预印本）：§III-A 系统与查询可见性；§IV-A/B enclave/policy/token/trust proof；§VI 正确性定义、算子与 ACL 限制。

4. Cai, Zang, Wang, Jia, Wang, *Vizard: A Metadata-hiding Data Analytic System with End-to-End Policy Controls*, ACM CCS 2022, DOI `10.1145/3548606.3559349`；ePrint 2022/1115。[PARTIAL：ePrint PDF 直下被 Cloudflare 拦截，使用原文全文索引片段]  
   - URL：`https://eprint.iacr.org/2022/1115`  
   - 关键定位：§1.1 DPF/SHSE；§2.1–2.3 参与方与威胁模型；§4 DPF policy control；§5.1–5.2 release policy / ringer / verifiable MPC 扩展。

5. Faisal et al., *TVA: A Multi-party Computation System for Secure and Expressive Time Series Analytics*, USENIX Security 2023, pp.5395–5412。[全文]  
   - 官方 PDF：`https://www.usenix.org/system/files/usenixsecurity23-faisal.pdf`  
   - 关键定位：§2 元数据与查询可见性；§3 replicated secret sharing / 威胁模型 / up-to-abort；§4 oblivious operators；§7 future work。

6. Gu, Li, Shi, *Verifiable and robust query processing for multi-owner secret-shared databases under malicious owners*, Cybersecurity 9(1):231, 2026, DOI `10.1186/s42400-026-00674-4`。[全文]  
   - URL：`https://link.springer.com/article/10.1186/s42400-026-00674-4`  
   - 关键原文：  
     - "The query digest *H*(*q*) covers the query type, predicate, requested attributes, aggregation function, policy version, and the identifier of the outsourced database state."  
     - "Outsourced servers store secret-shared data and execute set and aggregation computations under an honest-but-curious model."  
     - "A valid authorization quorum is a signer set ... |S|≥Q=⌈2N/3⌉ ..."  
     - "*QC₂* is a result-confirmation certificate rather than a verifiable-computation proof."  
     - "the correctness of server-side execution is not established by *QC₂*."  
   - 关键定位：System and threat model；Security objectives；Adaptive Query Consensus；Query execution workflow / Scope of QC₂；Conclusion。

**边界复述：** 本报告给出的是协议可行性与增量判定，不是形式化安全证明；没有实现电路、没有运行实验、没有声称 T1 已被解决。
