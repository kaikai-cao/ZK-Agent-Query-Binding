# RELATED_WORK_MATRIX.md — 相关工作逐维对比矩阵

**任务：** ZKQ-00-G0 + ZKQ-00-G0.1（有限文档校正：ACL 保密对象与查询覆盖范围）
**日期：** 2026-11-25
**G0.1 校正说明：** 原矩阵的 "Private ACL = YES（SIGMOD'18）" 口径过宽，已被拆为 "对 Agent / Verifier 隐藏" 与 "对 Query Service / Prover 隐藏"；H1 / H3 不再用一句"已覆盖"概括。
**判定口径：**
- `YES`：有原文 + 代码证据；
- `PARTIAL`：只实现部分 / 仅形式化 / 仅摘要支持；
- `NO`：核实后确认没有；
- `UNKNOWN`：现有资料无法判断（**绝不因 README 没提就填 NO**）。

**重要纪律：** "论文声称"与"源码实测"分开记在单元格内，格式为 `结论(依据)`。

---

## 1. 主矩阵

| 维度 | CVA (2607.21325 v3 + code e998285) | TruthTable (2026/1260 + code a214267) | PoneglyphDB (2411.15031 + code a8eaf24) | ZkChainDB (DOI ...11575456, **仅摘要**) | SIGMOD'18 Xu et al. (全文) | 旧 MVP (proxy e327a94) |
|---|---|---|---|---|---|---|
| **Authorization Binding** | PARTIAL（论文 §4；PoC 仅 plan-level SHA256，且电路外计算） | NO（源码 agent/authorization/grant/principal 命中均 0） | NO（源码四词命中均 0） | UNKNOWN（摘要 "approved SQL query templates"，正文 BLOCKED） | NO（无独立授权请求证明；访问策略绑定在记录上） | YES（Ed25519 SignedGrant 绑定请求/上下文/策略/工具/schema/nonce，R1） |
| **Agent / Principal Binding** | YES（电路 Poseidon(sk,ρ)=id；论文 §5 + circom:27-31） | NO（源码 agent/principal 命中 0） | NO（源码 0） | UNKNOWN（摘要无 agent 主体概念） | NO（是 user + role set，非 Agent 授权主体） | PARTIAL（agent_id 在 Grant 与请求校验中；无 ZK，R1） |
| **Context Binding** | NO（论文 Table 2 "Open / No explicit context commitment"；PoC 无 context 信号） | NO | NO | UNKNOWN | NO | YES（context_hash 覆盖 session/task/tenant，快照重建，R1） |
| **Policy Binding** | PARTIAL（论文 §5.3 "Partial / no explicit pid_j public input"；PoC 策略硬编码、属性自报） | NO | NO | UNKNOWN（"approved templates"是否=策略，正文未知） | PARTIAL（每条记录带访问策略 Υ_i，单调 DNF，由 DO 签名；无策略版本/授权请求绑定） | YES（policy_hash + 版本，Issuer/Gateway 双点复核，R1） |
| **Dataset Commitment** | NO（CVA 无数据库概念） | YES（table oracle + polynomial commitment；README 的 `.oracle` 产物 + crates/tt-arithmetic/table_oracle.rs） | PARTIAL（论文 §3.2 IPA 承诺；源码 `data/database_commitment.rs` 孤立、**未**在 `lib.rs`/`data.rs` 声明为 mod） | PARTIAL（摘要 "committed dataset state"，正文 BLOCKED → 机制 UNKNOWN） | YES（ADS 签名 + APP 签名，每记录签名，§3/§5） | NO（mock 内存记录，无 DB 承诺） |
| **Query Binding** | PARTIAL（PoC plan_hash=SHA256(op\|res\|change_id) 电路外算后直通公共输出；非完整 query） | YES（README §5 "Use the exact same query"；verify CLI 强制 --query） | PARTIAL（查询逐条硬编码进电路 `src/sql/q*_final_*.rs`，无公开查询声明，公开输入恒 `[1]`） | PARTIAL（摘要 "approved SQL query templates"，绑定机制 UNKNOWN） | YES（equality/range/join query 在 VO 验证中绑定，§3/§5/§6） | NO（绑定的是 ToolCall args fields/where/limit，非 SQL query） |
| **Query Correctness** | NO | YES（摘要 + README + tt-core 算子 gadget 的 prove/verify） | PARTIAL（门约束存在 `q1_final_v4.rs:110-255`；但无输出/承诺绑定，验证者无法据公开输入确认） | PARTIAL（摘要声称，正文 BLOCKED） | YES（Definition 7.4 Soundness + Theorem 7.6） | NO（返回行由 mock 工具自报，自签回执，R1） |
| **Result Completeness** | NO | YES（证明系统对查询结果一致性；README verify 同时校验 result-path） | NO〔推论 C3〕（`q1_final_v4.rs:409-411` selector 由 witness 侧决定，无门绑定 check） | UNKNOWN（摘要 "verify result consistency"，是否含无遗漏未明） | YES（Definition 7.4 明确 "not in RS ... satisfies query and Υ(A)=1" 即失败） | NO |
| **ACL Enforcement** | NO（电路 clearance/env/action 硬编码谓词，非行级 ACL） | NO（源码无 ACL 语义；"acl"命中为 Oracle/local 子串误匹配） | NO（论文 §3.2 明确 ACL 是电路外预处理；源码 0 匹配） | UNKNOWN | YES（行级 Υ_i 单调 DNF，CP-ABE + APP 签名加密强制，§3/§5） | PARTIAL（字段白名单/强制过滤/行限，工具层而非 DB 行级 ACL，R1） |
| **Private ACL（H1-U：对 Agent / 查询用户 / 合并 V）** | NO | NO | NO | UNKNOWN | PARTIAL→YES（§3/§7.5 对**不可访问记录**：用户不能得知 size/access policy；对可访问记录 VO 返回 `Υ`；未定义独立 V） | NO |
| **Private ACL（H1-S：对 Query Service / Prover）** | NO | NO | NO | UNKNOWN | **NO（原文相反）**：§3/Algorithm 1 明示记录 `⟨o_i,v_i,Υ_i,σ_i⟩` 外包给 SP，VO 构造按 `Υ_oq(A)=1` 分支 | NO |
| **Field Projection Integrity** | NO | PARTIAL（源码有 projection 算子；无 ACL 语义） | PARTIAL（论文声称，源码弱于论文） | PARTIAL（摘要 "projection"，正文 BLOCKED） | NO（论文只核验 equality/range/join，未给独立投影完整性定义） | PARTIAL（字段白名单，工具层） |
| **LIMIT / Sorting Integrity** | NO | PARTIAL（源码有 limit/sort 算子；无 ACL 绑定） | PARTIAL/UNKNOWN（源码显著弱于论文） | PARTIAL（摘要 "sorting, Top-K"，正文 BLOCKED） | NO | PARTIAL（行限 / args 校验，工具层） |
| **Aggregation Integrity** | NO | PARTIAL（源码有 aggregate 算子；论文正文 PARTIAL） | PARTIAL/UNKNOWN（源码未给出可用证据） | PARTIAL（摘要 "group-by aggregation"，正文 BLOCKED） | **NO（§11 aggregation 列为 future work）** | NO |
| **Freshness / Revocation** | PARTIAL（nonce/t 在 PoC 公共输入，replay 由 gateway 外部执行；无撤销列表） | NO | NO/UNKNOWN（论文仅把 Merkle 更新列未来方向，无实现） | UNKNOWN | NO（全文 update/revocation 命中 0） | PARTIAL（nonce 原子消费 + expiry；无撤销列表，单进程内存，R1） |
| **Output Binding** | PARTIAL（receipt/output_hash 绑定；E2.2 证明可被合法密钥虚假声明） | YES（result-path 在 verify 中强制校验） | NO（`public_input=[1]`，exposed cell 恒 `F::from(1)`，q1 未 expose） | PARTIAL（摘要，正文未知） | YES（VO 中结果集与签名绑定） | PARTIAL（output_hash 由 Adapter 自签，E2.2 虚假声明反例 R2） |
| **Runtime Execution Evidence** | NO（§4.5 + Table 2 "Open / No trusted execution evidence"） | NO | NO | UNKNOWN | NO（VO 证明结果正确，不证明 SP 实际读取行为） | PARTIAL（E2.1 探针可检测偏离，E2.2 自签虚假回执绕过，DR=0，R2） |
| **ZK Proof System** | Groth16 over bn128, Circom/snarkjs（PoC） | 多项式承诺 + sumcheck/PIOP（arkworks 风格，tt-arithmetic/tt-core）；**非** Halo2 | PLONKish + Halo2 + 递归组合（Cargo.toml + src/chips/） | zk-SNARK（摘要；具体系统 UNKNOWN） | ABS + CP-ABE + APP 签名 + ADS（非通用 ZK SQL 电路） | Ed25519 签名 + 有限 Halo2 配额电路（zk-v2-host），主体路径非 ZK |
| **Implementation Evidence** | 论文声称 8 项性质；**源码实测弱于声称**（无 SHA256 电路约束、无 pid_j、无 context、策略硬编码、属性自报、gateway 返回硬编码 action） | 论文声称 TPC-H 17/22、55s/32ms/24kB；源码实测算子齐全、verify 强制同 query；无授权语义（源码 0 命中） | **源码实测显著弱于论文**：承诺文件未接入电路、公开输入恒 `[1]`、递归未实现、查询逐条硬编码；论文 §3.2 自述 ACL 在电路外。无授权语义（源码 0 命中） | 仅摘要，正文 BLOCKED；源码无官方公开地址（任务包未给） | 论文与 16 页 PDF 正文完整核验；Definition 7.4/7.5 + Theorem 7.6；无代码仓库核验（本轮未找到官方代码） | 源码 R1 + 冻结实验 R2；README 自述边界与源码一致 |

**补充系统 — nulltea/zk-SQL（code `4c3626d`）：** 具备 `prove_table/commitment + query + result` 三元组公共输入绑定（合约 `ZKPQueryVerifier.sol:51-70`，链上按 hash 比较承诺/结果）、输入/输出承诺哈希链（`scalar_hash_pair.sol`）、教学性 range 电路；但**无 Agent / 授权 / ACL / 策略 / principal 语义**，README 明言 "does not currently restrict which address may query the contract"（任何地址可查），定位为教学 demo（最后提交 2022-07-28）。它说明"承诺+查询+结果"绑定本身是已知且常规的机制，不构成的新增量。

---

## 2. 三项最重要对比（任务包验收项 5）

| 排序 | 工作 | 与候选目标的关系 |
|---|---|---|
| **1** | **SIGMOD'18 Xu et al.**（全文核验） | **覆盖 H1-U，不覆盖 H1-S**：同一篇里同时实现"行级细粒度 ACL（DNF 单调策略）+查询结果 soundness & completeness + 对查询用户的零知识机密性（不泄露不可访问记录的存在/数量/策略）"。因此"对 Agent / 用户隐藏 ACL"的朴素版本已有强先例；但 SP 明确接收并使用 `Υ_i`，所以不能据此宣称"对不可信查询服务隐藏 ACL 同时验证结果完整性"已被覆盖。差别：无 Agent 授权请求绑定、无策略版本/撤销、无执行时证据、无独立 `V` 模型。 |
| **2** | **TruthTable**（全文摘要 + 源码） | **最接近且直接覆盖 B**：验证者指定 Query、强制同 query 验证、17/22 TPC-H、算子齐全；源码零授权语义。候选"把 Grant 的 query_hash 绑到 TruthTable 的 Query 输入"是**常规组合**（公共输入相等性），不是新密码学约束。 |
| **3** | **CVA**（全文 + 源码） | **授权侧基线，且作者自己划界**：授权绑定 ≠ 执行绑定（§4.5），context binding / runtime execution binding 在 PoC 中 Open；PoC 源码比论文自述更弱。候选不能靠"接上 CVA"获得查询结果保证。 |

**并列提及**：PoneglyphDB（Halo2 SQL 证明，源码零授权语义 → "用 Halo2"不是增量）；ZkChainDB（approved templates 但正文 BLOCKED → 无法判定是否已覆盖授权模板绑定，标 UNKNOWN）。

---

## 3. H1 / H2 / H3 逐项对照结论

| 缺口 | 现有工作是否已覆盖 | 依据 |
|---|---|---|
| **H1-U** ACL 隐藏于 Agent / 查询用户（及合并 V）下的结果完整性 | **已覆盖（限 equality/range/join 与不可访问记录）** | SIGMOD'18 §3 威胁模型 + Def 7.4 + Def 7.5 + Theorem 7.6；对可访问记录 VO 会返回 `Υ`，未定义独立 V |
| **H1-S** ACL 隐藏于 Query Service / Prover 下的结果完整性 | **未覆盖；架构未闭合** | SIGMOD'18 原文相反：SP 接收 `⟨o_i,v_i,Υ_i,σ_i⟩` 并使用 `Υ_oq(A)` 构造 VO。若 `S` 不可见 ACL，谁持 witness、谁生成证明尚未确定 |
| **H2** 策略版本 / 快照联合一致性 + 撤销 | **部分覆盖，仍有缺口** | CVA §6 Gap 3 形式化 TOCTOU 但未实现；SIGMOD'18 全文无 update/revocation；ZkChainDB 正文 BLOCKED 无法判定；但可用业务层版本比较 + 撤销表解决，无新密码学约束 |
| **H3** 授权约束查询的输出完整性 | **按算子拆分后 PARTIAL，不可概括为"任意 SQL 已覆盖"** | SIGMOD'18 支持 equality/range/join，aggregation 为 future work；TruthTable / PoneglyphDB / ZkChainDB 的 Query Correctness 不自动等同私有 ACL 强制，投影 / LIMIT / 排序 / 聚合需逐项标注 |

---

## 4. 本矩阵的证据限制

1. ZkChainDB 正文付费墙 BLOCKED → 该列多数格为 `UNKNOWN`，**不得**据此判定其"没有"某性质；也不得仅凭摘要判"有"。
2. CVA 代码 HEAD（`e998285`，08-24）早于论文 v3（09-24）约一个月 → 源码弱于论文自述的部分，标注为"版本错位，是否存在后续电路 UNKNOWN"，不武断认定作者自述错误。
3. SIGMOD'18 未找到官方代码仓库（本轮有限搜索）→ 其实现证据限于论文正文（16 页 PDF + 安全定义与定理），Implementation Evidence 列不填 YES。
4. TruthTable 中 `acl` 字符串命中为 `TrackedOracle`/`local` 等子串误匹配，非真实 ACL 语义——已按源码上下文人工确认，避免误判。

---

## 5. G0.1 拆分后的 H1 / H3 覆盖矩阵

> **纪律：** `YES` 只表示该性质在该来源的已核验范围内成立，不等于整个候选目标已覆盖。尤其不得把 Query Correctness 自动翻译成 Private ACL Enforcement。

| 性质 | SIGMOD'18 Xu et al. | TruthTable | PoneglyphDB | ZkChainDB（仅摘要） | CVA | G0.1 结论 |
|---|---|---|---|---|---|---|
| **ACL 隐藏于 Agent / 查询用户 / 合并 V** | PARTIAL→YES：§3/§7.5 对不可访问记录隐藏内容与策略；可访问记录 VO 含 `Υ`；无独立 V | NO（源码 ACL 语义 0） | NO（论文 §3.2 ACL 在电路外） | UNKNOWN（摘要无 ACL 语义） | PARTIAL（属性隐私，不是行级 ACL 隐藏） | H1-U 在 SIGMOD 场景有强先例，不能原样宣称新增量 |
| **ACL 隐藏于 Query Service / Prover** | **NO**：SP 接收并使用 `Υ_i`；Algorithm 1 明示外包记录含 `Υ_i` | NO | NO | UNKNOWN | NO | H1-S 是模型分叉；当前无可执行架构证据 |
| **行级授权结果 soundness** | YES（Def 7.4：结果不得含不满足 query 或 `Υ(A)=0` 的记录） | NO（无授权语义） | NO（源码无授权语义） | UNKNOWN | NO（授权层无 DB 行集合） | H1-U 侧已覆盖；H1-S 侧未覆盖 |
| **行级授权结果 completeness** | YES（Def 7.4：满足 query 且 `Υ(A)=1` 的遗漏记录使验证失败） | NO（查询完整性有，授权行集合无） | NO（源码完整性弱于论文） | UNKNOWN | NO | 同上 |
| **Query correctness（相对指定 query 与承诺 DB）** | YES，但限 equality / range / join | YES（摘要 + 源码 query 结构性绑定） | PARTIAL（源码显著弱于论文） | PARTIAL（摘要声称，正文 BLOCKED） | NO（CVA 明确无查询结果保证） | 常规组件已有，不构成新增量 |
| **Field projection integrity** | NO / UNKNOWN（论文未给独立投影完整性定义） | PARTIAL（源码有 projection 算子；无 ACL 语义） | PARTIAL/UNKNOWN | PARTIAL（摘要 "projection"） | NO | 必须按系统逐项标注，不能归入"任意 SQL 已覆盖" |
| **LIMIT / sorting integrity** | NO / UNKNOWN | PARTIAL（源码有 limit/sort 算子） | PARTIAL/UNKNOWN | PARTIAL（摘要 "sorting, Top-K"） | NO | 同上 |
| **Aggregation integrity** | **NO（§11 列为 future work）** | PARTIAL（源码有 aggregate 算子；正文 PARTIAL） | PARTIAL/UNKNOWN | PARTIAL（摘要 "group-by aggregation"） | NO | SIGMOD'18 不得被写成覆盖 aggregation |

**总体校正：** 原 `Private ACL = YES` 只能保留为 **H1-U = YES（且限 equality/range/join 的不可访问记录场景）**。当前 `SECURITY_MODEL.md` 若要求 ACL 对 `S` 不可见，则研究目标已变为 **H1-S / H1-Both**；这不是 SIGMOD'18 所覆盖的问题，但也不能直接判 GO，因为"S 不知 ACL 时谁持有 witness、谁生成完整性证明"尚未闭合。
