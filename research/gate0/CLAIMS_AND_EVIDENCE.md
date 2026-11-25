# CLAIMS_AND_EVIDENCE.md — 结论与证据分级

**任务：** ZKQ-00-G0（Gate 0，只读研究审计）
**日期：** 2026-11-25
**纪律：** 论文作者自述、源码静态事实、实验可验证事实、我方推论、未核实假设——五类严格分开，不得混用。英文引号内为原文直接引用。

---

## 0. 证据分级约定

| 等级 | 含义 |
|---|---|
| **[原文]** | 论文正文直接陈述，附章节 / 定义号与英文原文 |
| **[源码]** | 官方代码可静态核验的事实，附文件路径与行号（R1） |
| **[实验]** | 已冻结的实验结果（R2/R3），附出处 |
| **[推论]** | 我方基于上述证据的推断，**不是**作者声称，也不等于已证事实 |
| **[未核实]** | 无法从现有证据确认，标 UNKNOWN / BLOCKED |

---

## 1. CVA（arXiv:2607.21325 v3）

### 1.1 [原文] 形式化模型已绑定的维度
- §3–§4：请求 `q_i` 形式化为 `(id_i, α, res, c, pid_j, n, t)`；候选性质含 authorization soundness、principal binding、request binding、policy binding、replay resistance、attribute privacy。
- 但**形式化模型 ≠ 已实现功能**（见 1.3）。

### 1.2 [原文] 授权绑定不等于执行绑定（决定性引用）
> §4.5: "VerifyAuth(pp,xq,π)=1 ⇏ qexec=qauth where qauth denotes the request committed in the verified statement xq, and qexec denotes the request actually executed by the runtime. Therefore, Authorization Request Binding ≢ Runtime Execution Binding."

> §4.5: "A ZK circuit is evaluated at proof generation time over a committed representation of the intended request; it has no access to the runtime state at execution time and cannot constrain what the agent subsequently does with the authorization it receives. Closing this gap requires a trust anchor that operates at execution time rather than at proof generation time ... such as remote attestation, a trusted execution environment, or verifiable execution receipts ... This constitutes an open problem."

### 1.3 [原文] PoC 实际实现边界（§5.2 + §5.3 Table 2）
- 公共声明 `x_PoC = (id_i, h_plan, n, t)`；私有 witness `w_PoC = (sk_i, ρ_i, attrs_i, plan)`。
- [原文] "R_PoC = BindPrincipal_Poseidon ∧ BindPlan_SHA256 ∧ SatisfyPolicy_Circuit, with replay resistance enforced externally by the gateway"。
- [原文] Table 2 逐项状态：Authorization soundness **Partial**；Principal binding **Implemented**；Request binding **Implemented for plan-level binding; partial relative to full CVA request binding**；Policy binding **Partial / not fully implemented**（"no explicit `pid_j` public input in the current prototype"）；Replay resistance **Implemented externally**；Attribute privacy **Implemented under proof-system assumptions**；Context binding **Open**（"No explicit context commitment"）；Runtime execution binding **Open**（"No trusted execution evidence"）。
- [原文] §7 Limitations："Context binding is included in the formal model through Hc(Encode(cpriv))=hc but is not implemented in the current prototype."；"Runtime execution binding is an open problem not addressed by the ZKP authorization layer alone"；"The prototype's request binding uses a single plan-level commitment (SHA256(plan)) rather than the model's decomposition of the request into distinct resource and action components."

### 1.4 [原文] CVA 不涉及数据库查询结果
- [原文] 全文无 "database query result correctness / completeness" 类主张；最接近的限定句为 §4.5 "This does not imply that the runtime subsequently executes the same request." 与 §5.2 "the predicate P_PoC ... captures only the policy logic explicitly encoded at circuit generation time."
- **[推论]** CVA 提供的是"授权层证据"，不提供"查询层证据"；把 CVA 与 ZK SQL 证明拼接，CVA 侧贡献的只是主体/请求承诺绑定，不贡献任何查询结果保证。

### 1.5 [原文] §6 Research Agenda 的四个开放问题
1. Identity Binding ≢ Authorization Request Binding ≢ Runtime Execution Binding。
2. Proof correctness ≠ policy correctness（策略治理 / 版本 / 电路治理是一等安全问题）。
3. TOCTOU / context drift：`Authorized(q, c_tv)=1 ⇏ Authorized(q, c_te)=1`（对应 H2 的时间维度）。
4. Multi-agent delegation chains 未覆盖，作者明确不形式化。

### 1.6 [源码] zk-auth-agent-demo（commit `e9982850a3c48aaf5994ea3c10b2d43f15a289d7`）
- `circuits/zk_auth_policy_v3.circom:27-31`：`Poseidon(agent_secret, rho) → agent_id`，principal binding 在电路中。
- `circuits/zk_auth_policy_v3.circom:15,46`：`plan_hash` 是 signal input 直通 signal output，**电路内无 SHA256 组件**。[原文] 论文 §5.2 声称 `SHA256(plan)=hplan` 是电路约束，源码未支持该表述（代码 HEAD 08-24 早于论文 v3 09-24，[未核实] 是否存在后续电路版本）。
- `scripts/generate_input.js:38-46` 与 `gateway/main.py:143-155`：电路外计算 `h_plan = SHA256(op|res|change_id)`。
- `circuits/zk_auth_policy_v3.circom:35-41`：策略硬编码 `clearance ≥ 3 / env == 1 / action == 2`；`scripts/generate_input.js:13-17`：属性由 agent 自报。
- 无 `pid_j` / context / database / query 电路信号；`gateway/main.py:188` 返回硬编码 `action:"ROTATE_SECRET"`。
- 电路规模 531 constraints / 805-byte proof。
- **[源码]** 关键词计数：`database` / `query` / `SQL` / `completeness` 均为 0。
- **[推论]** PoC 实际覆盖面**弱于**论文 Table 2 的自述（request binding 仅为电路外哈希，policy binding 为硬编码谓词且属性自报），更不可能提供任何查询结果保证。

---

## 2. TruthTable（IACR ePrint 2026/1260）

> **正文不可得**：ePrint PDF（2026/1260.pdf）返回 Cloudflare 403、无 HTML 全文；仅元数据页 + 摘要。官方仓库根目录 `paper.pdf` 是另一篇 **"TruthTable++: Verifiable Query Engine with complete TPC-H support"（DRAFT，2026-09-03）**，**不得**当作 2026/1260 原文使用。

### 2.1 [原文，仅摘要] 可核验事实
- "a succinct proof that convinces a verifier of the correct execution of the verifier's SQL query over the prover's committed database"。
- TPC-H 22 查询证明 17；百万行平均 proving 55 s / verify 32 ms / 24 kB；较先前工作 6.3×–63× 证明加速。
- **[推论]** TruthTable 摘要直接给出性质 B（Query Result Correctness），且验证者自己指定 Query。

### 2.2 [源码] 官方代码实测（commit `a214267`）
- `readme.md:109-119`：verify 步骤原文 "This step checks that the proof is valid against the query, the committed table oracle, and the prover-produced result. Use the exact same query and the fresh proof.pi / proof.result.parquet"。
- **query 绑定方式（本次亲自核验，`crates/tt-exec/tests/proof_substitution.rs:102-160`）**：测试 `substituted_proofs_are_rejected` 先断言诚实 proof 必须验证通过（否则后续拒绝无意义），再对 5 类替换逐一断言拒绝：①不同 literal 的 proof+result；②诚实 proof 配另一 query 的 result；③不同形状 query 的 proof；④对另一张表查询的 proof；⑤反向。最终 `assert!(accepted.is_empty())`。即 query 由证明系统**结构性绑定**（换 query / result / 表均失败），而非显式 query_hash 公共输入相等性。[推论] 这比"共享 query_hash"更强，但仍只覆盖性质 B。
- `crates/tt-exec/src/cmd/query.rs:45`：verify 命令把 SQL 编译进执行计划后再验证（query 决定计划，计划决定证明）。
- [未核实] 后台核查曾报告 `crates/tt-proof-planner/src/finalize.rs:312` "transcript 对 query-oracle results digest 签名"——该路径在核验的 commit `a214267` 中**不存在**，本次未能确认，不作为证据使用。
- `crates/tt-core/src/irs/nodes/plan/lps/` 下有 filter / projection / join / limit / sort / aggregate / table_scan 全套算子。
- 授权语义源码零命中：`agent` / `authorization` / `grant` / `principal` 均 0 文件；`acl` 命中为 `TrackedOracle` / `local` 等子串误匹配，非真实 ACL。
- **[推论]** TruthTable 覆盖 B（含结果完整性），不覆盖 A/C/H1/H2；把 Grant 的 query_hash 绑到其 Query 输入是公共输入层的常规组合。

---

## 3. PoneglyphDB（arXiv:2411.15031）

### 3.1 [原文] 摘要可核验事实
- "leverages non-interactive zero-knowledge proofs (ZKP) to support both confidentiality and provability"；"raw data remains exclusively with the host, while also enabling verification of the correctness of query responses by providing proofs to clients"。
- "efficient ZKP designs (called circuits) for basic operations in SQL query processing ... combined to form ZKP circuits for larger, more complex queries"；"PLONKish-based circuits, recursive proof composition techniques, and designs with low-order polynomial constraints"。
- **[推论（摘要层）]** PoneglyphDB 声称覆盖性质 B 的一类实现（SQL 查询正确性 + 数据保密），使用 PLONKish/Halo2 与递归组合——候选方向"用 Halo2"不构成增量。**但源码实测显著弱于论文声称，见下。**

### 3.2 [源码] 官方代码实测（commit `a8eaf24`）—— 与论文声称的差距
- `Cargo.toml` + `src/chips/`（add_carry / hash / inclusion_check / lessthan 等）确认 PLONKish/Halo2 电路实现。
- `src/circuits/mod.rs`：按 query 编号硬编码电路（`q*_final_*.rs`）。
- `src/data/database_commitment.rs`：定义 IPA 承诺，但**未在 mod 树中声明、未接入实际电路**——论文 §3.2 的数据库承诺链在核验的 commit 中未生效。
- `src/sql/q1_final_v4.rs:409-411`：selector 由 witness 侧决定，无门绑定 check → **[推论 C3]** 结果完整性在电路中未被约束。
- `src/sql/mod.rs:1`：注释 "manually copy and paste"；`main.rs:11`：`public_input = [1]`，exposed cell 恒为 1，查询未 expose → **无输出绑定到公共输入**。
- 递归证明组合：`src/` 下未发现实现（论文声称 "recursive proof composition"，源码未见）。
- 论文 §3.2 自述 ACL 在电路外预处理；授权语义源码零命中（agent / authorization / acl / grant / policy / principal 均 0 文件）。
- **[推论]** 该代码是论文原型，远非可部署系统；但即便按其论文声称的完备版本，也只覆盖 B，不覆盖 A/C/H1/H2。"用 Halo2 SQL 电路"本身不是增量。

---

## 4. ZkChainDB（DOI 10.1109/ICBC67748.2026.11575456）★ 正文 BLOCKED

### 4.1 [原文，仅摘要]
- "template-based verifiable SQL engine for off-chain databases using zk-SNARKs and blockchain"；"off-chain execution, on-chain verification"。
- "executes **approved SQL query templates** over private data and generates succinct zero-knowledge proofs, while the blockchain verifies the proof against the **committed dataset state** without accessing raw records"。
- 算子："selection, projection, sorting, Top-K, and group-by aggregation"；优化："Random Linear Combination (RLC), Grand-Product (GP) checks, and pseudo-index structures"；"verify result consistency without fully replaying database execution inside the circuit"。
- 性能：1,000 行 16.67 s、10,000 行 124.67 s、约 1 KB 证明、毫秒级链上验证；对比 ZKSQL、PoneglyphDB。
- [未核实] "approved SQL query templates" 中的"approved"是模板白名单还是授权策略（policy/ACL）；证明与模板的具体绑定机制；查询验证与授权策略是否区别；结果完整性语义。**IEEE 正文 PDF 因付费墙不可得，以上不作最终裁决依据。**

---

## 5. SIGMOD'18 — 查询认证 + 细粒度访问控制（★ 决定性先例）

### 5.1 [原文] 三方模型与数据/策略绑定（§3 Problem Definition）
> "There are three parties in the system: (i) data owner (DO); (ii) service provider (SP); and (iii) users."；每条记录是 `⟨o_i, v_i, Υ_i⟩`，`v_i` 用 CP-ABE 加密，`Υ_i` 是访问策略（单调布尔函数，DNF）；DO 用 ADS 签名全部记录并外包给 SP。

### 5.2 [原文] 授权约束下的结果完整性（直接命中候选 H1/H3）
> "Using the VO, the user should establish the soundness and completeness of a result set RS: **Soundness.** No records in RS are tampered with and are truly the results with respect to the roles of the user. **Completeness.** All records not in RS are either non-results or are inaccessible to the user."

> §7.2 Definition 7.4 (Unforgeability)：恶意 SP 成功的条件包括 "The result set RS contains a record ... such that o* does not satisfy the query q or Υ*(A)=0" 以及 "There exists a record ⟨oj,vj,Υj⟩ not in RS, such that ... oj satisfies the query q, and Υj(A)=1"——即同时禁止插入越权行与遗漏授权行。
> §7.2 Theorem 7.6："Our proposed query authentication algorithms satisfy the security properties of Unforgeability (Definition 7.4) and Zero-Knowledge (Definition 7.5)."

### 5.3 [原文] 私有 ACL / 零知识机密性（直接命中候选 H1 "Private ACL"）
> §3 三级机密性，最强级："Zero-Knowledge Confidentiality. Any information beyond the accessible records D+ in the database D is protected. That is, the users can gain nothing about D\D+ (e.g., not even its size or the associated access policies)."
> §7.2 Definition 7.5 (Zero-Knowledge)：Ideal game 中不可访问记录被替换为 `⟨o_i, random, Role_∅⟩`；"by achieving the zero-knowledge confidentiality, the data content confidentiality and access policy confidentiality are automatically guaranteed."

### 5.4 [原文] 明确的未覆盖边界
- §11 Conclusion future work："we plan to extend the proposed techniques to support more complex queries, such as aggregation"；"multi-source data in a distributed environment"。
- [源码/文本统计] 全文 `update` / `revocation` 关键词命中为 0；无 Agent、无独立授权请求证明（无 agent_id / grant / policy version）、无执行时证据。
- **[推论]** SIGMOD'18 已给出"私有 ACL 约束下查询结果 soundness + completeness + 零知识"的一体化密码学方案（APP 签名 + ABS + CP-ABE + ADS），其威胁模型是"SP 不完全可信 + 用户好奇"——与候选 H1 的目标性质高度重合。差别在：**没有 Agent 授权请求/上下文/策略版本绑定，也没有撤销/动态更新**，因此 H2（策略版本与快照联合一致性）在此文中仍未解决。

---

## 6. 旧仓库（agent-exec-binding-mvp，R1/R2）

### 6.1 [实验，R2] E2.2 自签虚假回执反例
- 出处：分支 `experiment/independent-execution-proxy`（SHA `e327a944`）`research/e-stage-results-v0.1.md` §3.3。
- 结果：Adapter 实际执行越权 Finance 查询，丢弃诚实回执，用**同一把合法 `tool_sk`** 重签 `request_hash = H_authorized`、`output_hash = H_Finance output` 的回执；Gateway 八项绑定失配项恒为 `[]`，返回越权数据；`DR=0`、`UER=1.0`（10/10）；`AuditChain.verify()` 10/10 通过但语义错误。
- [原文] "This is not forging a signature, but a legitimate key holder making an untrue claim about a real execution."（中文义）
- **[推论]** 该反例证明：纯签名回执链无法得到性质 C。若候选方案新增的 ZK 查询证明只约束 `Query vs DB vs Result`（性质 B），它同样**无法**拦截 E2.2——因为 S4（执行行为虚假声明）发生在证明系统之外。这构成"朴素组合不足"的具体攻击候选（见 COMPOSITION_ANALYSIS.md）。

### 6.2 [源码，R1] 独立代理分支覆盖
- `independent_execution_proxy.py`：远程 HTTP 查询代理、独立进程执行、Ed25519 验签、`request_hash`/`context_hash`/`agent_id`/`tool_id`/`tool_schema_hash` 校验、nonce 新鲜度。
- `_staging/e486-d1/D6_EXTERNAL_TOOL_SEMANTICS.md` §7 [原文]："A Gateway-signed receipt attests to the Gateway's recorded execution result. It is not automatically a provider-signed proof of an external side effect."
- `_staging/e486-d1/D5_PROCESS_RESTART_VALIDATION.md` §4 [原文]：测试**不**建立 "Exactly-once execution for arbitrary external tools or services"、"Exactly-once external side effects without cooperation from the external service"、"hardware-backed monotonic counter guarantees"。
- [原文] README："This MVP isolates the authorization-to-execution binding problem rather than claiming novelty for generic 'LLM + ZKP' integration."；"A recent CVA study explicitly lists context-binding implementation and runtime execution binding as open problems."
- **[推论]** 任务包 §0.3 "特别核查独立代理分支已经覆盖的远程查询和执行证据，不得把同一问题重新包装成新方向"——已确认：远程查询代理、执行 binding、进程隔离恢复语义均已覆盖；其边界（不证明实际外部副作用、不证明 exactly-once）也已明确声明。候选方向若仅重新实现"远程查询 + 执行绑定"属重复。

---

## 7. 未核实假设（不得当作结论）

1. **ZkChainDB 正文**：付费墙 BLOCKED；"approved templates" 的授权语义、与策略的关系、结果完整性机制均 UNKNOWN。
2. **CVA 代码版本错位**：代码 HEAD（2026-08-24）早于论文 v3（2026-09-24）；论文声称的 SHA256 电路约束在核验的 commit 中不存在，是否存在更新代码 UNKNOWN。
3. **TruthTable / PoneglyphDB / sxt / QEDB 源码细节**：见 `evidence/source_manifest.json`；未核验项一律 UNKNOWN。
4. **H2 的撤销机制**：现有 ZK SQL 系统是否已有版本/撤销机制，需正文级证据；ZkChainDB 正文不可得，故 H2 裁决受限。
