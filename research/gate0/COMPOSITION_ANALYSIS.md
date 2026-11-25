# COMPOSITION_ANALYSIS.md — 朴素组合是否足够

**任务：** ZKQ-00-G0（Gate 0，只读研究审计）
**日期：** 2026-11-25
**核心问题：** "Authorization 证明 + ZK SQL 查询证明"是否只是已有两类工作的简单组合？共享 `query_hash` 是否已经足够？

---

## 0. 结论先行

> **[推论] 朴素组合（共享 query_hash 的公共输入相等性检查）在密码学上是直接的、常规的组件组合，本身不构成研究增量。** 它能得到的性质是"授权声明与查询证明指向同一 query 字符串"+"该 query 在承诺 DB 上被正确执行"；它**不能**得到"实际执行行为被约束"（性质 C），也不能自动得到"ACL 私有且行级强制"（H1）与"策略版本/快照版本联合一致"（H2）。

> **[推论] 唯一可能构成增量的是 H2 中"授权时刻策略版本与执行时刻快照版本的联合一致性 + 撤销后旧证明失效"这一具体缺口**——但它尚无证据表明现有机制无法解决（ZkChainDB 正文 BLOCKED、SIGMOD'18 无动态更新但属 2018 年外包 DB 模型而非 Agent 授权模型）。按任务包裁决规则，缺关键证据 → 不是 GO。

---

## 1. 朴素组合模型（任务包 §2.2 原文复述）

```
Authorization layer (CVA-style):
  public inputs:  agent_id, query_hash, context_hash, policy_id, nonce, expiry
  proof:          π_auth  ← 证明 attrs 满足策略、principal/request 绑定

Database proof layer (TruthTable/PoneglyphDB-style):
  public inputs:  query_hash, database_root, result_commitment
  proof:          π_query ← 证明 R = Q(D_root) 且输出完整

Verifier:
  verify(π_auth);  verify(π_query);  check query_hash_A == query_hash_Q
```

## 2. CVA 的授权声明（实测，evidence 已核验）

- 论文形式化公共声明：`x_q = (id_i, α, res, c, pid_j, n, t)`（§3–§4）。
- PoC 实际公共声明（§5.2 + 源码 commit `e998285`）：`x_PoC = (id_i, h_plan, n, t)`；**无显式 `pid_j`、无 context commitment、无 database/query 信号**；`h_plan` 是 SHA256(plan) 的电路外计算后作为公共输入直通。
- CVA 明确不证明：数据库查询结果正确 / 完整、远程服务返回结果是否为请求的真实计算结果、运行时执行一致性（§4.5、§5.3 Table 2、§7）。

## 3. TruthTable 的查询证明声明（摘要级 + 源码见 evidence）

- "succinct proof ... correct execution of the **verifier's SQL query** over the prover's **committed database**"（ePrint 2026/1260 摘要）。
- Verifier 自己指定 Query；prove/verify 必须使用同一 Query / Oracle / Proof / Result（官方 README，见 evidence）。
- 已覆盖性质 B（查询结果正确），TPC-H 17/22，百万行 55 s / 32 ms / 24 kB。

## 4. 公共输入关系与共享 `query_hash` 的充分性分析

### 4.1 直接组合可获得的三件事
1. **主体绑定**：π_auth 绑定 agent_id（CVA 已实现 principal binding）。
2. **请求同一性**：`query_hash_A == query_hash_Q` 保证两层证明指向同一 query 字符串——这是公共输入相等性检查，**标准组合**，不是新密码学机制。
3. **查询结果正确性**：π_query 保证 R 是该 query 在 committed DB 上的正确、完整结果（TruthTable/PoneglyphDB/ZkChainDB 都能给）。

### 4.2 共享 `query_hash` 不足以保证的四件事（逐条给反例）

| # | 性质 | 共享 hash 是否足够 | 具体反例 / 理由 |
|---|---|---|---|
| 1 | 实际执行行为（C） | **否** | 旧仓库 E2.2（R2，10/10）：恶意服务实际执行 Finance 查询，却提交 `query_hash=Sales` 的授权证明 + 一份针对 Sales query 的查询证明；它可以选择只对 Sales query 生成诚实 π_query（此时返回的是 Sales 结果，与授权一致，无越权）；**或**返回 Finance 结果并伪造一个"针对 Sales query 的 π_query"——后者在 SNARK 可靠下不可行，但前者说明组合只能约束"被证明的那个 query"，**不能约束服务私下的额外读取**。查询证明本身也不覆盖"服务是否额外读了未授权记录"。 |
| 2 | 私有 ACL 行级强制（H1） | **否（但已有工作覆盖）** | 标准 ZK SQL 证明的 query 是 verifier 指定的任意 SQL，可以写成 `SELECT ... WHERE acl_predicate`，从而"证明结果满足 ACL 条件"；但 predicate 与 ACL 在证明中是**公开**的（公共输入或电路常量）。若要求"ACL 属性不公开"，共享 hash 无能为力。**但** SIGMOD'18（全文已核验）已用 APP 签名 + ABS + CP-ABE + ADS 给出零知识机密性下的行级 ACL 结果 soundness + completeness（Definition 7.4/7.5、Theorem 7.6），直接覆盖这一缺口。 |
| 3 | 策略版本 / 快照版本联合一致（H2） | **否（关键候选缺口）** | 授权时刻 `t_auth` 策略版本 `pid_k`，执行时刻 `t_exec` 数据快照 `root_m`。若 `pid_k` 已被撤销、或 `root_m` 是撤销前的旧快照，两层证明的 hash 相等性检查**不比较** `pid` 与 `root` 的时序一致性。反例：Issuer 在 v1 策略下签发 Grant（允许 Sales），随后策略升级为 v2（禁止 Sales），恶意服务在 v2 生效后仍用 v1 Grant + 撤销前快照 root_old 生成 π_query 与 π_auth；两个 proof 都验证通过，共享 hash 相等，Verifier 接受本应被撤销的查询。**这是朴素组合确实缺失的语义。** |
| 4 | Grant 新鲜度 / 撤销后旧证明失效 | **否（同上反例）** | nonce/expiry 是 CVA 层公共输入，π_query 层不绑定它们；即使 Grant 过期，只要 Verifier 不主动检查 expiry，查询证明仍可被复用。需额外状态（nonce set / 撤销列表）——属**业务逻辑**，不是密码学新约束；CVA §5.2 已明确"replay resistance enforced externally by the gateway"。 |

### 4.3 是否有"不能由简单组合解决"的安全问题？

**[推论]** 有且仅有一个候选：**H2 的联合一致性**——它要求证明"授权时刻的策略/数据状态"与"执行时刻的策略/数据状态"满足某种偏序或相等关系，且撤销后旧 proof 失效。这需要：
- 把 `pid`/策略版本和 `database_root`/快照版本**同时**放进一个联合承诺或联合关系；
- 或引入执行时信任锚（TEE / 远程证明 / 可验证回执）来绑定运行时状态。

但：
- CVA §4.5 已明说执行时信任锚是**开放问题**，不由 ZKP 授权层提供；
- 现有数据库版本机制（如 Merkleized state + 版本 root）和撤销列表（业务状态）**可以直接实现**"比较版本号 + 查撤销表"，无需新密码学约束；把两个版本号放进公共输入做相等性检查也是常规组合；
- ZkChainDB 摘要显示其验证针对 "committed dataset state"，可能已含快照版本绑定，但**正文 BLOCKED，无法核实**。

---

## 5. 具体反例（形式化）

**反例 R1 — 策略撤销后旧授权仍被接受（针对 H2）：**

```
t1:  Issuer 在策略 pid=v1（允许 agent A 查 Sales）下签 x_auth=(A,h_q,pid=1,n,t1)，生成 π_auth。
     DO 承诺快照 root_1（此刻 ACL 允许 Sales）。服务预生成 π_query = Prove(Q=Sales, root_1, R)。
t2:  策略升级 pid=v2（禁止 A 查 Sales），数据快照更新为 root_2（ACL 已 enforced）。
t3:  恶意服务提交 (π_auth, π_query, query_hash=h_q, pid=1, root=root_1, R)。
Verifier: verify(π_auth)=1（v1 下确实授权），verify(π_query)=1（R 是 Sales query 在 root_1 上的正确结果），
          query_hash 相等 → 接受 R。
结果：一个在 t2 已被撤销的查询，在 t3 仍被验证通过。
朴素组合无任何机制阻止；修补方式是业务层检查当前 pid/root 是否等于证明中的值 + 撤销表，
不需要新的密码学原语。
```

**反例 R2 — 私有 ACL 下的结果完整性（针对 H1，说明为何不是缺口）：**
若 verifier 指定 `Q = SELECT id FROM t WHERE acl_ok(user_attrs, row.acl) = 1`，则 ZK SQL 证明直接给出"结果只含授权行、且所有授权行都在结果中"（SIGMOD'18 Def 7.4 的 soundness+completeness 语义等价物）。若要求 `acl_ok` 的输入属性保密，SIGMOD'18 的 ABS + CP-ABE 已实现零知识机密性。**因此 H1 不是一个"现有方案未覆盖"的缺口**——除非引入"Agent 私有授权属性 + 动态 ACL 撤销"的组合，那又回到 H2。

**反例 R3 — 执行行为虚假声明（针对 C，说明为何查询结果证明不够）：**
旧仓库 E2.2（R2）：服务实际读取 Finance 行，但提交一个"针对 Sales query、在 DB 上的正确结果"的 π_query（返回 Sales 结果）并同时提交 π_auth。**结果本身在授权范围内**——客户拿到的是合法 Sales 数据。服务的违规行为是"私下多读了 Finance"；π_query 的存在无法证明它没多读（ZK SQL 证明证明的是"某查询的正确执行"，不是"没执行其他查询"）。这是查询隐私/访问模式问题，属 PA-VFANN R0.2.1 已记录的 A1/A2/A3 执行模型边界，不是本方向的新增量。

---

## 6. 哪些性质可直接组合获得，哪些仍然缺失

| 性质 | 朴素组合 | 备注 |
|---|---|---|
| Principal / Agent Binding | **可直接获得** | CVA 已实现，共享 query_hash 不额外贡献 |
| Query Binding | **可直接获得** | 公共输入相等性检查，标准组合 |
| Query Result Correctness (B) | **可直接获得** | TruthTable / PoneglyphDB / ZkChainDB 已实现 |
| Result Completeness（相对公开 query） | **可直接获得** | 同上 |
| ACL Enforcement（公开 ACL 表达为 WHERE） | **可直接获得** | 写进 query 即可，非新机制 |
| Private ACL（H1） | **已有 SIGMOD'18 覆盖** | 不构成增量 |
| Runtime Execution Binding (C) | **缺失，但组合无法解决** | CVA 明说需执行时信任锚；E2.2 实证 |
| Policy/Snapshot 联合一致 + 撤销（H2） | **缺失，候选缺口** | 但可用业务层版本比较 + 撤销表解决，无新密码学约束；ZkChainDB 正文未知 |
| 查询隐私 / 访问模式隐藏 | **缺失，不属本方向** | 属 PA-VFANN A3 后端问题 |
| 数据真实性 | **不在范围** | garbage-in-garbage-out |

---

## 7. 对任务包 §2.2 五个问题的直接回答

1. **两个证明共享 `query_hash` 是否足以绑定授权请求和查询证明？** —— 足以绑定"字符串同一性"，不足以绑定"执行行为"或"状态时序"。
2. **是否只需要公共输入相等性检查？** —— 对请求同一性，是；对 H1/H2/C，否。
3. **数据库证明已保证输出正确，额外 Agent 证明增加了什么？** —— 增加"主体/策略/上下文/新鲜度的授权关系"，即性质 A；不增加查询侧任何保证。
4. **Grant 的 Query Hash 与 TruthTable 的 Query 绑定是否只是常规组合？** —— **是**。这是把 CVA 的 `h_plan` 与 TruthTable 的 Query 公共输入设为同一值，无需新电路约束。
5. **是否存在不能由简单组合解决的安全问题？** —— 唯一候选是 H2 联合一致性 + 撤销；但其可通过业务层版本检查解决，且 ZkChainDB 正文不可得无法排除已有方案；按裁决规则不能判 GO。性质 C 虽不能由组合解决，但它是 CVA 明说的开放问题且需执行时信任锚（不在本任务"可验证查询结果"范围内），强行纳入会构成"不现实的威胁模型/范围扩张"。

---

## 8. 反例构造的诚实边界

- [实验 R2] E2.2 反例来自旧仓库冻结实验，本阶段未复跑，只作交叉引用。
- R1 / R3 为**形式化推理反例**（[推论]），不是本阶段运行的实验；任务包要求"至少一个具体攻击过程或形式化反例"——R1 满足，但它指向的业务层修补不需要新密码学约束，因此**不足以支撑 GO**。
- ZkChainDB 的 approved templates 是否已有 H2 机制，正文 BLOCKED → UNKNOWN，不得判定其"没有"。
