# DECISION.md — Gate 0 最终裁决

**任务：** ZKQ-00-G0 + ZKQ-00-G0.1（ACL 保密对象与查询覆盖范围校正）
**日期：** 2026-11-25
**G0 基线：** 空仓库初始化基线 `e9e42c4`，G0 交付 HEAD `afe0a3abdb890f117c910a3d3abfab85a78ca1a7`（详见 README.md Phase 0 异常记录）
**G0.1 工作分支：** `research/g0-privacy-audience-correction`（从 G0 HEAD 新建，不覆盖旧提交）
**校正范围：** 仅修正威胁模型口径、H1/H3 覆盖范围与最终裁决措辞；不重跑完整 Gate 0、不扩相关工作、不写代码、不进入 Gate 1。

---

## 0. 最终裁决

# **HOLD**

**一句话理由（G0.1 修正）：** 原裁决中"H1/H3 已被 SIGMOD'18 直接覆盖"口径过宽。SIGMOD'18 覆盖的是 **H1-U**：对用户隐藏不可访问记录的 ACL 信息，并在 equality / range / join 场景给出许可行集合的 soundness + completeness；它**不覆盖 H1-S**：不可信 Query Service / Prover 对 ACL 不可见时仍生成完整性证明。若当前模型坚持 ACL 对 `S` 隐藏，则"谁持有 ACL witness、谁出证明、`S` 能否独立生成"尚未闭合，属核心模型阻断项；H2 仍更像依赖可信当前状态的版本/撤销业务检查；H3 必须按算子逐项标注而非一句"任意 SQL 已覆盖"。因此仍判 **HOLD**，**不进入 Gate 1**。

**不是 NO_GO 的原因：** 不能把"尚未找到"写成"已证明不存在"——H1-S 的 ACL 保密对象与证明生成架构虽未闭合，但没有被证明不可行；ZkChainDB 正文不可得，其对 approved templates / dataset state 的处理是否含版本一致性机制属 UNKNOWN；CVA §6 的 TOCTOU gap 是作者明确形式化但留空的问题。这些是**具体的、可通过有限工作闭合的**缺口，不是无限调研。

**不是 GO_TO_GATE1 的原因：** 未找到"不是简单组合、且现有工作论文+源码均不能满足"的可形式化性质。SIGMOD'18 已覆盖 H1-U 的主要场景；H1-S 尚无可执行架构证据（S-as-Prover 缺少 ACL witness 进入证明的路径，DO/PA-as-Prover 则改变信任边界且仍不覆盖运行时执行）；H2 缺关键证据且无新密码学约束证据；H3 的投影 / LIMIT / 排序 / 聚合需逐系统核对，不能据现有材料宣称新增量。

---

## 1. 逐项核查裁决前提（任务包 Phase 3）

| GO 条件 | 是否满足 | 依据 |
|---|---|---|
| 1. 明确找到可形式化安全性质 | **部分** | H2 可形式化（见 §3）；H1-U 已被 SIGMOD'18 覆盖；H1-S 尚未形成闭合模型（ACL witness/Prover 未定）；H3 需按算子拆分 |
| 2. 不是已有 CVA + ZK SQL 的简单组合 | **否** | 共享 `query_hash` = 公共输入相等性，标准组合（COMPOSITION §4.1/§7.4）；H1-S 即使不是简单组合，也尚无可执行架构 |
| 3. 已有系统论文和源码均不能直接满足 | **否（H1-U、多数 H3）/ UNKNOWN（H1-S、H2）** | SIGMOD'18 全文 Def 7.4/7.5；TruthTable/PoneglyphDB 源码；H1-S 因模型未闭合无法判定，H2 因 ZkChainDB 正文不可得无法判定 |
| 4. 能构造具体攻击或反例说明现有机制不足 | **部分** | R1 反例（撤销后旧授权仍被接受）为形式化推理；CVA §6 Gap 3 原文支持；H1-S 是模型缺口，尚不是攻击/反例 |
| 5. 新机制可通过有限规模实验验证 | 未评估 | 因 2/3/6 不满足，暂不评估 |
| 6. 能明确标注需要新增的密码学约束 | **否** | H2 的修补是业务层状态检查；H1-S 尚未证明必须新增密码学约束（见 `SECURITY_MODEL.md` §3.4 / `COMPOSITION_ANALYSIS.md` §4.4） |
| → GO_TO_GATE1 | **不满足** | — |

---

## 2. 朴素组合是否足够的明确结论

> **G0.1 修正：足够覆盖"授权同一性 + 查询结果正确性"；对 H1 只能说覆盖"对用户隐藏 ACL 的 H1-U"，不能说覆盖"对不可信 Prover 隐藏 ACL 的 H1-S"；仍不足以覆盖"实际执行行为"与"策略/快照联合一致性"。**

- 共享 `query_hash` 的公共输入相等性检查，能让"授权证明指向的 query"与"查询证明验证的 query"一致——这是**常规组合**，不是增量。
- TruthTable 的 query 是**结构性绑定**（换 query/结果/表 5 类替换全部被拒，源码实测），比共享 hash 更强，因而 Grant→Query 绑定的边际价值更低。
- CVA 的 PoC 甚至没有把完整 query 放进电路（plan_hash 电路外计算、直通公共输出），其授权层贡献只有主体/计划级承诺。
- **[推论]** 若把候选声称的增量写成"我们在 CVA 与 TruthTable 之间共享了一个 query hash"，它精确落在任务包 NO_GO 清单的"所谓创新只来自增加一个 Query Hash / Merkle Root / Nonce / Version"一条；H1-S 与 H2 的 UNKNOWN / 模型未闭合使本轮不能直接 NO_GO，但也不足以判 GO。

---

## 3. 尚存的具体性质与反例（H1-S 模型阻断项 + H2）

### 3.0 H1-S：ACL 对 Query Service / Prover 隐藏的模型阻断项

- **[原文]** SIGMOD'18 §3/Algorithm 1 把 `⟨o_i,v_i,Υ_i,σ_i⟩` 外包给 SP，VO 构造按 `Υ_oq(A)` 分支；其 Zero-Knowledge（Def 7.5）保护的是恶意用户，不是 SP。因此 SIGMOD'18 覆盖 H1-U，不覆盖 H1-S。
- **[推论]** 若 `S` 不可见 ACL 且仍由 `S` 生成查询完整性证明，本轮没有证据说明 ACL witness 如何在不泄露给 `S` 的前提下进入证明约束；若改由 DO / PA 生成证明，则 `S` 不再是独立不可信 Prover，信任边界改变，且不自动覆盖运行时执行行为（性质 C）。
- **裁决影响：** H1-S 是当前候选缺口，但首先是**安全模型未闭合**，不是已证可形式化新性质；不能直接 GO。闭合至少需要指定 ACL witness holder、Prover、公私输入边界、对 `S` 的泄露定义，以及当前策略/数据状态的可信来源。

### 3.1 形式化定义（H2 候选，**尚未证明需要新机制**）

设授权时刻 `t_auth` 签发 `x_auth = (A, h_q, pid_k, n, t)`，策略版本 `pid_k`；执行时刻 `t_exec > t_auth`，数据快照版本 `root_m`。定义联合一致性性质：

```
JointFresh(A, h_q, pid_k, root_m, t_exec) = 1
  iff  pid_k == current_policy_version(t_exec)
   AND root_m == current_committed_root(t_exec)
   AND pid_k not in revoked_set(t_exec)
```

要求：Verifier 接受当且仅当 `JointFresh = 1`。

### 3.2 形式化反例 R1（推理，非本阶段实验）

```
t1: Issuer 在 pid=1（允许 A 查 Sales）下签 x_auth；DO 承诺 root_1。
    服务预生成 π_query = Prove(Q=Sales, root_1, R)。
t2: 策略升级 pid=2（禁止 A 查 Sales），快照更新 root_2。
t3: 服务提交 (π_auth, π_query, h_q, pid=1, root=root_1, R)。
    verify(π_auth)=1（v1 下确实授权）；verify(π_query)=1（R 在 root_1 上正确）；hash 相等 → 接受。
```

朴素组合无机制阻止该接受。这是任务包要求的"具体攻击过程/形式化反例"。**但**修补方式——在 Verifier 侧比较 `pid/root` 与当前值、查撤销表——属业务层状态检查，**不是新密码学约束**；与非 ZK 系统的 ACL 撤销检查同构。因此即便 H2 成立，也**不足以支撑 GO**（对应 GO 条件 6 不满足）。

### 3.3 已有工作对 H2 的覆盖情况
- CVA §6 Gap 3：形式化 `Authorized(q,c_tv)=1 ⇏ Authorized(q,c_te)=1`，但明确未实现。
- CVA PoC：nonce/t 是公共输入，replay 由 gateway 外部状态执行——与"比较版本号 + 撤销表"同类业务机制。
- SIGMOD'18：全文 `update`/`revocation` 命中 0（2018 年外包 DB 静态数据模型）。
- ZkChainDB：摘要提到 "committed dataset state"，是否含版本/撤销机制 **UNKNOWN（正文 BLOCKED）**。
- TruthTable / PoneglyphDB / zk-SQL / sxt / QEDB：源码均无策略版本/撤销语义。

---

## 4. 与最接近工作的对比：多了哪一项可验证性质

| 最接近工作 | 它已有 | 候选想多的 | 实际状态 |
|---|---|---|---|
| SIGMOD'18（全文） | 对用户隐藏不可访问记录 ACL 信息的行级 ACL + 结果 soundness/completeness（equality/range/join） | H1-S：对 Prover 隐藏 ACL 仍证明结果完整性 | **未覆盖 H1-S**；但 witness/Prover 架构未闭合，不能直接主张增量；aggregation/limit/sort 等也未被其覆盖 |
| TruthTable（源码） | verifier 指定 Query、结构性绑定、完整 SQL 算子、结果完整性 | Agent 授权主体/策略绑定 | 可由共享公共输入获得（常规组合）；无私有 ACL 强制语义 |
| CVA（全文+源码） | 主体/计划绑定、私有策略满足（PoC 弱于论文） | 查询结果正确性 | 由 TruthTable 等现成给出；CVA 自己不声称 |
| ZkChainDB（仅摘要） | approved templates + committed dataset state + 5 类算子 | 策略版本/撤销联合一致 | **UNKNOWN（正文 BLOCKED）** |

> 结论（G0.1 修正）：在所有已核验的来源中，**没有一项已闭合、且"现有方案均不能满足"的可验证性质**被找到。H1-S 是模型分叉而非已闭合增量；H2 是具体候选但其是否被 ZkChainDB 覆盖未知、且修补看起来不需新密码学约束；H3 必须按算子逐项标注。

---

## 5. HOLD 的三个具体阻断项（G0.1 更新）

| # | 阻断项 | 闭合所需证据 | 闭合后可做什么 |
|---|---|---|---|
| **B1（核心模型阻断项）** | **ACL 保密对象未闭合**：当前模型要求 ACL 对 `S` 不可见，但 SIGMOD'18 的 SP 明确可见并使用 `Υ_i`；若 `S` 不可见，谁持 ACL witness、谁生成证明、能否独立生成均未定 | 给出四元组：`ACL witness holder`、`Prover`、`公开/私有输入边界`、`对 S 的泄露定义`；并论证当前策略版本与数据根如何可信获得。若保留 S-as-Prover，需说明私有 ACL witness 进入约束而不泄露给 S 的机制；若改为 DO/PA-as-Prover，需明确信任边界变化及其与运行时执行证据的关系 | 若形成闭合架构且仍非现有工作可组合得到 → 才进入下一轮形式化；若证明不可行或只是信任边界转移 → NO_GO 结案 |
| **B2** | H2 覆盖与密码学必要性未闭合：ZkChainDB 正文不可得；且版本比较 + 撤销表看起来是业务层机制 | 通过机构订阅 / 作者公开版 / 后继论文获取 ZkChainDB 正文 §III/§IV，确认 approved 语义、policy version 与 dataset version 绑定、撤销处理；随后形式化 Verifier 状态模型，给出一个现有可信状态检查无法防、而新密码学约束可防的具体攻击 | 若已覆盖或找不到需新约束的攻击 → NO_GO 结案；若找到 → 可评估 GO |
| **B3** | 复现性边界：CVA 代码 HEAD（08-24）早于论文 v3（09-24）约一月，PoC 实测弱于论文自述（无 SHA256 电路约束、无 pid_j/context） | 核验 CVA 仓库是否存在更新分支/commit 或 v3 对应实现；确认最终代码状态 | 影响"授权侧基线"的准确描述；不影响 H1-U 与 H1-S 的区分结论，但影响任何未来以 CVA 为基线的增量声明 |

> 三项均可由**有限、明确**的工作闭合，不是"继续深入调研"的空泛结论。B1 是本轮新增的核心模型阻断项；若 B1 不闭合，即使 B2/B3 闭合也不得进入 Gate 1。

---

## 6. 诚实边界（任务包 §5 + 项目硬约束）

- 本轮是只读研究审计，**未**编写电路、**未**实现查询引擎、**未**运行任何证明、**未**修改旧仓库或其他分支。
- TruthTable（ePrint 2026/1260）正文被 Cloudflare 403 拦截、ZkChainDB 正文被 IEEE 付费墙拦截——两篇的正文级细节标 UNKNOWN，**没有**任何裁决单独依赖这两篇的正文。
- PoneglyphDB 源码实测显著弱于论文声称（承诺未接入电路、公开输入恒 `[1]`、无递归）；本裁决**不**把源码缺陷当作"论文错误"，只记录两者差异。
- SIGMOD'18 的结论来自 16 页 PDF 全文与 Definition 7.4/7.5、Theorem 7.6；G0.1 已重新核对 §3/§5/§7：其 Zero-Knowledge 保护恶意用户，SP 接收并使用 `Υ_i`，故只支持 H1-U，不支持 H1-S。本轮未找到其官方代码仓库，Implementation Evidence 列不填 YES。
- 反例 R1/R3 是**形式化推理**（[推论]），E2.2 是旧仓库 R2 冻结实验的交叉引用，本阶段均未复跑。
- **HOLD 不表示方向彻底失败**：它表示"当前切口尚未找到可辩护的新性质，且有一个可通过有限工作闭合的关键证据缺口"。不启动 Gate 1，不建 PR，不合并 main。

---

## 7. 下一步（本轮到此停止）

G0.1 交付到此为止，等待独立审查。若审查通过并决定继续，下一轮应**先**闭合 B1（ACL 保密对象与 Prover/witness 架构），再处理 B2（ZkChainDB 正文与 H2 是否需新密码学约束）；不得同时展开新研究方向、不得提前设计电路。若 B1 无法闭合，保持 HOLD 并停止，不自动进入 Gate 1 或 G0.2。
