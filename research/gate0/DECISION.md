# DECISION.md — Gate 0 最终裁决

**任务：** ZKQ-00-G0（Gate 0，只读研究审计）
**日期：** 2026-11-25
**基线：** 空仓库（详见 README.md Phase 0 异常记录）
**工作分支：** `research/g0-related-work-audit`

---

## 0. 最终裁决

# **HOLD**

**一句话理由：** 候选的朴素组合（CVA 授权证明 + ZK SQL 查询证明，共享 `query_hash`）已由现有工作直接覆盖 H1 与 H3，不构成研究增量；唯一尚未被覆盖的具体性质是 H2（策略版本与数据快照的联合一致性 + 撤销后旧证明失效），但**判断它是否已由 ZkChainDB 解决的关键证据（论文正文）被 IEEE 付费墙拦截**，且即便未解决，其修补看起来是业务层版本比较 + 撤销表而非新密码学约束。关键证据缺失 → 按任务包规则判 HOLD，**不进入 Gate 1**。

**不是 NO_GO 的原因：** 不能把"尚未找到"写成"已证明不存在"——ZkChainDB 正文不可得，其对 approved templates / dataset state 的处理是否含版本一致性机制属 UNKNOWN；CVA §6 的 TOCTOU gap 是作者明确形式化但留空的问题。诺干证据缺口是**具体的、可通过有限工作闭合的**，不是无限调研。

**不是 GO_TO_GATE1 的原因：** 未找到"不是简单组合、且现有工作论文+源码均不能满足"的可形式化性质；H2 缺关键证据，且尚无证据表明它需要新增密码学约束（见 §3）。

---

## 1. 逐项核查裁决前提（任务包 Phase 3）

| GO 条件 | 是否满足 | 依据 |
|---|---|---|
| 1. 明确找到可形式化安全性质 | **部分** | H2 可形式化（见 §3），但 H1/H3 已被覆盖 |
| 2. 不是已有 CVA + ZK SQL 的简单组合 | **否** | 共享 `query_hash` = 公共输入相等性，标准组合（COMPOSITION §4.1/§7.4） |
| 3. 已有系统论文和源码均不能直接满足 | **否（H1/H3）/ UNKNOWN（H2）** | SIGMOD'18 全文 Def 7.4/7.5 + TruthTable/PoneglyphDB 源码 |
| 4. 能构造具体攻击或反例说明现有机制不足 | **部分** | R1 反例（撤销后旧授权仍被接受）为形式化推理，非实验；CVA §6 Gap 3 原文支持 |
| 5. 新机制可通过有限规模实验验证 | 未评估 | 因 2/3 不满足，暂不评估 |
| 6. 能明确标注需要新增的密码学约束 | **否** | H2 的修补是业务层状态检查，无新密码学约束（见 §3） |
| → GO_TO_GATE1 | **不满足** | — |

---

## 2. 朴素组合是否足够的明确结论

> **足够覆盖"授权同一性 + 查询结果正确性"；不足以覆盖"实际执行行为"与"策略/快照联合一致性"。**

- 共享 `query_hash` 的公共输入相等性检查，能让"授权证明指向的 query"与"查询证明验证的 query"一致——这是**常规组合**，不是增量。
- TruthTable 的 query 是**结构性绑定**（换 query/结果/表 5 类替换全部被拒，源码实测），比共享 hash 更强，因而 Grant→Query 绑定的边际价值更低。
- CVA 的 PoC 甚至没有把完整 query 放进电路（plan_hash 电路外计算、直通公共输出），其授权层贡献只有主体/计划级承诺。
- **[推论]** 若把候选声称的增量写成"我们在 CVA 与 TruthTable 之间共享了一个 query hash"，它精确落在任务包 NO_GO 清单的"所谓创新只来自增加一个 Query Hash / Merkle Root / Nonce / Version"一条——但 H2 的UNKNOWN使本轮不能直接 NO_GO。

---

## 3. 唯一尚存的具体性质与反例（H2）

### 3.1 形式化定义（候选，**尚未证明需要新机制**）

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
| SIGMOD'18（全文） | 行级 ACL + 结果 soundness/completeness + 零知识机密性 | — | H1/H3 已被覆盖，无可主张增量 |
| TruthTable（源码） | verifier 指定 Query、结构性绑定、完整 SQL 算子、结果完整性 | Agent 授权主体/策略绑定 | 可由共享公共输入获得（常规组合）；无新密码学约束 |
| CVA（全文+源码） | 主体/计划绑定、私有策略满足（PoC 弱于论文） | 查询结果正确性 | 由 TruthTable 等现成给出；CVA 自己不声称 |
| ZkChainDB（仅摘要） | approved templates + committed dataset state + 5 类算子 | 策略版本/撤销联合一致 | **UNKNOWN（正文 BLOCKED）**，这是阻断项 1 |

> 结论：在所有已核验的来源中，**没有一项"现有方案均不能满足"的可验证性质**被找到。H2 是唯一候选，但其是否被 ZkChainDB 覆盖未知，且其修补不需新密码学约束。

---

## 5. HOLD 的三个具体阻断项（任务包要求：最多三个 + 每个所需证据）

| # | 阻断项 | 闭合所需证据 | 闭合后可做什么 |
|---|---|---|---|
| **B1** | ZkChainDB 正文不可得（IEEE 付费墙），其 "approved SQL query templates" + "committed dataset state" 是否已实现策略版本/撤销联合一致性未知 | 通过机构订阅 / 作者公开版（arXiv、机构仓储、会议 open access）/ 引用该文并描述其协议的后继论文，获取正文 §III 系统模型、§IV 验证协议，确认：(a) approved 是授权策略还是模板白名单；(b) 证明是否绑定 policy version 与 dataset version；(c) 是否处理撤销 | 若已覆盖 H2 → **NO_GO 结案**；若未覆盖 → 继续 B2 |
| **B2** | H2 即便未被覆盖，也未见"必须新增密码学约束"的证据——版本比较 + 撤销表看起来是业务层机制 | 在 B1 闭合后，形式化定义 Verifier 状态模型，论证：在当前威胁模型下（Issuer 可信、Verifier 持有当前版本与撤销表），是否存在只能靠新密码学原语（而非可信状态）解决的攻击；给出一个现有状态检查无法防、而新约束可防的具体攻击 | 若找到 → 可评估 GO；若找不到 → **NO_GO 结案** |
| **B3** | 复现性边界：CVA 代码 HEAD（08-24）早于论文 v3（09-24）约一月，PoC 实测弱于论文自述（无 SHA256 电路约束、无 pid_j/context） | 核验 CVA 仓库是否存在更新分支/commit 或 v3 对应实现；确认最终代码状态 | 影响"授权侧基线"的准确描述；不影响 H1/H3 已被覆盖的结论，但影响任何未来以 CVA 为基线的增量声明 |

> 三项均可由**有限、明确**的工作闭合，不是"继续深入调研"的空泛结论。

---

## 6. 诚实边界（任务包 §5 + 项目硬约束）

- 本轮是只读研究审计，**未**编写电路、**未**实现查询引擎、**未**运行任何证明、**未**修改旧仓库或其他分支。
- TruthTable（ePrint 2026/1260）正文被 Cloudflare 403 拦截、ZkChainDB 正文被 IEEE 付费墙拦截——两篇的正文级细节标 UNKNOWN，**没有**任何裁决单独依赖这两篇的正文。
- PoneglyphDB 源码实测显著弱于论文声称（承诺未接入电路、公开输入恒 `[1]`、无递归）；本裁决**不**把源码缺陷当作"论文错误"，只记录两者差异。
- SIGMOD'18 的结论来自 16 页 PDF 全文与 Definition 7.4/7.5、Theorem 7.6；本轮未找到其官方代码仓库，Implementation Evidence 列不填 YES。
- 反例 R1/R3 是**形式化推理**（[推论]），E2.2 是旧仓库 R2 冻结实验的交叉引用，本阶段均未复跑。
- **HOLD 不表示方向彻底失败**：它表示"当前切口尚未找到可辩护的新性质，且有一个可通过有限工作闭合的关键证据缺口"。不启动 Gate 1，不建 PR，不合并 main。

---

## 7. 下一步（本轮到此停止）

本轮交付到此为止，等待独立审查。若审查通过并决定继续，下一轮应**只**针对 B1（获取 ZkChainDB 正文）与 B2（H2 是否需新密码学约束的形式化论证），不得同时展开新研究方向、不得提前设计电路。
