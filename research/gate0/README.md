# Gate 0 — 授权绑定的可验证查询结果：研究增量与可行性核验

**任务：** ZKQ-00-G0 + ZKQ-00-G0.1（ACL 保密对象与查询覆盖范围校正）
**项目：** ZK-Agent Query Binding
**执行日期：** 2026-11-25
**任务性质：** 只读研究审计 + 有限文档校正（**不**写电路、**不**实现查询引擎、**不**生成证明、**不**复制旧仓库代码）
**G0 分支 / HEAD：** `research/g0-related-work-audit` @ `afe0a3abdb890f117c910a3d3abfab85a78ca1a7`
**G0.1 分支：** `research/g0-privacy-audience-correction`（从 G0 HEAD 新建）
**最终裁决：** **HOLD**（详见 `DECISION.md`）

---

## 1. 本轮目标与纪律

候选研究问题：在 Agent 通过授权机制访问远程数据库时，能否让不可信查询服务提供密码学证据，证明返回结果确实是指定 Agent 在指定上下文下获批的查询，在数据所有者承诺的数据快照和授权策略版本上的正确、完整结果？

**本轮的目的不是证明该方向可行，而是尝试推翻它**：只有当找到明确、可复现、不能由现有方案简单组合得到的安全性质时才进入下一阶段。本轮严格按任务包 Phase 0–3 执行，未扩大范围、未启动 Gate 1。

---

## 2. Phase 0 基线核验（含一处重要异常）

| 核验项 | 结果 |
|---|---|
| 本地路径 `D:\Research\ZK-Agent Query Binding` | 存在，但**完全为空**：无 `.git`、无 starter ZIP、无任何文件 |
| 远端 `kaikai-cao/ZK-Agent-Query-Binding` | 存在（创建于 2026-11-25T07:32:13Z，`size=0`，默认分支 main，**无任何分支、无提交**） |
| origin | 确为新仓库 `https://github.com/kaikai-cao/ZK-Agent-Query-Binding.git`，非旧仓库 |
| 工作区 | 干净（初始化后） |
| 远端 main 与本地关系 | 远端无 main 提交；本地初始化空提交作基线 |

**异常处理（未做任何历史重写）：** 任务包假设"starter ZIP 已包含文件、可从核验通过的基线创建分支"——该前提不成立。处理如下，均已记录、可复核：
1. 不 reset、不 force push、不改写历史；
2. 在空目录 `git init -b main`，创建**一个空提交**作为基线 `e9e42c4b578ab817790f9c34148d7c4ad06968a1`（提交信息明示"no starter files present"）；
3. 从该基线创建分支 `research/g0-related-work-audit`；
4. 关联 origin；**本轮所有新增文件仅在该分支**，不修改 main、不建 PR。

**旧仓库只读检查（未修改、未复制代码）：**
- `agent-exec-binding-mvp`：main `f304857`、experiment/independent-execution-proxy `e327a94`、feat/step3-2b-plan-root-circuit `48169bc`（本地 checkout，工作区干净）。
- `pa-vfann-experiment`：HEAD `6ce5fc6`，分支 `exp08-agentic-trace-leakage-audit`；仅读取其 exp08 README 的相关结论。

---

## 3. 交付文件

```
research/gate0/
├── README.md                    本文件：范围、基线、交付清单
├── SOURCE_MANIFEST.md           每项来源的正式名称/作者/版本/地址/源码 SHA/检查章节/核验状态
├── RELATED_WORK_MATRIX.md       15 维 × 7 系统对比矩阵 + 三项最重要对比
├── CLAIMS_AND_EVIDENCE.md       原文/源码/实验/推论/未核实 五类分级
├── SECURITY_MODEL.md            角色/信任假设/攻击者能力/资产/泄露对象/范围外攻击
├── COMPOSITION_ANALYSIS.md      朴素组合充分性 + 三个具体反例 + 逐维缺失表
├── DECISION.md                  最终裁决 HOLD + 三个具体阻断项
└── evidence/
    └── source_manifest.json     来源地址/论文版本/代码 SHA/访问日期/核验状态（可机读）
```

---

## 4. 核心核查结果摘要

### 4.1 论文原文与官方代码（见 SOURCE_MANIFEST.md / evidence/source_manifest.json）

| 来源 | 论文 | 代码 | 状态 |
|---|---|---|---|
| CVA (arXiv 2607.21325 v3) | HTML 全文核验 | `e998285`（源码弱于论文自述） | VERIFIED |
| TruthTable (ePrint 2026/1260) | **正文 403 拦截**（仅摘要） | `a214267`（query 结构性绑定，源码实测） | PARTIAL + VERIFIED 源码 |
| PoneglyphDB (arXiv 2411.15031) | HTML 全文核验 | `a8eaf24`（源码显著弱于论文） | VERIFIED |
| ZkChainDB (DOI ...11575456) | **正文付费墙拦截**（仅摘要） | 无官方公开代码 | PARTIAL |
| SIGMOD'18 Xu et al.（补充发现） | 16 页 PDF 全文核验 | 无官方代码仓库 | VERIFIED 论文 |

其余核对：nulltea/zk-SQL `4c3626d`、sxt-proof-of-sql `f28544d`、QEDB `dc5358a`。

### 4.2 最重要的三项已有工作对比

1. **SIGMOD'18（全文，G0.1 校正）** — 用 APP 签名 + ABS + CP-ABE + ADS 实现"行级 ACL + 结果 soundness & completeness（Def 7.4）+ 对用户零知识机密性（Def 7.5：不可访问记录的数量与策略不泄露）"。它覆盖 **H1-U** 与 equality/range/join 的部分 H3；**不覆盖 H1-S**，因为 SP 明确接收并使用 `Υ_i`。aggregation 是 future work。
2. **TruthTable（源码）** — verifier 指定 Query、proof 结构性绑定 query（5 类替换全拒）、全套 SQL 算子；授权语义源码零命中。**覆盖性质 B；把 Grant 绑到其 Query 是常规组合；不等于私有 ACL 强制。**
3. **CVA（全文 + 源码）** — 作者自己在 §4.5 明确 `VerifyAuth=1 ⇏ q_exec=q_auth`，PoC 中 context binding / runtime execution binding 均为 Open。**授权层基线，不提供任何查询结果保证。**

### 4.3 朴素组合是否足够 — 明确结论

**足够覆盖"授权同一性 + 查询结果正确性"，不足以覆盖"实际执行行为"与"策略/快照联合一致性"。** 共享 `query_hash` 是公共输入相等性检查，属常规组合；TruthTable 的结构性绑定比它更强，使 Grant→Query 绑定的边际价值更低。详见 `COMPOSITION_ANALYSIS.md`。

### 4.4 具体反例

- **R1（形式化推理）**：策略撤销后旧 Grant + 旧快照 root 仍能让两层证明通过、Verifier 接受本应被拒的查询 —— 指向 H2。
- **R2（推论，G0.1 修正）**：H1-U（对用户隐藏 ACL 的结果完整性）已被 SIGMOD'18 覆盖；H1-S（对 Query Service / Prover 隐藏 ACL）未被覆盖，但证明生成者架构未闭合，不能直接判为新增量。
- **R3（推理）**：实际执行行为虚假声明 —— 旧仓库 E2.2 冻结实验（R2，10/10，UER=1.0）已实证纯签名回执无法得到 Runtime Execution Binding；ZK SQL 查询证明只证明"某查询的正确执行"，不证明"没执行其他查询"。

### 4.5 最终裁决：HOLD（不进入 Gate 1）

- **不是 NO_GO**：H1-S 的 ACL witness / Prover 架构未闭合但未被证明不可行；ZkChainDB 正文不可得，H2 是否已覆盖属 UNKNOWN。不能把"尚未找到"写成"已证明不存在"。
- **不是 GO**：SIGMOD'18 已覆盖 H1-U 的主要场景；H1-S 尚无可执行架构证据；H2 的修补看起来是业务层版本比较 + 撤销表；H3 必须按算子逐项标注，不能据现有材料主张新增量。
- **三个具体阻断项 B1/B2/B3** 及各自闭合所需证据见 `DECISION.md` §5；G0.1 将 **B1 更新为核心模型阻断项（ACL 保密对象 + Prover/witness 架构）**。

---

## 5. 执行边界与提交

- G0 原始提交仅修改 `research/gate0/` 下 8 个文件并推送 `research/g0-related-work-audit`。
- G0.1 修正仅修改允许的 `research/gate0/` 文档（README / SOURCE_MANIFEST / RELATED_WORK_MATRIX / CLAIMS_AND_EVIDENCE / SECURITY_MODEL / COMPOSITION_ANALYSIS / DECISION）；`evidence/source_manifest.json` 未发现元数据错误，故未改动。
- G0.1 在 `research/g0-privacy-audience-correction` 分支提交并推送；核验远端 SHA；main 与 G0 分支未修改；不建 PR、不合并、不启动 Gate 1。
- 提交与远端核验结果见交付报告。
