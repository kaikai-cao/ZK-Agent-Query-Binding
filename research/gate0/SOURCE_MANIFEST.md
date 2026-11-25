# SOURCE_MANIFEST.md — Gate 0 原始来源清单

**任务：** ZKQ-00-G0 + ZKQ-00-G0.1（有限文档校正：ACL 保密对象与查询覆盖范围）
**访问日期：** 2026-11-25（G0.1 于同日重新核对 S11 全文）
**纪律：** 论文原文优先于摘要；代码优先于 README；无法获取的来源明确标注 BLOCKED / UNKNOWN，不得推测。英文引号内为原文，其余为中文说明。

---

## 0. 核验状态汇总（先看结论）

| # | 来源 | 类型 | 原文/源码获取 | 核验状态 |
|---|---|---|---|---|
| S1 | CVA, arXiv:2607.21325 v3 | 论文 | HTML 全文可获取 | **VERIFIED（全文）** |
| S2 | Imari91/zk-auth-agent-demo | 代码 | 见 §2 | 见 §2 |
| S3 | TruthTable, IACR ePrint 2026/1260 | 论文 | **正文 PDF 被 Cloudflare 403 拦截（无 HTML）；仅元数据页 + 摘要可获取** | **PARTIAL（仅摘要）** |
| S4 | arkworks-rs/truth-table | 代码 | 见 §4 | 见 §4 |
| S5 | PoneglyphDB, arXiv:2411.15031 | 论文 | HTML 全文可获取 | **VERIFIED（全文）** |
| S6 | tuzijun111/PoneglyphDB | 代码 | 见 §6 | 见 §6 |
| S7 | ZkChainDB, DOI 10.1109/ICBC67748.2026.11575456 | 论文 | **正文 PDF 被 IEEE 付费墙拦截**；摘要页可获取 | **PARTIAL（仅摘要）** |
| S8 | nulltea/zk-SQL | 代码 | 见 §8 | 见 §8 |
| S9 | sxt-proof-of-sql | 代码 | 见 §9 | 见 §9 |
| S10 | QEDB | 代码 | 见 §10 | 见 §10 |
| S11 | Xu et al., SIGMOD'18 "When Query Authentication Meets Fine-Grained Access Control: A Zero-Knowledge Approach" | 论文 | 作者主页 PDF 全文可获取（16 页） | **VERIFIED（全文）** |
| S12 | agent-exec-binding-mvp（旧仓库） | 代码/文档 | 本地只读 | **VERIFIED（R1/R2）** |
| S13 | pa-vfann-experiment（旧仓库） | 文档 | 本地只读 | **VERIFIED（仅记录相关内容）** |

> S11 是本轮补充搜索发现的最相关先例，因覆盖候选的 **H1-U**（对用户隐藏 ACL 的行级授权结果完整性）而加入矩阵；G0.1 已校正：它**不覆盖 H1-S**（对 Query Service / Prover 隐藏 ACL）。来源为 ACM SIGMOD 2018，DOI 10.1145/3183713.3183741。

---

## 1. S1 — CVA（Cryptographically Verifiable Agent Authorization）

- **正式名称：** Cryptographically verifiable authorization for autonomous AI agents: a falsifiable hypothesis and proof of concept
- **作者：** M. Llambí-Morillas, D. Fernández-Fernández
- **版本 / 时间：** arXiv:2607.21325，v1 2026-07-23，v3 2026-09-24（本次核验 v3）；13 页，1 图，3 表
- **发表：** Frontiers in Computer Science 8:1966725 (2026)
- **DOI / 地址：** arXiv https://arxiv.org/abs/2607.21325 ；HTML 全文 https://arxiv.org/html/2607.21325v3 ；期刊 DOI https://doi.org/10.3389/fcomp.2026.1966725
- **精读章节：** §3、§3.1、§3.2、§4、§4.5、§5（含 §5.2、§5.3 Table 2）、§6、§7
- **核验状态：** **VERIFIED（全文 HTML）**
- **关键事实（原文，见 CLAIMS_AND_EVIDENCE.md）：** §4.5 `VerifyAuth=1 ⇏ q_exec=q_auth`；§5.3 Table 2 中 Context binding = Open、Runtime execution binding = Open、Policy binding = Partial；不声称数据库查询结果正确性/完整性。

## 2. S2 — zk-auth-agent-demo（CVA 官方 PoC 代码）

- **地址：** https://github.com/Imari91/zk-auth-agent-demo
- **用途：** 核对 CVA PoC 实际实现（电路约束、公共输入、文件清单）与论文 §5 是否一致。
- **代码 commit SHA：** `e9982850a3c48aaf5994ea3c10b2d43f15a289d7`（2026-08-24，`Merge pull request #5 from Imari91/poc-review-2.0`）；clone 到 `$TEMP/gate0-src/` 只读核查。
- **核验状态：** **VERIFIED（全文论文 + 源码）**。注意代码 HEAD（08-24）早于论文 v3（09-24）约一个月，存在版本错位。
- **源码关键事实（见 CLAIMS_AND_EVIDENCE.md）：** 电路 `zk_auth_policy_v3.circom:27-31` 内 `Poseidon(agent_secret,rho)→agent_id`；电路**无 SHA256 组件**，`plan_hash` 只是私有输入直通公共输出（`v3.circom:15,46`）；`h_plan=SHA256(op|res|change_id)` 在电路外算（`generate_input.js:38-46`、`gateway/main.py:143-155`）；策略硬编码 `clearance≥3/env==1/action==2`（`v3.circom:35-41`），属性由 agent 自报（`generate_input.js:13-17`）；无 `pid_j`/context/database/query 信号；gateway 返回硬编码 `action:"ROTATE_SECRET"`（`main.py:188`）；531 constraints / 805-byte proof。`database/query/SQL/completeness` 全文关键词计数均为 0。

## 3. S3 — TruthTable（IACR ePrint 2026/1260）

- **正式名称：** TruthTable: A Verifiable Query Engine
- **作者：** Bharath Namboothiry, Alireza Shirzad, Spencer Solit, Ryan Marcus, Pratyush Mishra（均 University of Pennsylvania）
- **版本 / 时间：** Paper 2026/1260；received 2026-06-15，approved 2026-06-19
- **地址：** https://eprint.iacr.org/2026/1260 （短链 https://ia.cr/2026/1260）
- **摘要关键数字：** TPC-H 22 个查询中证明 17 个；百万行数据库平均证明 55 秒、验证 32 ms、证明大小 24 kB；证明时间较先前工作快 6.3×–63×。
- **正文获取状态：** ePrint PDF（https://eprint.iacr.org/2026/1260.pdf）返回 Cloudflare 403，无 HTML 版本，**正文 PARTIAL（不可得）**。
- **注意：** 官方 GitHub 仓库根目录的 `paper.pdf` 是另一篇 **"TruthTable++: Verifiable Query Engine with complete TPC-H support"（DRAFT，2026-09-03）**，**不是** ePrint 2026/1260 原文，不得用它替代 §3 的论文证据。
- **核验状态：** **PARTIAL（仅摘要 + 官方源码）**；论文正文级细节标 UNKNOWN，不作为最终裁决依据。

## 4. S4 — arkworks-rs/truth-table（TruthTable 官方代码）

- **地址：** https://github.com/arkworks-rs/truth-table
- **重点路径：** `crates/tt-exec`（setup / commit / prove / verify）、负责查询计划与数据库承诺的 crate、`tt-results` 基准脚本、README 中 prove/verify 必须使用相同 Query / Oracle / Proof / Result 的实现细节。
- **代码 commit SHA：** `a2142677bfd799abee5da5ba184528fc0afea71e`（2026-11-18，`Poneglyph micro results to 2^20 and print-size paper figures (#237)`）。
- **核验状态：** **VERIFIED（源码）**。
- **源码关键事实（见 CLAIMS_AND_EVIDENCE.md）：** `readme.md:109-119` 明确 verify 要用 "exact same query" + fresh proof/result；`crates/tt-exec/tests/proof_substitution.rs:102-160` 实测 5 类替换（换 literal / 换结果 / 换 query 形状 / 换表 / 反向）均被拒绝——query 由证明系统**结构性绑定**；授权语义源码零命中（agent / authorization / grant / principal = 0；"acl"命中为 TrackedOracle/local 子串误匹配）。

## 5. S5 — PoneglyphDB（arXiv:2411.15031）

- **正式名称：** PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification
- **作者：** Binbin Gu, Juncheng Fang, Faisal Nawab
- **版本 / 时间：** v1，2024-11-22（本次核验 v1 HTML 全文）
- **DOI / 地址：** https://arxiv.org/abs/2411.15031 ；HTML https://arxiv.org/html/2411.15031v1 ；DOI https://doi.org/10.1145/3709713
- **核验状态：** **VERIFIED（全文 HTML）**
- **摘要关键事实：** 原始数据仅留在 host；PLONKish 电路 + 递归证明组合 + 低阶多项式约束；TPC-H 评测。

## 6. S6 — tuzijun111/PoneglyphDB（官方代码）

- **地址：** https://github.com/tuzijun111/PoneglyphDB
- **代码 commit SHA：** `a8eaf241fbf9d02a47951906d1e38bbdd5f55b72`（2026-09-30）。
- **核验状态：** **VERIFIED（源码）**，但**源码实测显著弱于论文**（见下）。
- **源码关键事实：** `src/circuits/mod.rs` 按 query 编号硬编码；`src/data/database_commitment.rs` 定义 IPA 承诺但**未在 mod 树中声明、未接入电路**；`src/sql/q1_final_v4.rs:409-411` selector 由 witness 侧决定、无门绑定 check；`src/sql/mod.rs:1` 注释 "manually copy and paste"；`main.rs:11` `public_input=[1]`，exposed cell 恒为 1，**无输出绑定**；递归组合未实现；论文 §3.2 自述 ACL 在电路外。授权语义源码零命中。

## 7. S7 — ZkChainDB（DOI 10.1109/ICBC67748.2026.11575456）★ 正文 BLOCKED

- **正式名称：** ZkChainDB: A Verifiable and Privacy-Preserving SQL Query Engine for Off-Chain Database Using zk-SNARKs and Blockchain
- **作者：** Lulu Li, Wei Wang, Jianan Hong, Jing Fu, Junyu Wang
- **会议 / 时间：** 2026 IEEE International Conference on Blockchain and Cryptocurrency (ICBC)，2026-06-01 至 06-05，Brisbane, Australia；IEEE Xplore 收录日 2026-07-01
- **地址：** https://doi.org/10.1109/ICBC67748.2026.11575456 ；https://ieeexplore.ieee.org/document/11575456
- **正文获取状态：** IEEE Xplore 页面明确提示 PDF 无访问权限（"You do not have access to this PDF"），**正文 BLOCKED**。仅摘要页可核验。
- **摘要可核验事实（原文）：** "template-based verifiable SQL engine for off-chain databases using zk-SNARKs and blockchain"；"off-chain execution, on-chain verification"；"executes **approved SQL query templates** over private data and generates succinct zero-knowledge proofs, while the blockchain verifies the proof against the **committed dataset state** without accessing raw records"；"selection, projection, sorting, Top-K, and group-by aggregation"；RLC / Grand-Product checks / pseudo-index；1,000 行 16.67 s、10,000 行 124.67 s、证明约 1 KB；与 ZKSQL、PoneglyphDB 对比。
- **核验状态：** **PARTIAL（仅摘要）**。凡需正文才能判断的字段（授权策略与查询验证是否明确区别、证明与模板绑定的具体机制、结果完整性机制）均标 `UNKNOWN`，不作为最终裁决依据。

## 8. S8 — nulltea/zk-SQL

- **地址：** https://github.com/nulltea/zk-SQL
- **代码 commit SHA：** `4c3626d383873fdd5e64e7fa874967d26cc61f96`（2022-07-28，教学 demo）。
- **核验状态：** **VERIFIED（源码）**；具备 `table_commitment + query + result` 三元组公共输入绑定（`ZKPQueryVerifier.sol:51-70`），但**无 Agent/授权/ACL/策略/principal 语义**，README 明言不限制调用地址；最后提交 2022 年。

## 9. S9 — sxt-proof-of-sql

- **地址：** https://github.com/spaceandtimelabs/sxt-proof-of-sql
- **代码 commit SHA：** `f28544df71c1afd04e4675ee4e798fa2a5f82551`（2026-10-28）。
- **核验状态：** **VERIFIED（源码）**；只做查询结果正确性与隐私，未发现授权 / ACL 语义。

## 10. S10 — QEDB

- **地址：** `qedb`（本地 clone 目录名；来源见 `evidence/source_manifest.json`）。
- **代码 commit SHA：** `dc5358aa5da557dced95b6f6f9c9f5d9f2161278`（2026-11-16）。
- **核验状态：** **VERIFIED（源码）**；只做查询结果正确性，未发现授权 / ACL 语义。

## 11. S11 — SIGMOD'18 查询认证 + 细粒度访问控制（★ 关键先例）

- **正式名称：** When Query Authentication Meets Fine-Grained Access Control: A Zero-Knowledge Approach
- **作者：** Cheng Xu, Jianliang Xu, Haibo Hu, Man Ho Au（Hong Kong Baptist University / Hong Kong Polytechnic University）
- **发表：** Proceedings of 2018 International Conference on Management of Data (SIGMOD'18)，16 页
- **DOI / 地址：** https://doi.org/10.1145/3183713.3183741 ；PDF（作者主页）http://www.comp.hkbu.edu.hk/~xujl/Papers/sigmod18_auth.pdf
- **本地证据文件：** `$TEMP/gate0-src/sigmod18_auth.pdf`（1,246,855 bytes）、`$TEMP/gate0-src/sigmod18_auth.txt`（99,849 chars，pypdf 提取）
- **G0.1 复核来源：** 作者主页 PDF `https://xuc.me/file/paper/SIGMOD18.pdf`（2026-11-25 重新下载全文核对，仅用于校正同一论文的章节口径，不新增来源记录）
- **精读章节：** §3 Problem Definition、§5 Equality Query Authentication、§7 Security Analysis、§9 Relaxing Zero-Knowledge、§11 Conclusion
- **核验状态：** **VERIFIED（全文 PDF，16 页）**
- **已核验事实（原文，见 CLAIMS_AND_EVIDENCE.md）：**
  - 三方模型（DO / SP / users），记录 `<o_i, v_i, Υ_i>`，CP-ABE 加密内容 + APP 签名认证；**G0.1 确认完整记录（含 `Υ_i`）外包给 SP，Algorithm 1 由 SP 使用 `Υ_oq(A)` 构造 VO**；
  - 安全定义同时含 **Soundness**（结果未被篡改、且符合用户角色）与 **Completeness**（未返回记录要么非结果、要么对该用户不可访问）——即"授权约束下的结果完整性"；
  - 三级机密性：**Data Content / Access Policy / Zero-Knowledge**，其中 Zero-Knowledge = "users can gain nothing about D\D+ (e.g., not even its size or the associated access policies)"；**G0.1 确认其保密受益方是 users，不是 SP**；
  - Definition 7.4 Unforgeability、Definition 7.5 Zero-Knowledge、Theorem 7.6（证明见附录）；
  - **G0.1 覆盖口径：** 覆盖 H1-U（对用户/合并 V 隐藏不可访问记录的 ACL 信息）与 equality/range/join 的行级结果完整性；**不覆盖 H1-S**（对不可信 SP/Prover 隐藏 ACL）；
  - **明确未覆盖：** 全文 `update` / `revocation` 命中为 0；aggregation 列为 future work；无 Agent、无独立授权请求证明、无独立 V 模型、无执行时证据。

## 12. S12 — agent-exec-binding-mvp（旧仓库，只读）

- **本地路径：** `D:\Research\agent-exec-binding-mvp`（origin `https://github.com/kaikai-cao/agent-exec-binding-mvp.git`）
- **核验分支 / SHA（本地 git 实测，R1）：**
  - main `f3048571268642696616d9f38c536d9449106918`
  - experiment/independent-execution-proxy `e327a9444ed8cea17baefbac01587b7fa77e8d39`
  - feat/step3-2b-plan-root-circuit `48169bc7d0d6dbaf231fb0d2944a8d85035c9e9c`（本地 checkout，工作区干净）
- **检查文件：** README.md；`research/threat-model-v0.1.md`；`research/security-properties-v0.1.md`；`research/e-stage-results-v0.1.md`；`independent_execution_proxy.py`；`_staging/e486-d1/D6_EXTERNAL_TOOL_SEMANTICS.md`；`_staging/e486-d1/D5_PROCESS_RESTART_VALIDATION.md`；`zk-v2-host/src/quota_circuit.rs`（文件存在性）
- **核验状态：** **VERIFIED（R1 源码/文档静态核对；E2.2 反例为 R2 引用）**
- **与本项目相关的既有覆盖：** 请求哈希 / 上下文哈希 / 策略哈希 / tool schema 哈希 / nonce / 签名 Grant / 回执绑定 / 计划级 Merkle Root / 有限 Halo2 配额电路；独立代理分支的远程 HTTP 查询代理、进程隔离、幂等 / INDETERMINATE 恢复语义；E2.2 自签虚假回执反例。
- **旧仓库已声明的边界（README 原文）：** "The tool server is a mock process and is trusted to sign truthful execution receipts. A signature authenticates the server's assertion; it does not independently prove that external data are true."；"A recent CVA study explicitly lists context-binding implementation and runtime execution binding as open problems."

## 13. S13 — pa-vfann-experiment（旧仓库，只读，仅记录相关结论）

- **本地路径：** `D:\Research\pa-vfann-experiment`，当前 HEAD `6ce5fc64afa847731d0613e5b1178a3dd6382eee`，分支 `exp08-agentic-trace-leakage-audit`（未修改）
- **相关内容：** `research/exp08-agentic-trace-leakage-audit/README.md` 的 HOLD 结论与三问速答第 3 问——"是否有合理密码学落点？尚不能确认……没有证据支持现在引入新的 ZK/PIR/ORAM 贡献。R0.2.1 强调查询隐私后端（A3）缺失是实验后端层的阻塞，但不得因此先定密码学机制再找问题。"
- **核验状态：** **VERIFIED（仅记录，不复制代码、不并入本项目）**
