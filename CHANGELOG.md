# Changelog

## v0.2.0

交付完整性核验。

- 新子命令 `verify --run-id`：流式重读目标库，按 manifest 逐批重算行数与校验和并比对，核对假名映射库计数/摘要与审计链完成事件；全部通过输出 OK（退出码 0），任何不一致指明具体表与批次（退出码 1），无法核验时退出码 2。
- run 结束现在记录每批行数与校验和（持久化在检查点库并汇总进 manifest，断点续跑可累积）、映射库记录数与内容摘要；策略含 `hash`/`pseudonym` 时校验和为带密钥 HMAC-SHA256（由 `hmac_salt` 派生、域分离），否则为无密钥 SHA-256。
- 密钥缺失时 verify 按文档承诺降级：只校验行数/结构/证据一致性/映射计数并醒目标注未覆盖内容列，降级通过退出码仍为 0 且审计事件记录 `degraded: true`。
- verify 对目标库、映射库、检查点库严格只读（`mode=ro` + `query_only`），无临时文件；每次核验结果作为 `event: verify` 追加进审计链。
- 审计完成事件新增 `event: run_completed`、`checksum_mode`、`pseudomap_count`、`pseudomap_digest` 字段。

## v0.1.0

首个可用版本，全部功能离线运行。

- 数据集登记：SQLite / CSV 内容指纹、表结构、行数，幂等入库。
- 敏感字段发现：手机号、邮箱、IPv4、身份证、银行卡、统一社会信用代码、中文姓名与地址；GB 11643、Luhn、GB 32100 校验；高/中/低置信度。
- 声明式 YAML 策略：严格校验未知数据集/表/列/转换器/参数，生成策略指纹。
- 六类转换器：mask、HMAC-SHA256 hash、generalize（日期/年龄/金额/地址）、pseudonym、nullify、round。
- 流式执行：分批读取、独立目标库、dry-run、rowid 断点、resume 续跑与幂等重跑。
- 可逆假名映射：物理独立映射库、跨运行确定性 token、reveal 子命令。
- 审计：追加式 JSONL 哈希链、头锚点、篡改/截断定位。
- 报告：Markdown / JSON，字段发现、策略、统计、抽样前后对比、未配置策略告警。
- 一键演示与固定种子合成数据生成器；测试覆盖核心模块。
