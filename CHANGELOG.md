# Changelog

## Unreleased

报告一致性与执行留痕增强（保持 Markdown / JSON 默认字段结构，旧报告仍可解析）：

- Markdown 与 JSON 报告改为由同一个内存报告对象渲染，统计字段逐字段一致；新增双格式解析入口 `maskline.report.load_report()`，旧版本报告缺失字段按默认值补齐。
- 报告生成前与检查点、manifest、审计头锚点、假名映射库条目数、输出库实际内容哈希逐项交叉校验，不一致时抛出 `ReportConsistencyError`，拒绝生成对不上的报告。
- 审计条目在报告之前追加，报告记录真实的 `audit_seq` 与 `audit_anchor`；审计条目扩展 `skipped_rows`、`pseudomap_entries`、`resumed`、`events` 字段并纳入哈希链保护（纯增量，旧校验器不受影响）。
- 检查点库新增 `run_events` 执行事件表与 `skipped_rows` / `skipped_rowids_json` 列，旧库打开时自动迁移；完整记录运行启动、中断、恢复、完成/失败节点。
- 新增异常行跳过：CSV 列数不匹配或转换器报错的行计入 `skipped_rows` 并持久化跳过 rowid，多轮中断-恢复不重复计数，跳过原因只保留有界样本。
- 大数量级优化：存储初始化跳过已存在的 DDL，内容哈希使用复用编码器与标量快速路径；报告生成不随行数线性增长内存。

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
