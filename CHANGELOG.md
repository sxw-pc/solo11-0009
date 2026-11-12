# Changelog

## Unreleased

- 目标写入抽象为可插拔输出目标（`maskline/pipeline/targets.py`），流式执行器与断点机制与目标解耦。
- 新增 CSV 目标（`run` / `demo` 增加 `--target-format csv`）：每张源表一个 CSV 文件，列顺序保持源表顺序，UTF-8 带表头，NULL 为空字段，分隔符/换行/引号按 RFC 4180 转义，数值按源列 SQLite 类型亲和性渲染。
- CSV 目标与 SQLite 目标共用批量流式写入与 rowid 断点：批次追加到 `.csv.part` 并由 `.csv.journal` 记录提交偏移，表完成后原子替换为正式文件；中断续跑按断点截断半成品（journal 丢失时流式扫描定位），不产生重复行或半截行，半成品丢失/损坏时按表安全重建。
- `resume` 从运行记录的输出路径自动识别目标类型；SQLite 目标行为、断点表结构与清单字段保持兼容，旧 checkpoint 可直接续跑。manifest 与审计条目新增 `target_kind` 键（纯新增）。

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
