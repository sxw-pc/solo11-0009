# Changelog

## v0.2.0

- 人工裁定层：新增 `overrides.yaml`（`force_sensitive` / `force_not_sensitive` + 必填理由），扫描时与检测器结果合并，报告和 registry 标注裁定与理由。
- 裁定冲突策略：`force_not_sensitive` 不改变执行计划；策略仍配置变换时告警并继续脱敏（宁可多脱，不漏脱）。
- 未匹配裁定显式提示：列改名、列删除、数据集消失都会在 scan 输出与报告中列出，附原因与列名提示。
- 重复/歧义裁定在加载时报错，不做后者覆盖。
- registry 新增 `adjudications` 历史表；`findings` 保留检测器原始结论（`detected_type`/`detected_confidence`）。
- 审计新增 `event: adjudication`（操作者 `MASKLINE_OPERATOR`、时间、理由、裁定文件指纹、registry 行号）；run 审计条目也带裁定摘要。
- CLI：`scan` / `run` / `resume` 支持 `--overrides`、`--no-overrides`、`--operator`。

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
