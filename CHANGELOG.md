# Changelog

## Unreleased

- 假名映射写入改为原子且幂等：同一原文/同一 token 重复执行不新增、不覆盖条目。
- 并发写同一个 `pseudomap.sqlite` 时使用冲突处理与 busy timeout，避免 `UNIQUE constraint` 与 `database is locked`。
- 新增 `pseudonym_map_operations` 操作台账（不含原文），审计条目的 `mapping` 字段记录本次运行的插入、复用、冲突及可追溯操作。
- 兼容旧版映射库表结构；旧库可直接读取、还原并继续追加，无需重新生成。
- 审计日志的追加与校验增加跨线程/跨进程文件锁，避免并发运行破坏哈希链。

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
