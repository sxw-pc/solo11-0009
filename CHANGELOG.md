# Changelog

## Unreleased

- 增量扫描：registry 升级到 schema v2，新增表级结构指纹与列级内容指纹。未变更表/列
  逐字节沿用历史 findings，加列/删列/单列值变化只重检受影响列，行数显著变化（默认
  >50%）或 detector 版本/sample_limit 变化才整表重扫；`scan --full` 可强制全量。
- v1 registry 自动迁移：打开旧库时在单事务内迁移到 v2，失败回滚、可重试；遇到更新
  版本的 registry 抛出明确的 `RegistryVersionError`。
- 中断安全：每个数据集的增量写入包在单个事务中，Ctrl-C 回滚，残留的 running 扫描
  记账行在下次扫描时自动清理，不参与复用判定。
- 设计文档：`docs/incremental-scan.md` 说明指纹粒度取舍（表级结构 + 列级内容）及
  各项承诺。

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
