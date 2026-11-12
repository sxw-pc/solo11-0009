# Changelog

## Unreleased

跨运行关联追溯（lineage），全部功能离线运行。

- **关联 ID**：新增由数据集内容指纹确定性派生的 `correlation_id`（`maskline.lineage`），同一份源数据集的多次脱敏运行、不同策略版本、中断后续跑共享同一 ID；纯函数派生，无中心协调，多进程并发不会冲突。
- **lineage 库**：新增 `data/lineage.sqlite`，把 registry 的数据集指纹、checkpoint 的运行/策略版本元数据与审计链的 seq/entry_hash 指针打通；中断、失败但未产生审计条目的运行也可被追溯。
- **审计链兼容**：仅向新审计条目追加 `correlation_id` 字段，哈希链结构、字段哈希算法、head 锚点逻辑完全不变；旧版本生成的无该字段 JSONL 照常通过 `audit --verify`，查询时按需派生 ID。
- **审计校验增强**：`audit --verify` 在原哈希链校验之上叠加关联 ID 语义校验；篡改关联 ID 先被哈希链捕获，重算哈希后仍被语义校验拒绝。
- **新查询入口**：`maskline trace --dataset/--fingerprint/--correlation [--json]` 拉出同一源数据集所有关联运行的全链路事件（审计事件 + 未收尾运行事件）。
- **断点续跑一致性**：checkpoint `runs` 表新增 `correlation_id` 列（带旧库自动迁移）；续跑复用同一 run_id 与 correlation_id，发现关联 ID 被改会拒绝续跑。
- **并发安全**：审计追加增加 `fcntl` 咨询文件锁（不改变链格式），meta/checkpoint/pseudomap/lineage SQLite 统一启用 WAL 与 busy_timeout，支持多进程并发运行而不产生 seq 或关联 ID 冲突。
- 单条审计记录仅新增约 30–41 字节（实测膨胀约 3.3%，远低于 10% 上限）。

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
