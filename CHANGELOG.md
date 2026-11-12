# Changelog

## Unreleased

多密钥与密钥标识（kid）轮换模型。

- 密钥文件支持 `keys:` 列表，每组假名密钥带 `kid` 与 `current` 标记；恰有一个 `current: true`，新映射一律使用当前密钥。
- 假名映射库每条记录保存生成时的 `kid`，主键改为 `(kid, token)`；同一人轮换前后的映射并存且互不干扰，`reveal` 按记录的 `kid` 选钥并做 HMAC 校验。
- 旧版无 `kid` 的映射库打开时自动迁移到默认 `kid: "default"`；旧版扁平密钥文件（`hmac_salt` / `pseudonym_key`）继续兼容，不报错拒绝。
- 密钥文件缺少当前生效标记、存在多个当前标记或 `kid` 重复时明确报错并指出问题条目，不再静默选择。
- 审计日志仅记录 `pseudonym_kid`，不写入任何密钥内容；新增 `scripts/rotate_key.py` 轮换脚本与端到端校验脚本 `scripts/verify_rotation_e2e.py`。

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
