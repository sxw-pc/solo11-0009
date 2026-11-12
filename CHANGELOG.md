# Changelog

## v0.2.0

异常退出脏资源自动识别与清理，全部离线完成。

- 运行锁：每个 run 持有 `data/locks/<run_id>.lock` 的 `flock` 排他锁，进程死亡（含 SIGKILL）由内核自动释放，清理器据此精确区分"活跃运行"与"异常退出残留"；并发 resume/清理不会误伤彼此。
- 脏资源识别：`failed` 与失去锁持有者的 stale `running` 判定为脏；`interrupted` 合法断点与 `completed` 正式产物一律保留；源数据集与 manifest 记录的产物永不被触碰。
- 清理能力：`maskline clean`（`--dry-run` / `--min-age-seconds` / `--min-free-bytes`），回收半成品目标库（含 `-wal`/`-shm` 侧车文件）、无记录孤儿输出、失效断点与锁文件；磁盘空间不足时最旧优先；全程幂等且跨进程串行。
- 假名映射归属：新增 `pseudonym_refs` 引用表与 `run_id` 归属列，清理只删除仅被脏 run 引用且由其创建的映射条目，共享条目与历史条目保留。
- 失败现场保留：清理前把 run 记录、断点、输出状态、失败原因写入 `data/cleanup/<run_id>.json`，便于排查。
- runner 现在先写 run 记录再建目标库（崩溃不再产生无记录孤儿文件），失败时记录 `status_detail`、属主 pid/主机名；续跑校验失败不再把合法断点降级为 failed。

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
