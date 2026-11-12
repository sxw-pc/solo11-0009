# 增量扫描（Incremental Scan）设计说明

本文档说明 `maskline scan` 的增量检测机制：指纹模型、复用判定、旧 registry 迁移与
中断安全承诺。代码入口为 `maskline/detectors/incremental.py`，持久化在
`maskline/registry.py`（schema v2）。

## 1. 要解决的问题

全量扫描每次都会对所有表的所有列重新采样、打分。对于「200 张表里只有一张表加了
一列」这类日常变更，绝大多数计算是浪费；而且重扫会用新结果覆盖 registry 里人工核对
过的历史 findings。增量扫描的目标是：**没变的对象不重算，结论逐字节沿用；只对真正
变化的部分重新检测。**

## 2. 指纹粒度：为什么是「表级结构指纹 + 列级内容指纹」

需求允许在表级与列级指纹之间取舍。本实现采用混合方案，理由如下。

### 2.1 检测证据的天然边界是列，不是表

detector 的采样、打分、置信度、候选证据全部按列产出并按
`(dataset, table, column)` 存储。findings 的复用单元因此天然是列：复用一列就意味着
它的整条 finding 记录（含 `score`、`confidence`、`candidates_json`、`updated_at`）
原样保留。若只做表级内容指纹，表内任意一格变化都会使整表哈希失效，无法区分「加了
一列」与「某列改了一个值」，只能整表重扫，新加的列也无法被单独识别。

### 2.2 结构信息以表为单位哈希最划算

列的增删、改类型、改名首先是**表结构**事件。把一张表的全部列描述符（列名、声明
类型、可空性）做一次规范化哈希，得到表级 `structure_fingerprint`，一次比较即可判断
结构是否变化；结构变化时再逐列对比描述符定位到具体列。这样既保留了 O(表数) 的快速
路径，又能在变化发生时下钻到列。

### 2.3 列级内容指纹不增加 I/O

SQLite/CSV 的指纹计算本来就要对数据集做一次完整的流式遍历（见
`registry._sqlite_fingerprint / _csv_fingerprint`）。列级哈希只是在这同一次遍历里为
每列额外维护一个 hasher，逐行把该列的规范化值喂进去，不产生第二次数据读取。表级
`content_fingerprint` 再由各列哈希派生（对「列名→列哈希」映射做规范化哈希），用于
整表内容的快速等值判断。

### 2.4 结论

| 维度 | 选择 | 用途 |
|---|---|---|
| 结构指纹 | **表级** | 一次比较判断结构是否变化 |
| 内容指纹 | **列级** | 精确定位值发生变化的列；支撑加列/删列/单列变更 |
| 表内容指纹 | 列哈希派生 | 整表内容等值快速判断，避免逐列比对 |
| 数据集身份 | 解析后路径的哈希 `dataset_id` | 内容变化后仍能关联同一数据集的历史版本 |

纯表级方案会在加列场景退化为整表重扫；纯列级方案则让「结构是否变化」失去快速路径
且无法表达整表等值。混合方案在单次 I/O 内同时拿到两种粒度，是当前采样式检测器下
复用粒度与计算成本的最佳平衡。

## 3. 指纹定义（v2）

所有哈希均为 SHA-256，输入经 `utils.canonical_json` 规范化（排序键、无空白、
`ensure_ascii=False`），SQLite 值经 `normalize_sqlite_value` 归一（bytes、NaN、
inf 等有确定性表示）。

- 列结构指纹：`sha256("maskline-column-v2\0" + canonical(列描述符))`
- 表结构指纹：`sha256("maskline-table-structure-v2\0" + canonical([列描述符...]))`
- 列内容指纹：以 `maskline-column-content-v2\0 + 列名 + \0` 初始化，逐行追加
  `canonical(该列规范化值) + "\n"`（NULL 也参与，空表得到仅含前缀的确定性哈希）
- 表内容指纹：`sha256("maskline-table-content-v2\0" + canonical({列名: 列内容指纹}))`
- 数据集整体指纹：沿用 v1 的全量行流哈希，保持 manifest/runner/审计侧的既有语义不变

## 4. 扫描判定逻辑

对每张表，与 registry 中该 `dataset_id` 的上一版本比较，产出一个动作：

| 动作 | 触发条件 | 行为 |
|---|---|---|
| `reuse` | 结构指纹、表内容指纹、行数全部一致 | 不读数据、不打分；findings 原样保留（`updated_at` 都不变） |
| `rescan_columns` | 结构变化（加列/删列/改类型）或同构下内容变化，且行数变化未超阈值 | 只对新增/变化的列采样打分，其余列 findings 逐字节沿用；删除列的 finding 被清除 |
| `rescan_table` | 行数相对变化超过阈值（默认 50%）、detector 版本或 sample_limit 变化、无可用基线 | 整表所有列重新打分 |
| `new_table` | 该数据集此前没有这张表 | 整表打分 |

行数阈值由 `DEFAULT_ROW_COUNT_CHANGE_RATIO = 0.5` 控制。它是一条**保守的安全网**：
采样取的是确定性前缀样本（见下节），行数大幅变化意味着前缀样本的代表性可能改变，
此时即使列哈希能定位变化，也对整表重新打分以保证结论可靠。阈值内的行数变化仍走列级
定位。

### 4.1 采样随机性与结论漂移

检测器使用 `detectors/base.py` 的 `text_sample`：取清洗后非空值的**确定性前缀**
（SQLite 按 `rowid`、CSV 按文件顺序），代码路径中不存在随机数。因此：

- 未变更的表/列不会被重新采样，结论在存储层逐字节复用，不可能漂移；
- 即使将来引入随机采样，`reuse` 路径根本不调用采样器，未变更对象依然不受影响；
- 只有被判定为变化的列/表才会重新打分，这是预期内的结果更新。

### 4.2 detector 版本与采样预算

每条表指纹记录 `detector_version` 与 `sample_limit`。检测器打分语义变化时提升
`DETECTOR_VERSION`，或用户调整 `--sample-limit`，都会让该表降级为 `rescan_table`，
杜绝跨评分口径复用证据。

## 5. Registry schema 与旧版本迁移

### 5.1 v2 表结构

- `schema_meta`：schema 版本戳（当前 `2`）与迁移来源
- `dataset_records`：以 `dataset_id`（路径哈希）为主键，记录当前内容指纹与表清单；
  同一数据集内容变化后更新同一行而非新增
- `table_fingerprints`：每表的结构/内容指纹、列清单（含列级哈希）、采样预算与
  detector 版本
- `findings_v2`：按 `(dataset_id, table, column)` 存储检测证据
- `scan_runs` / `scan_table_actions`：扫描运行与每表动作的审计记录
- `datasets` / `findings`：保留的 v1 表，迁移期间只读不删

### 5.2 v1 → v2 自动迁移

打开 registry 时：

1. 无任何表 → 直接建 v2 schema；
2. 存在 v1 的 `datasets` 表且无 `schema_meta` → 在**单个事务**内建 v2 表并拷贝数据
   （DDL 使用逐条 `execute` 而非 `executescript`，因此 DDL 也参与事务、可回滚）；
3. `schema_meta` 版本高于本构建支持的版本 → 抛 `RegistryVersionError`，给出明确
   升级提示，而不是崩溃或误读。

v1 registry 没有列级内容哈希，迁移后的表指纹以空内容指纹 + 空 detector 版本标记，
首次 v2 扫描会据此对所有表做一次 `rescan_table` 重建基线，之后才进入增量模式。v1
表与数据在迁移后原样保留，迁移失败时整个事务回滚，旧库不受影响、可重试。

## 6. 中断安全

一个数据集的全部增量写入（scan 运行记录、数据集记录、表指纹、findings 增删）包在
单个 `BEGIN IMMEDIATE` 事务中：

- Ctrl-C / 任意异常 → `ROLLBACK`，registry 回到上一次成功扫描的完整状态；
- 不存在「写了一半的指纹」或「部分新 findings 混着旧 findings」的状态；
- `scan_runs` 中可能残留 `running` 记账行，下一次扫描开始时由 `reap_stale_scans()`
  清理；它不参与任何复用判定，因此不会污染后续扫描。

## 7. CLI

```bash
# 默认增量扫描：未变更表沿用 findings，只重检变化部分
python -m maskline scan data/raw

# 忽略所有缓存指纹，对全部列重新打分（仍写入同一套 v2 表）
python -m maskline scan data/raw --full
```

扫描输出会分别打印表级（reused/rescanned/new）与列级（reused/scanned）统计，便于
确认本次实际工作量。

## 8. 验收场景对应关系

| 验收场景 | 判定动作 | 承诺 |
|---|---|---|
| 无变更重扫 | 全部 `reuse` | findings 逐字节一致（含时间戳），采样器不被调用 |
| 加列 | 该表 `rescan_columns`，仅新列打分 | 新列被识别并单独检测，其余列 findings 不变 |
| 删列 | 该表 `rescan_columns` | 旧列 finding 被删除，其余不变 |
| 行数翻倍 | 该表 `rescan_table` | 变化表重新打分，未变化表全部复用 |
| 扫描中 Ctrl-C | 事务回滚 | 下次扫描从上次完整状态恢复，无残留污染 |
| 旧 v1 registry | 自动迁移 | 首次全量重建基线后增量；新版本库给明确报错 |
