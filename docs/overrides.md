# 人工裁定（overrides）指南

检测器是启发式工具，必有误报和漏报。overrides 让安全/数据负责人对具体列给出**人工裁定**，无需修改策略 YAML（策略只管执行、不管发现），也无需改代码。

## 文件位置

默认读取工作区根目录的 `overrides.yaml`；`scan` 与 `run` 也接受 `--overrides <path>` 指定其他文件，`--no-overrides` 完全忽略（包括默认文件）。`MASKLINE_HOME` / `--workspace` 决定工作区根目录。

没有该文件时行为与之前完全一致。

## 结构

```yaml
version: 1
description: optional human-readable note
overrides:
  - dataset: demo.sqlite          # 数据集匹配（同策略 YAML）
    table: customers              # 表名，大小写敏感
    column: address               # 列名，大小写敏感
    decision: force_not_sensitive # 或 force_sensitive
    reason: 该列仅为城市级地址，已人工确认不含门牌与姓名  # 必填，非空
```

| 键 | 必填 | 说明 |
|---|---|---|
| `version` | 是 | 固定为整数 `1` |
| `description` | 否 | 说明文字 |
| `overrides` | 否 | 条目列表；空文件等价于没有裁定 |
| `dataset` | 是 | 数据集规则，语义与[策略路径匹配](policies.md#顶层结构)完全一致 |
| `table` | 是 | 表名 |
| `column` | 是 | 列名 |
| `decision` | 是 | `force_sensitive` 或 `force_not_sensitive` |
| `reason` | 是 | 非空字符串，会进入报告、registry 与审计 |

未知键、空字段、未知 decision、`version` 非 `1` 都会在加载时报错并给出条目序号。

## 操作者

**生效裁定必须在审计中可追责**，因此：

- 当 overrides 文件里有至少一条条目时，必须提供操作者，否则报错退出；
- 操作者优先取 `--operator`，否则取环境变量 `MASKLINE_OPERATOR`；
- 该身份写入 registry 的 `adjudications` 表与审计事件；空文件不需要操作者。

```bash
export MASKLINE_OPERATOR="security-ops/alice"
python -m maskline scan data/raw
```

## 裁定语义

两条裁定的语义是**不对称**的，这是刻意设计：

| 裁定 | 发现结论 | 报告 | 执行层 |
|---|---|---|---|
| `force_sensitive` | 改为敏感，置信度提升为 `high`；保留检测器原始结论 | 标注「强制敏感」及理由 | 不改变策略；策略未覆盖时仍会进入「未配置策略告警」 |
| `force_not_sensitive` | 改为非敏感（`none`），不再误报 | 标注「强制非敏感」及理由 | **不改变策略**；若策略仍配置变换，告警并继续脱敏 |

### 冲突：裁定 force_not_sensitive 但策略仍配置变换

例如：某列被人工确认不是敏感字段，但策略 YAML 里仍写着 `mask`。此时：

- 报告「人工裁定冲突」一节列出该列、理由、策略转换器和「仍执行脱敏」；
- `scan`/`run` 控制台打印冲突提示；
- 报告 JSON 的 `adjudications.conflicts[]` 中 `execution: "masked"`；
- **默认且唯一的行为是继续脱敏**。宁可多脱，不能漏脱；不接受反向开关。

`scan` 不加载策略，因此只提示「本次扫描未检查策略冲突」；`run` / `resume` 会加载策略并给出上面的正式冲突告警。

要消除冲突，请同步修改策略 YAML（删除该列的变换）或撤销该条裁定。

### force_sensitive 不会自动加策略

发现结论与执行策略是两层。裁定为敏感只改变「发现/报告/registry」的结论；若该列没有策略变换，它在报告中会出现在「未配置策略告警」，提示你把策略补上。这避免一个只读的 overrides 文件悄悄改写执行计划。

## 重复与歧义

- 同一 `(dataset, table, column)` 出现两次：**直接报错**（不是「后者覆盖」）。重复几乎总是复制粘贴或合并产物错误，静默取舍不可接受。
- 两条 dataset 规则指向同一 table/column 且路径可能匹配同一数据集（如 `*.sqlite` 与 `demo.sqlite`）：报错要求消歧。
- 同一文件内条目顺序不影响结果（在无上述错误时）。

## 表结构变化：未匹配裁定

裁定是数据驱动的，表改名/删列后旧裁定可能不再匹配。**不会静默失效**：每次 scan/run 都会在控制台、报告与 JSON 中列出未匹配条目及原因：

- `kind: table` — 数据集存在但表不存在；
- `kind: column` — 表存在但列不存在（若存在大小写/标点仅差一处的唯一候选，会附加 rename 提示与当前列清单）；
- `kind: dataset` — 本次扫描的任何数据集都不匹配该条目的 `dataset` 规则（数据集改名或删除）。

未匹配裁定当前不产生任何效果，也不会被删除；请复核后更新或删除条目。

## 写入位置

一次 `scan`（以及 `run`/`resume` 内部的发现步骤）会：

1. 把**合并后的最终结论**写入 registry `findings`，同时保留 `detected_type` / `detected_confidence`；
2. 每条生效裁定写入 `adjudications` 表（操作者、时间、理由、裁定文件指纹、检测器结论、最终结论、策略冲突）；
3. 追加一条 `event: "adjudication"` 审计事件，包含 `operator`、`ts`、`override_fingerprint`、生效条目、冲突与未匹配条目、写入的 registry 行号。

`run` 的审计条目本身也包含 `operator` 与裁定摘要。`run` 内部的发现步骤不会额外产生裁定审计事件（避免同一次运行出现两条）。

`--dry-run` 只读：读取 overrides 并在内存中合并用于打印/统计，不写 registry、报告或审计，也不产生目标库。

## 查看

```bash
python -m maskline scan data/raw            # 控制台显示裁定与冲突
python -m maskline audit --verify           # 校验审计链（含裁定事件）
```

registry 路径：`data/meta.sqlite`，表 `findings`（每次扫描覆盖为该次有效结论）与 `adjudications`（追加式历史，保留每次裁定）。可以用任何 SQLite 客户端只读查询；请把该库视为内部元数据，不要随脱敏数据交付。

## 与策略指纹、断点续跑的关系

裁定不改变策略指纹，因此修改 overrides 后：

- 正常重跑 `run` 是安全的：报告、registry 与审计会反映新裁定；
- 用旧 run 的 `resume` 续跑会沿用已中断运行的执行计划；裁定只影响报告与发现结论，不会改变已开始执行的策略变换集合。若裁定涉及策略冲突，请先完成当前 run，再重跑以更新报告。
