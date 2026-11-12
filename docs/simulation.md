# 策略影响仿真评估

在不修改原始数据、不生成正式脱敏产物的前提下，对指定数据集执行一次「仿真脱敏」，量化规则调整对业务可用性的影响。仿真能力复用现有的敏感识别、声明式策略解析和数据采样三类能力，因此**与正式脱敏管道支持完全相同的策略语法和六类转换器**。

## 解决的问题

调整脱敏规则后，过去只能等全量任务跑完才能判断脱敏数据是否还能支撑统计与关联分析。仿真用一次低成本、可重复、可对比的评估回答四个问题：

1. **脱敏覆盖率**：每个字段的非空取值有多大比例真的被改变；
2. **取值分布偏移度**：PSI（群体稳定性指数）与 Jensen-Shannon 散度，附空值率、基数保留和高频取值变化；
3. **跨表关联保留率**：指定关联字段对在脱敏前后的多重集重叠比例，直接暴露关联断裂；
4. **核心业务指标偏差率**：数值列脱敏前后的总和、均值、最值偏差（全量流式统计，而非仅样本）。

## 命令

```bash
# 单次仿真（结果默认持久化，便于后续版本对比）
python -m maskline simulate \
  --dataset data/raw/demo.sqlite \
  --policy policies/example.yaml \
  --sample-size 10000 \
  --linkage orders.customer_id=customers.customer_id \
  --kpi orders.amount --kpi customers.balance

# 与同一数据集的上一次仿真结果做版本对比
python -m maskline simulate-diff --current sim-20260101-120000-ab12cd

# 也可以显式指定对比基线
python -m maskline simulate-diff \
  --current sim-20260101-120000-ab12cd --previous sim-20251231-100000-ef34ab
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--sample-size` | 每表蓄水池采样上限，默认 10000；边缘取值会额外确定性纳入 |
| `--batch-size` | 流式读取批大小，默认 1000 |
| `--file-size-threshold` | 单文件字节阈值，超过即切换小批流式模式，默认 100 MiB |
| `--linkage` | 跨表关联字段对 `表.列=表.列`，可重复传入 |
| `--kpi` | 需要评估业务指标偏差的数值列 `表.列`，可重复传入 |
| `--temp-root` | 临时资源根目录，默认 `MASKLINE_SIM_TMP` 或 `<工作区>/data/sim-tmp` |
| `--no-detect` | 跳过敏感识别摘要 |
| `--no-save` | 不写入仿真结果库（无法再做版本对比） |
| `--no-report` | 只向 stdout 输出结构化 JSON，不写报告文件 |

## 指标定义

### 脱敏覆盖率

```
coverage_rate = 采样中被改变的非空值数 / 采样非空值数
```

样本覆盖率会结合全量流式统计到的非空值总数，换算出整表的 `changed_values_estimated`。`estimated: true` 表示该结果由样本变化率推算。

### 取值分布偏移度

- **PSI**：按脱敏前后的取值频率分桶计算，零频率桶以 `1e-4` 平滑，避免除零并惩罚消失的取值。经验上 PSI < 0.1 偏移轻微，0.1–0.25 中等，> 0.25 显著；
- **JS 散度**：取值范围固定在 `[0, ln2]`，作为 PSI 的交叉验证；
- 同时给出空值率前后值、去重基数保留率和前后 Top5 取值。

### 跨表关联保留率

对每个 `--linkage` 指定的字段对，在采样集合上计算多重集交集：

```
retention_rate = 脱敏后重叠行数 / 脱敏前重叠行数
```

`fully_broken: true` 表示脱敏前存在可关联取值、脱敏后重叠为零——即关联字段完全断裂（例如外键被单侧假名化或置空）。未配置脱敏的关联键保留率为 1.0。

### 业务指标偏差率

数值列在**全量流式遍历**中累加总和、均值、最小值、最大值：

```
sum_deviation_rate  = |sum_after - sum_before| / |sum_before|
mean_deviation_rate = |mean_after - mean_before| / |mean_before|
```

基线为零的情况按「两侧都为零记 0、否则记 1」处理。非数值列不产出 KPI 指标；脱敏后变为非数值（如金额被 `mask`）会如实反映为 100% 偏差。

## 采样与内存边界

- 每张表采用 Algorithm R 蓄水池采样，内存占用与 `--sample-size` 成正比，与表大小无关；
- 在蓄水池之外，对每个策略覆盖列确定性记录边缘行（空值/空串、最短、最长、数值最小、数值最大）的 rowid，并在采样后按 rowid 有限回读，保证边缘取值场景不被随机采样遗漏；
- 单文件超过 `--file-size-threshold` 时自动切换 `streaming` 模式（小批读取，500 行/批），报告中会列出进入流式模式的表；
- KPI 数值累加器在全量流上工作，只保留标量计数，不缓存整列。

## 资源隔离与清理

- 每次仿真在临时根目录下创建独立的 `0700` 临时目录，临时假名映射库、暂存文件全部位于其中；
- 多个仿真并发运行时目录互不重叠，临时假名库互不可见；
- 无论成功或失败，结束时自动 `shutil.rmtree` 清理整个临时目录；启动时还会清扫超过 24 小时的残留目录；
- 仿真**从不**写入正式输出目录 `data/out`，也不写正式的 `checkpoints.sqlite`、`pseudomap.sqlite` 或 manifest；
- 持久化结果只写入独立的 `data/simulations.sqlite`，报告写入 `reports/<sim_id>.sim.{md,json}` 与 `reports/<sim_id>.compare.{md,json}`。

## 审计留痕

所有仿真操作（含规则校验失败、源文件不可读等失败尝试）都向同一条追加式 JSONL 哈希链追加条目，`event_type` 为 `policy_impact_simulation`，与正式脱敏运行共用 `audit/audit.jsonl` 并可通过 `maskline audit --verify` 统一校验。审计追加使用跨进程排他文件锁，并发仿真不会破坏哈希链。仿真条目的 `output_path`/`output_hash` 恒为 `null`，明确区分于正式脱敏产物。

## 异常场景约定

| 场景 | 行为 |
|---|---|
| 源文件只读 | 通过 SQLite `mode=ro` / 只读句柄访问，仿真正常完成，源文件不变 |
| 规则校验不通过 | 仿真前置失败，退出码 2，写入 `status=failed` 审计条目，不产生临时残留 |
| 采样数据为空（空表） | 仿真完成但状态为 `completed_with_warnings`，告警写入报告与审计 |
| 策略含 hash/pseudonym 但无密钥 | 明确报错要求提供 `MASKLINE_SECRET_FILE` |
| 关联/KPI 引用不存在的表或列 | 仿真前置失败并给出具体字段名 |
| 并发仿真 | 临时目录隔离 + 审计文件锁，结果库按仿真 ID 独立写入 |

## 与正式脱敏任务的资源关系

仿真不创建目标库、不登记正式 manifest、不占用检查点或正式假名库，因此不会与 `maskline run` 产生写冲突。它对源数据只读，对共享资源的写操作仅限：仿真结果库（独立 SQLite，WAL + busy timeout）、审计链（加锁追加）和报告目录（按仿真 ID 命名的新文件）。
