# 资源配额管控（governor）

面向普通办公电脑的**离线脱敏任务资源配额与调度管控层**。它把已有的三类能力——
流式批处理执行、断点续跑、任务状态存储——整合到一个独立守护进程之下，在不修改
现有脱敏任务执行命令的前提下，提供 CPU / 内存 / 运行时长三类配额、FIFO 排队、
自动降速、自动暂停落断点、资源释放后自动恢复，以及全程操作留痕与实时资源查询。

所有逻辑运行在本地，仅依赖 Python 标准库与项目已有的 PyYAML，**不引入任何外部
调度组件、不发起网络请求**。

## 1. 架构

```
                         maskline governor start（守护进程 / PID 锁）
                                          │
                  ┌───────────────────────▼────────────────────────┐
                  │                   Scheduler                     │
                  │  FIFO 准入 · 并发槽位 · 配额采样 · 降速/暂停/恢复 │
                  └───┬───────────────┬───────────────┬────────────┘
                      │               │               │
            ┌─────────▼──────┐ ┌──────▼───────┐ ┌─────▼──────────────┐
            │ governor.sqlite│ │ /proc 采样器  │ │ 审计哈希链 audit.jsonl│
            │ 队列/配额/样本  │ │ CPU·RSS·内存  │ │ （与脱敏运行共用）    │
            └────────────────┘ └──────────────┘ └────────────────────┘
                      │
        每个任务一个独立进程组（start_new_session）
                      │
        ┌─────────────▼──────────────┐
        │ maskline run（现有命令原样）│── 每批提交 + rowid 检查点
        │ MASKLINE_PROGRESS_FILE 事件 │── checkpoints.sqlite
        └────────────────────────────┘
```

### 为什么用独立子进程而不是线程内调度

- **故障隔离**：单个任务 OOM 或崩溃不会拖垮管控器；异常时直接向整个进程组发信号，
  保证该任务占用的 CPU、内存全部释放，不留下孤儿子进程。
- **透明接入**：任务以提交时的原生命令行启动，任务本身无感知、无需改造。
- **复用既有断点机制**：暂停只在批边界优雅终止，此时检查点已落盘；恢复时用同一
  `run_id` 调 `maskline resume`，从最后提交的 rowid 继续，天然满足「不重复、不丢失」。

## 2. 配额模型与处置动作

| 配额 | 判定 | 超限处置（逐级升级，全自动） |
| --- | --- | --- |
| `cpu_max_percent` | 连续采样高于上限 | 先 `SIGSTOP/SIGCONT` 占空降速；持续超限升级为暂停落断点，冷却后自动恢复 |
| `memory_max_mb` | 进程树 RSS 超阈值，或系统可用内存占比过低 | 立即在批边界暂停，等待系统内存回落后自动恢复 |
| `max_runtime_seconds` | 单个执行切片的**流水线执行时长**到点（不含进程启动预热） | 暂停并持久化断点，冷却后以同一 run_id 续跑 |

要点：

- **预热不计入运行时长**。子进程解释器加载、数据集扫描与敏感探测发生在
  `execute_run` 创建运行记录之前；调度器只在任务通过 `MASKLINE_PROGRESS_FILE`
  上报 `run_id` 后才启动切片计时，避免任务在产生可续跑断点前就被杀掉。
- **暂停即一致性点**。runner 在每批目标库提交之后才写 rowid 检查点，SIGTERM 只会
  在两批之间被响应；强杀兜底（SIGKILL）也依赖最后一次已提交检查点，恢复语义不变。
- **排队不报错**。运行/降速/暂停态任务占用并发槽位；超过 `max_concurrency` 的任务
  保持 `queued`，按 `created_at` FIFO 依次准入。暂停任务保留其槽位，恢复时不受准入
  闸门限制，因此单任务在并发度为 1 时也能正常自愈。

## 3. 任务状态机

```
queued ──► running ◄──► throttled
             │  │          │
             │  └──────────┴──► paused ──► running（自动 resume）
             ▼                    │
        completed/failed      failed / cancelled（终态）
```

所有状态迁移都经 `GovernorStore.transition` 校验，非法跳转直接报错；守护进程自身被
杀掉后重启时，`reset_orphans_on_start` 会把残留的 `running/throttled` 任务统一转为
`paused` 并按检查点自动续跑。

## 4. 配置：全局默认 + 单任务自定义

见 [`configs/governor.example.yaml`](../configs/governor.example.yaml)。配额解析优先级：

```
内置默认  <  defaults 块  <  jobs.<任务名>  <  提交时 --quota 显式覆盖
```

运行期还可通过 `governor quota` 动态调整：全局默认写入 `governor.sqlite` 的 settings
表并对后续新任务生效；单任务覆盖直接更新该任务记录。两类调整都会写入审计哈希链。

## 5. 命令用法

```bash
# 1. 前台启动管控守护进程（PID 锁保证单实例）
maskline governor start --workspace <工作区> --config configs/governor.example.yaml

# 2. 用「现有命令原样」提交任务，放在 -- 之后；无需修改任务命令
#    （--workspace/--config 与其它 maskline 子命令一样放在动作动词之后）
maskline governor submit --workspace <工作区> --name daily-leads -- \
  maskline run --dataset data/raw/demo.sqlite \
    --policy policies/example.yaml --output data/out/demo.masked.sqlite

# 提交时临时覆盖配额（可重复）
maskline governor submit --workspace <工作区> \
  --quota cpu_max_percent=30 --quota memory_max_mb=512 -- \
  maskline run --dataset big.sqlite --policy p.yaml

# 3. 实时查看所有任务的资源占用与配额使用（也支持 --json）
maskline governor ps --workspace <工作区> --all

# 4. 配额调整（留痕）
maskline governor quota --workspace <工作区> --global --set memory_max_mb=4096
maskline governor quota --workspace <工作区> --job <job_id> --set cpu_max_percent=20

# 5. 取消任务（终止整个进程组并释放全部资源）、重载配置、查看守护状态
maskline governor cancel --workspace <工作区> <job_id>
maskline governor reload --workspace <工作区>
maskline governor status --workspace <工作区>
```

### 通用（非 maskline）命令

`submit` 默认自动识别原生 `maskline run/resume`（支持控制台脚本、`python -m
maskline`、解释器绝对路径等写法）。对非 maskline 命令，恢复时原样重放命令，由命令
自身基于检查点幂等续跑；也可显式 `--resume-mode generic|maskline` 控制。

## 6. 断点一致性保证

- 暂停路径只调用优雅终止，runner 在批提交后才持久化 rowid；恢复走
  `maskline resume --run-id <同一 run_id>`，重复批次通过「删除区间后重插」保证至少一次
  执行不产生重复行。
- `tests/governor/test_native_integration.py` 端到端验证：一个真实脱敏任务在多次
  配额暂停/自动恢复后，目标库内容哈希与一次不间断运行**逐字节一致**，且行数完全相等。
- 任务异常退出（非零码）时先 `killpg` 释放整个进程组，再按最后检查点排队续跑，超过
  `max_resume_attempts` 才标记 `failed` 并保留日志尾部用于排障。

## 7. 操作留痕

管控事件复用与脱敏运行同一条防篡改追加式哈希链（`audit/audit.jsonl`），以
`governor_event` 字段区分类型：`job_submit / job_start / job_throttled / job_paused /
job_resumed / job_completed / job_failed / job_cancelled / quota_updated /
config_reloaded / daemon_start / daemon_stop / orphan_recovered`。
`maskline audit --verify` 可对包含管控事件在内的整条链做完整性校验。

## 8. 离线与可移植性

- Linux 下 CPU/RSS/系统内存全部直接读取 `/proc` 与 `/proc/meminfo`，进程树通过
  `/proc/<pid>/stat` 的 PPID 聚合，无第三方依赖。
- 非 Linux 平台提供基于标准库的降级采样（内存精度下降，调度逻辑不变）。
- 全部状态保存在工作区 `data/governor.sqlite`（WAL 模式、带轻量列迁移），守护进程
  重启后可仅凭磁盘状态重建队列与续跑计划。
