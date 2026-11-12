# 产物生命周期与可证明销毁

每次脱敏运行都会留下五类产物。它们各有合规留存期限，到期后必须能**可证明地销毁**；其中假名映射库等同于明文钥匙，管控最严格。本模块把"留存 → 宽限 → 二次确认 → 抹除 → 入链凭证"做成一条可审计的状态机。

## 受管产物与默认留存期

| 类型 | 标识 | 默认留存 | 说明 |
|---|---|---:|---|
| 假名映射库 | `pseudomap` | 30 天 | 等同明文钥匙，默认留存最短 |
| 脱敏目标库 | `output` | 90 天 | 独立 SQLite 输出 |
| 断点记录 | `checkpoint` | 14 天 | 仅在可能续跑期间有用，最早到期 |
| 报告 | `report` | 180 天 | Markdown / JSON |
| 运行清单 | `manifest` | 180 天 | 策略指纹与输出哈希 |

默认宽限期 **7 天**。审计日志本身**不在**受管范围内：它是追加只增的，销毁事件要作为新记录写进去，销毁审计日志等于销毁销毁凭证。

## 留存策略文件

用 `--retention-policy` 传入 YAML，可全局调整每类产物的天数，并按数据集指纹单独覆盖：

```yaml
grace_days: 5            # 全局宽限期（天）
retention_days:          # 全局默认覆盖
  pseudomap: 10
  checkpoint: 7
datasets:
  "9f3c2a1b8d7e4f60":    # 数据集指纹（完整或前缀均可匹配，见下）
    grace_days: 2
    retention_days:
      pseudomap: 3       # 该数据集的映射只留 3 天
      output: 20
```

- 天数必须是 `>= 0` 的整数，未知产物类型会在加载时报错。
- 数据集覆盖以完整指纹匹配；清单里登记的是完整指纹。
- 不传策略文件时使用内置默认值。

## 状态机

```
ACTIVE ──留存到期──> PENDING（发放销毁令牌）
                      │  宽限窗口内可撤销
       revoke <───────┤
         │            │ 宽限结束
         ▼            ▼
      REVOKED     GRACE_EXPIRED（虚拟态，行仍为 PENDING）
         │            │ destroy 二次确认
         └ 留存重启    ▼
                   DESTROYED（凭证追加进审计链）

  抹除出错 ──> FAILED（保留现场与令牌；重跑续清）
```

- **PENDING 是可撤销的**：`revoke` 会清空令牌、把留存时钟重新计满，并把对应销毁批次项标记为 `skipped`，使之后的 `destroy` 不会再碰它。
- **宽限期结束后不可撤销**，只能确认销毁。
- **假名映射二次确认**：进入宽限时发放 `dtk-...` 销毁令牌，`destroy` 必须原样回传；令牌用恒定时间比较，防止时序侧信道。非映射类产物不需要令牌。

## 命令

```bash
# 只读预览：到期可安排 / 宽限中 / 宽限已过 / 被在途任务阻止
maskline lifecycle preview [--json]

# 把到期产物移入宽限窗口（发放令牌、写审计、建销毁批次）
maskline lifecycle schedule [--json]

# 宽限内撤销
maskline lifecycle revoke --artifact-id art-xxxx

# 宽限结束后销毁；映射类必须带令牌
maskline lifecycle destroy \
  --token art-xxxx=dtk-yyyy [--destruction-id dst-...]

maskline lifecycle list [--json]
maskline lifecycle batches
```

## 在途任务保护

销毁前会检查 `checkpoints.sqlite` 中所有 `running / interrupted / failed` 的 run：

- 断点库、假名映射库只要还有在途或可续跑 run，一律拒绝并列出 run_id；
- 某个输出/报告关联的 run 仍在途，同样拒绝；
- 拒绝原因会在 `preview` 的 `blocked` 项中说明，`schedule` 会跳过这些项，不建批次。

run 续跑完成（状态变 `completed`）后阻止自动解除。

## 可恢复的销毁（不留半删状态）

每个销毁批次在 `lifecycle.sqlite` 的 `destruction_items` 表里逐项记录 `pending / succeeded / failed / skipped`：

- 抹除到一半失败（如文件被占用），对应项保持 `failed`，产物行置 `FAILED` 并保留令牌，失败事件入审计链；
- 重新执行 `destroy` 时只挑所有未完成项继续，已成功的不重复处理，已撤销的自动跳过；
- 不存在"删了一半无法收口"的状态。

## 抹除方式与销毁凭证

`secure_erase` 在 `unlink` 之前先用密码学随机字节覆写整个文件并校验覆写确实落盘（覆写后哈希必须变化），同时处理 SQLite 的 `-wal / -shm / -journal` 旁路文件——它们可能含有最近写入的映射页。文件已不存在时视为已删除，保证重跑幂等。

每次成功销毁向审计链追加一条 `lifecycle.destroyed` 记录，包含：

- 销毁前内容哈希 `pre_hash`、覆写后哈希 `post_hash`、文件大小、旁路文件清单；
- 销毁时间、操作者、销毁批次号；
- 对上述负载计算的 `evidence_hash`，可独立重算核对。

销毁批次结束后重新校验整条审计哈希链，并在 `audit/certificates/` 写凭证（`latest.json` 与按批次号命名的不可变副本），凭证记录链头哈希。篡改任何一条生命周期事件都会让 `audit --verify` 在对应行失败。

## 测试用时钟

`MASKLINE_NOW`（ISO-8601）可把生命周期时钟固定到指定时刻，供集成测试驱动到期/宽限转换，生产环境不应设置。
