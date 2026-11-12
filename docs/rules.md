# 规则版本、灰度试跑与回滚

maskline 的探测器规则（正则、词典、校验位）默认仍是一套全局内置规则集，行为与此前版本保持一致。在此之上，可以把调整后的规则登记为**不可变版本**，只对指定测试数据集做隔离试跑，验证准确率后再一键回滚或切换正式任务使用的版本。

## 核心模型

| 概念 | 说明 |
|---|---|
| `builtin-v1` | 内置规则快照，默认正式版本。等价于旧版 `detectors` 全局规则。 |
| 规则版本 | 通过规则包 YAML 登记，标签如 `mobile-v2`。创建时保存**完整探测器快照**，之后不会随源码变化。 |
| 正式版本 | `data/rules.sqlite` 中的 `active_version`。所有正式 `scan` / `run` / `resume` / `demo` 自动使用它。 |
| 灰度试跑 | 针对单个数据集，用指定版本扫描。结果只写入 `data/gray/<trial_id>/findings.sqlite`。 |
| 回滚 | 把正式版本切换到某个历史版本；所有后续正式任务立即使用该版本。 |

内置规则集与旧行为一致：不创建规则版本、不做回滚时，识别结果不会变化。

## 规则包格式

规则包是可选的新文件，**不需要修改任何已有策略文件或 Python 规则文件**：

```yaml
version: 1

# 版本标签：字母、数字、点、横线、下划线，且不能是 builtin-v1
rule_version: "mobile-v2"
name: "手机号规则收紧"
description: "示例：调整正则并新增一个工牌号探测器"

# 可选，默认 builtin-v1；也可以写 active 表示基于当前正式版本
base: "builtin-v1"

# 可选；若填写必须与执行 --actor 一致
# created_by: "alice"

detectors:
  # 复用已有探测器：只覆盖给出的字段
  mobile_phone:
    pattern: '(?<!\d)1[3-9]\d{9}(?!\d)'
    validator: none

  # 停用某个内置探测器（只影响本版本）
  ipv4:
    disabled: true

  # 调整中文姓氏词典
  person_name:
    surnames: "赵钱孙李周吴郑王"

  # 调整地址最小长度和匹配模式
  address:
    min_length: 8

  # 新增探测器（必须显式声明 kind）
  badge:
    kind: regex
    pattern: '(?<!\d)BADGE-\d{6}(?!\d)'
    value_pattern: 'BADGE-\d{6}'   # 见下方说明
```

### 可调整字段

通用键：`kind`、`disabled`。

| `kind` | 可用字段 |
|---|---|
| `regex` | `pattern`（必填）、`flags`、`validator`、`require_fullmatch`、`value_pattern`、`min_length`、`max_length` |
| `person_name` | `pattern`、`flags`、`surnames` |
| `address` | `pattern`、`flags`、`min_length` |

- `flags`：`i` / `m` / `s` / `x` 的组合，例如 `"i"`。
- `validator`：`none`、`id_card`、`luhn`、`ipv4`、`credit_code`。内置校验器在 `maskline/detectors/patterns.py` 中定义。
- `require_fullmatch`：要求匹配结果覆盖整个单元格（内置 `email` 即使用此行为）。
- `value_pattern`：用另一个正则对匹配结果做整串校验，用于自定义格式/校验规则。
- `min_length` / `max_length`：按匹配结果长度过滤。
- 对已有探测器，覆盖字段会继承基础版本中的其余配置；`kind` 不可变更。
- 新探测器必须提供 `kind` 和 `pattern`。
- 未知键、非法正则、未知校验器、非法 flags 都会在登记时立即报错，不会写入规则库。

## 登记规则版本

```bash
python -m maskline rules add --file rules/mobile-v2.yaml --actor alice
python -m maskline rules list
python -m maskline rules current
python -m maskline rules show --version mobile-v2
```

创建者由 `--actor` 决定（也读取 `MASKLINE_ACTOR`，否则使用系统用户名）。规则包若写了 `created_by`，必须与 actor 一致，防止冒用他人身份。

## 灰度范围与权限

只有规则版本的创建者可以：

- 调整该版本的灰度数据集范围；
- 把正式版本回滚到该版本。

```bash
# 允许非创建者在这些测试数据集上试跑（可重复 --dataset）
python -m maskline rules scope --version mobile-v2 \
  --dataset "demo.sqlite" --dataset "leads.csv" --actor alice
```

非创建者只有在灰度范围内才能试跑；不在范围内会收到权限错误。`builtin-v1` 是共享基线，不作为某个人的私有版本。

> `--actor` / `MASKLINE_ACTOR` 是操作者身份声明，不是密码认证。真实部署应结合操作系统账号、工作区文件权限或上层系统的登录鉴权来控制谁能使用某个 actor 名称。

## 灰度试跑

```bash
python -m maskline gray run \
  --rules-version mobile-v2 \
  --dataset data/raw/demo.sqlite \
  --actor alice \
  --sample-limit 200 \
  --cpu-limit 2 \
  --memory-mb 512
```

试跑行为：

- 只做字段发现，不执行 `execute_run`，因此不会触发正式脱敏流程。
- 结果只写入 `data/gray/<trial_id>/findings.sqlite` 和 `trial.json`。
- **不写** `data/meta.sqlite` 正式发现结果、`checkpoints.sqlite`、`pseudomap.sqlite`、manifest、报告。
- 源数据集以只读方式打开。
- 输出 high/medium 发现摘要和临时快照位置。

查看与清理：

```bash
python -m maskline gray list
python -m maskline gray show --trial-id gray-20261112-...
python -m maskline gray cleanup   # 立即清理过期快照
```

## 保留期自动清理

- 默认保留 **7 天**（`--retention-days` 可覆盖；`0` 表示立即过期）。
- 每次执行 `gray run` / `gray list` / `gray show` / `gray cleanup` 时会先做惰性清理，删除已过期试跑的整个临时目录和索引记录。
- 清理只删除位于 `data/gray/` 下、由本工具创建的试跑目录，拒绝越界删除。

## 失败与资源清理

以下场景不会留下临时数据：

- 规则包正则/校验器等语法错误：在登记阶段失败，不创建版本，不产生试跑资源。
- 指定数据集不存在或格式不受支持：在创建临时目录前失败。
- 试跑过程中任何异常：删除本次 `data/gray/<trial_id>/`，删除索引记录，并写入审计事件 `gray_trial_failed`（含 `cleaned_up: true`）。

## 资源限流

单个试跑默认最多使用 **2 核 CPU / 512 MB 内存**，可通过 `--cpu-limit`、`--memory-mb` 调整：

- CPU：POSIX `sched_setaffinity` 将进程限制在至多 N 个 CPU。
- 内存：POSIX `RLIMIT_AS` 地址空间上限。
- 退出时恢复原 affinity 与 rlimit；平台不支持时退化为记录 `*_enforced: false`，文件隔离仍然有效。
- 实际生效值写入试跑元数据和审计事件。
- 注意：灰度试跑在 CLI 进程内执行，限制作用于该进程；正式任务应使用独立进程/工作区以获得最强的 CPU 配额隔离。

## 一键回滚

```bash
# 正式任务切到历史版本 mobile-v2
python -m maskline rules rollback --version mobile-v2 --actor alice

# 回到内置基线
python -m maskline rules rollback --version builtin-v1 --actor alice

python -m maskline rules current
```

回滚只修改 `rule_state.active_version`。之后的 `scan` / `run` / `resume` / `demo` 会通过 `resolve_active_rule_set` 自动解析当前版本，无需重启或额外参数。断点续跑不会因规则版本切换而改变已有 run 的策略指纹语义；需要重新执行时请新开 run。

## 审计事件

所有规则版本/灰度/回滚操作都进入现有追加式审计链（`audit/audit.jsonl`）：

| 事件 | 触发时机 |
|---|---|
| `rule_version_created` | 登记新规则版本 |
| `gray_scope_updated` | 创建者调整灰度范围 |
| `gray_trial_started` / `gray_trial_completed` | 试跑开始/成功 |
| `gray_trial_failed` | 试跑失败并完成清理 |
| `gray_trial_expired` | 过期快照被自动清理 |
| `rule_rollback` | 正式版本切换 |

使用 `python -m maskline audit --verify` 可继续校验整条哈希链。
