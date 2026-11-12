# 策略编写指南

策略是声明式 YAML。maskline 在执行前会解析并严格校验整份策略；错误会指出数据集、表、列或参数位置。

## 顶层结构

```yaml
version: 1
name: customer-masking
description: optional human-readable note
datasets:
  - path: "demo.sqlite"
    tables:
      customers:
        columns:
          full_name: {transformer: pseudonym}
          phone:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 4}
```

| 键 | 必填 | 说明 |
|---|---|---|
| `version` | 是 | 固定为整数 `1` |
| `name` | 是 | 非空策略名，会进入报告、清单和审计 |
| `description` | 否 | 说明文字 |
| `datasets` | 是 | 非空规则列表，每条规则包含 `path` 与 `tables` |

数据集路径匹配规则：

- `path: "demo.sqlite"` 匹配文件名、完整路径，或以该字符串结尾的路径；
- 支持 shell 风格通配符，如 `"*.sqlite"`；
- 不需要为每个数据集写规则，但运行的数据集必须至少匹配一条规则；
- 多条规则同时匹配会报错，要求改成更明确的路径。

表名与列名必须与源数据集完全一致（大小写敏感）。执行 `python -m maskline scan <path>` 可查看登记后的表/列与发现结果。未出现在策略中的表会**原样复制**到目标库；未配置的列也原样复制，但检测为高/中置信度敏感列时会进入报告告警。

## 列配置两种写法

简写：

```yaml
phone: mask
```

完整写法：

```yaml
phone:
  transformer: mask
  params:
    keep_prefix: 3
    keep_suffix: 4
```

不允许未知键。`transformer`、参数名、参数类型、枚举值、最小值都会在加载策略时校验。例如 `generalize` 缺少必填的 `mode`、未知转换器、未知列都会立即报错。加载时会填入参数默认值，因此策略指纹也包含默认值。

## 行级条件 `when`

列规则可以增加可选的 `when` 条件，只有当前行满足条件时才执行变换；不满足的行**保留原值**写入目标库。典型场景：「只对非 VIP 客户脱敏手机号」「金额超过阈值的记录清空备注」。

```yaml
phone:
  transformer: mask
  params: {keep_prefix: 3, keep_suffix: 4}
  when: {column: tier, op: ne, value: VIP}
notes:
  transformer: nullify
  when: {column: amount, op: gt, value: 1000000}
```

| 键 | 必填 | 说明 |
|---|---|---|
| `column` | 是 | 同一行中参与比较的列名（可以是未配置变换的列，也可以是本列自身） |
| `op` | 是 | 操作符，仅限白名单：`eq` 等于、`ne` 不等于、`gt` 大于、`lt` 小于、`contains` 包含、`is_null` 为空 |
| `value` | 除 `is_null` 外必填 | 比较的字面量；`gt`/`lt` 必须是数字，`contains` 必须是非空字符串，`eq`/`ne` 接受字符串/数字/布尔 |

语义约定：

- **无代码执行**：条件是纯声明式结构，只支持上表白名单操作符，策略文件不可能注入或执行代码。
- **加载期校验**：未知操作符、非法的 `value` 类型在加载策略时立即报错；`when.column` 引用不存在的列会在运行前的策略校验阶段报错，不会跑到一半才失败。
- **按变换前的值判定**：条件始终读取本行的原始值。即使 `when.column` 引用的列本身也配置了变换（例如上例 `amount` 同时取整），判定结果也不依赖列的执行顺序。
- **NULL 视为不满足**：参与比较的列值为 `NULL` 时，所有比较操作符（含 `ne`）都不满足，该行保留原值。要匹配空值请用 `is_null`（`NULL` 与空串都算「为空」）。
- **数值比较**：`gt`/`lt` 按数值比较，无法转成数字的值（如非数字文本）视为不满足；`eq`/`ne` 在两边都像数字时按数值比较（CSV 的字符串单元格可与 YAML 数字匹配），否则按字符串比较。
- **命中/跳过计数**：报告（Markdown 与 JSON）与命令行输出会列出每条条件规则的命中行数（已变换）与跳过行数（保留原值），被跳过的行不会静默消失。跳过行不计入该列转换器的 `seen/processed/changed` 统计。

`when` 会进入策略指纹：修改条件等同于修改策略，不能用旧 run 的断点续跑。完整示例见 `policies/example-when.yaml`。

## 策略指纹与清单

策略内容会被规范化（键排序、参数补默认值）并计算 SHA-256 指纹。每次运行写入 `data/manifests/<数据集指纹前缀>.json`，包含策略指纹、输出哈希、各列转换器和各转换器计数。若同一数据集再次运行时策略指纹与上次清单不同，清单会标记：

```json
{"policy_changed": true, "previous_policy_fingerprint": "..."}
```

策略指纹变化后不能用旧 run 的断点续跑；请重新执行。只需要确认影响面时先用 `--dry-run`。

## 转换器参考

所有转换器对 `NULL` 安全；空字符串通常保持空字符串（`nullify` 除外）。转换器必须确定性：同输入、同参数、同密钥（如适用）得到同输出。

### `mask` 遮蔽

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `keep_prefix` | int >= 0 | `0` | 保留开头字符数 |
| `keep_suffix` | int >= 0 | `0` | 保留结尾字符数 |
| `mask_char` | 单字符 | `*` | 掩码字符 |

- 非字符串会先转成字符串；`NULL` 与空串原样返回。
- 若 `keep_prefix + keep_suffix >= len(value)`，整串都会变成掩码字符，避免短串完全暴露。
- 示例：`12345678901` + 3/4 -> `123****8901`。
- 边界：保留的前后缀仍泄露部分信息，手机号前缀、身份证后四位等组合可用于重识别；高风险场景优先使用假名化或整列置空。

### `hash` 加盐哈希

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `salt_ref` | str | `hmac_salt` | 密钥文件中的条名 |

- 算法：HMAC-SHA256，输出 64 位十六进制字符串。
- 密钥只从 `MASKLINE_SECRET_FILE` 指向的 YAML 文件读取，不在策略中写密钥。
- `NULL`、空串原样返回。
- 示例：`alice@example.invalid` -> 64 hex。
- 边界：相同密钥下相同原文总得到相同哈希，可用于关联；手机号、身份证等低熵值可被枚举攻击。哈希不等于不可逆加密。

### `generalize` 泛化

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `mode` | enum | 必填 | `date` / `age` / `amount` / `address` |
| `level` | enum | `month` | `date` 的档位：`month` / `quarter` / `year` |
| `width` | int >= 1 | `100` | `age` 的年龄段宽度或 `amount` 的区间宽度 |
| `unknown_label` | str | `其他地区` | 地址无法识别城市时的占位 |

行为：

- `date`：支持 `YYYY-MM-DD`、`YYYY/MM/DD`、`YYYY-MM`、带时分秒的日期时间。输出 `2024-02`、`2024-Q1` 或 `2024`。无法解析的值原样返回。
- `age`：输入可转为整数的非负年龄。`width: 10` 时 `42` -> `40-49`。负数或非法值原样返回。
- `amount`：按宽度向下取整到区间，输出闭区间文本。`width: 100` 时 `1234.56` -> `1200-1299`。非法值原样返回。
- `address`：去掉省级前缀后抽取地级市/自治州/地区/盟。`浙江省杭州市西湖区示例路1号` -> `杭州市`；`北京市朝阳区示例路1号` -> `北京市`；无法识别 -> `其他地区`。
- 边界：泛化数值/城市仍可能与辅助数据结合重识别；唯一/稀有的区间或城市尤其危险。

### `pseudonym` 确定性假名化

无参数。

- 使用密钥文件中的 `pseudonym_key`，对原文做 HMAC-SHA256 并取前 40 位，输出形如 `psn_...`。
- 同一密钥、同一原文跨表、跨运行得到同一假名；不同原文不同假名。
- 明文/假名映射写入独立文件 `data/pseudomap.sqlite`。`python -m maskline reveal --token <token>` 可还原。
- `NULL`、空串原样返回。
- 映射库等同密钥：离开映射库无法还原；持有映射库的人可还原全部假名。不要与脱敏输出一起交付。
- dry-run 会计算假名但不写映射库，因此 dry-run 输出不可用于后续还原。

### `nullify` 置空

无参数。所有值（包括已经为空的值）都转换为 SQL `NULL`。适用于完全不应交付的列。

### `round` 数值取整

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `decimals` | int >= 0 | `0` | 保留小数位 |

- 使用十进制定点与 `ROUND_HALF_UP`，`2.5` -> `3`（`decimals: 0`）。
- 非数值、`NULL`、空串原样返回（空串仍为空串）。
- `decimals: 0` 返回整数，否则返回浮点数。
- 边界：取整/四舍五入不提供隐私保护，只是降低精度；不可单独作为匿名化手段。

## NULL、空串与非法格式

| 转换器 | `NULL` | 空串 | 非法格式 |
|---|---|---|---|
| mask | 原样 | 原样 | 按字符串遮蔽 |
| hash | 原样 | 原样 | 按字符串哈希 |
| generalize | 原样 | 原样 | 原样返回（地址除外：无法识别时输出占位） |
| pseudonym | 原样 | 原样 | 按字符串假名化 |
| nullify | `NULL` | `NULL` | 一律 `NULL` |
| round | 原样 | 原样 | 原样返回 |

## 完整示例

参见仓库中的 `policies/example.yaml`，它覆盖全部六类转换器，并分别作用于 SQLite 与 CSV 数据集。
