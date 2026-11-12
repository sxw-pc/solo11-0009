# 敏感字段合规分级映射（classification）

在敏感字段自动发现之后、脱敏策略配置之前，离线给每个已识别字段自动标注三类合规标签：

- **合规等级**（L1–L4，随标准不同含义不同）
- **数据类别**（如「敏感个人信息-金融账户」「Special category - health data」）
- **管控要求**（如静态加密、单独同意、假名化、出境安全评估）

能力完全离线运行：三套内置标准的规则以 YAML 随包分发，运行期不访问任何外部合规库或网络。

## 与既有能力的关系

分级能力是 `maskline/classification/` 下的独立子包，复用三类既有能力而不复制其实现：

| 既有能力 | 复用方式 |
|---|---|
| 敏感识别结果存储 `registry.Catalog.findings` | 分级输入；分级前自动跑检测并落库 |
| 字段元数据管理 `registry.DatasetInventory` | 表/列名、声明类型、数据集指纹 |
| 规则匹配引擎范式（`policies.py` 严格校验 + 内容指纹） | 规则包 YAML 严格校验、规范化 SHA-256 指纹 |

## 内置三套标准

| 标准代码 | 规则包 | 等级语义 |
|---|---|---|
| `pipl` | 个人信息保护法（2021） | L1 组织信息 → L4 敏感个人信息 |
| `gbt35273` | GB/T 35273-2020 个人信息安全规范 | L1 非个人信息 → L4 个人敏感信息 |
| `gdpr` | GDPR (EU) 2016/679 | L1 non-personal → L4 special category |

三套规则均为通用整理，非法律意见或认证结论；企业可发布同标准的自定义规则包覆盖/扩展。自定义规则包与内置包使用同一严格 schema：同 `standard.code` 的新指纹包会成为新任务的活跃快照（旧版本永久保留，旧任务仍可按 `rule_pack_version_id` 复现）；不同 `pack_id` 的同标准包不会合并，规则包之间是替换而非叠加关系。

## 规则包结构与版本化

规则包是声明式 YAML，加载时严格校验（未知键、未声明管控项、重复规则 ID、冲突别名、非法等级都会直接报错），并对规范化内容计算 SHA-256 指纹。

```yaml
version: 1
pack_id: pipl-custom
revision: 2
standard: {code: pipl, name: PIPL 扩展, version: "2021", description: ""}
level_order: [L1, L2, L3, L4]
level_names: {L1: 组织, L2: 一般, L3: 较高, L4: 敏感}
defaults: {fallback_level: L2, fallback_category: 兜底类别, fallback_controls: [c1]}
controls_catalog: {c1: 基础管控, c2: 增强管控}
cross_border_name_patterns: [ip, email, "*country*"]
aliases:
  - {canonical: mobile_phone, names: [hotline_no]}
rules:
  - id: custom-salary
    priority: 60
    match: {sensitive_types: [], name_patterns: ["*salary*", "*工资*"]}
    labels: {level: L4, category: 敏感个人信息-财产, controls: [c1, c2]}
    special_category: true
```

版本化保证：

- 每个 `(pack_id, fingerprint)` 在 `rule_pack_versions` 中只存一次，**追加式**且 SQLite 触发器拒绝 UPDATE/DELETE；
- 每次分级任务在开始时固定一个规则版本快照（`pack_version_ids`），同批多数据集共用同一快照，杜绝并发发布导致的版本冲突；
- 历史版本永久保留，旧任务可按 `rule_pack_version_id` 精确复现当时的分级依据。

## 匹配、跨境与特殊类别

单字段在每个标准下独立匹配：

1. `sensitive_types` 内容命中（检测引擎产出，优先级最高）；
2. `name_patterns` 名称/通配符命中（深嵌套字段按叶节点名称匹配）；
3. 命中敏感类型但无精确规则 → 兜底等级 + `rule_unmapped_sensitive` 告警；
4. 非敏感且无名称命中 → 不分级（`unclassified`），不硬贴标签。

- **跨境传输**：规则 `cross_border_flag: true` 或命中规则包 `cross_border_name_patterns`（IP、邮箱、国家/地区等）时置 `cross_border=true`，并产出 `cross_border_name_hit` 提示，避免漏判。
- **特殊类别**：`special_category: true` 规则（身份证、银行卡、健康等）置显式布尔标记。
- **规则冲突**：多条规则同分时按规则 ID 字典序确定性选取，并产出 `rule_conflict` 告警，任务不中断。
- **弱证据**：仅名称命中而内容置信度为 none/low 时产出 `weak_evidence_match`。

## 同义异名字段统一分级

`semantic.SemanticResolver` 合并内置别名词典（中英文）与规则包 `aliases`，把 `phone`/`mobile`/`联系电话`/`hotline` 等归一到同一 `semantic_key`。

引擎在全表分级后执行 `enforce_semantic_consistency`：同一语义键下若各字段标签不一致，按标准逐一套用**最高保护等级**字段的标签，并对被调整字段产出 `semantic_drift` 告警，保证同语义字段分级结果一致且差异可审计。

## 降级处理（不中断整体流程）

| 场景 | 行为 | 告警 |
|---|---|---|
| 无表头 CSV | 启发式识别后合成列名 `col_001..col_NNN`，仅按内容识别分级，禁用名称匹配 | `headerless_file` |
| 嵌套深度超过 `--max-nesting-depth`（默认 3） | 字段标记 degraded，按叶节点名称继续分级 | `nested_depth` |
| 单数据集分级失败（批量任务中） | 记录 `dataset_failed`，其余数据集继续 | `dataset_failed` |

## 人工修正与不可篡改

人工修正采用双保险：

1. `classification_corrections` 追加表，触发器拒绝 UPDATE/DELETE，且每行带独立哈希链（`prev_hash`/`entry_hash`），`classify verify` 可独立校验；
2. 每次修正同步写入既有 `AuditLog` 哈希链（事件 `classification_correction`），与脱敏运行留痕在同一条链路。

修正必须给出 `reason` 与 `operator`；修正后该字段 `source` 变为 `manual`，`match_basis=manual`。

## 指纹联动重分级

分级结果绑定数据集指纹，`dataset_classification_state` 记录每个路径最近一次分级时的指纹。`classify reclassify` 重新计算当前指纹，仅对发生变化的数据集触发重分级；文件缺失也只产生告警不中断。

## 供规则配置模块引用

`classify export` 把分级结果直接生成现有 v1 脱敏策略 YAML，可被 `maskline run --policy` 直接加载（经过同一严格校验器）。转换规则集中在 `policy_export.py`：

- 管控要求优先：`nullify` > `pseudonymization` > `hashing` > `masking` > `generalization`；
- 无管控命中时按最高等级取默认转换器；
- 未分级字段不进策略，并在导出通知中逐一列出。

## CLI

```bash
# 首次运行自动发布三套内置规则包，然后分级一个或多个数据集
maskline classify run data/raw/demo.sqlite data/raw/leads.csv

# 查看已注册规则版本 / 发布自定义规则包
maskline classify packs
maskline classify packs ./my-pipl-rules.yaml

# 查看某数据集指纹的分级结果
maskline classify results <fingerprint>

# 人工修正（追加式，带原因与操作人）
maskline classify correct --fingerprint <fp> --table customers --column phone \
  --standard pipl --level L4 --controls encryption-at-rest,separate-consent \
  --reason "评审上调" --operator alice

# 校验修正哈希链 / 指纹变更重分级
maskline classify verify
maskline classify reclassify

# 导出现有规则配置模块可直接引用的 v1 策略
maskline classify export <fp> --output policies/generated/derived.yaml
```

所有命令支持 `--workspace` 或 `MASKLINE_HOME` 指定工作区；产物落在 `data/classification.sqlite`，审计仍写入 `audit/audit.jsonl`。
