# maskline（数隐管线）

面向本地 SQLite / CSV 数据集的**敏感字段自动发现 + 声明式脱敏执行管道**。它解决的是小团队在把内部数据交给外包、测试环境或第三方分析前「漏字段、不可复现、无法审计」的问题。

一条命令生成合成数据，并完成：

```
生成演示数据 -> 数据集登记 -> 敏感发现 -> 策略执行 -> 脱敏输出 -> 审计 -> 报告
```

所有功能完全离线运行，运行期不会发起网络请求。

## 项目定位

**是：**

- 本地数据集的敏感字段发现引擎（正则 + 校验位 + 中文词典启发）
- 跨数据集敏感关联风险识别（等值/语义关联、组合风险评级、关联图谱）
- 基于 YAML 的声明式脱敏策略执行器
- 可逆假名化与独立映射表管理
- 防篡改的追加式审计日志
- Markdown / JSON 脱敏报告生成器

**不是：**

- 通用 ETL / 数据集成平台
- 数据采集器、实时流、数据血缘系统
- Web 管理后台、HTTP API、多租户权限系统
- 加密算法库或合规认证产品
- MySQL / PostgreSQL 等外部数据库连接器

## 快速开始

要求 Python 3.11+，依赖只有 PyYAML 与 pytest（测试）。

```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -e ".[dev]"
python -m maskline demo
pytest -q
```

`python -m maskline demo` 不需要预先配置密钥：它会在 `data/demo-secret.txt` 生成仅用于演示的本地随机密钥，并把环境变量指向它。该文件被 `.gitignore` 排除，**绝不要提交**。

演示产物：

- `data/raw/demo.sqlite`、`data/raw/leads.csv`：固定种子生成的合成数据
- `data/out/demo.masked.sqlite`、`data/out/leads.masked.sqlite`：独立目标库
- `data/pseudomap.sqlite`：假名映射库（等同密钥，请单独保管）
- `data/checkpoints.sqlite`：运行与断点记录
- `reports/<run_id>.md`、`reports/<run_id>.json`：报告
- `audit/audit.jsonl` 与 `audit/audit.jsonl.head`：追加式审计链与锚点

## 架构

```
┌────────────────┐      read-only       ┌────────────────────────┐
│ SQLite / CSV   │ ───────────────────> │ registry + fingerprint │
│ source dataset │                      │ detectors / sampling   │
└────────────────┘                      └───────────┬────────────┘
                                                    │ findings
┌────────────────┐      strict load     ┌───────────▼────────────┐
│ policy YAML    │ ───────────────────> │ policy validation      │
│ (declarative)  │   fingerprint        │ + plan per column      │
└────────────────┘                      └───────────┬────────────┘
                                                    │ batches
                                      ┌─────────────▼─────────────┐
                                      │ streaming runner          │
                                      │ checkpoint + resume       │
                                      └───┬──────────┬────────┬───┘
                                          │          │        │
                                ┌─────────▼──┐ ┌─────▼────┐ ┌─▼──────────┐
                                │ target DB  │ │ pseudo   │ │ manifests  │
                                │ (separate) │ │ map DB   │ │ checkpoints│
                                └────────────┘ └──────────┘ └────────────┘
                                                    │
                                 ┌──────────────────▼──────────────────┐
                                 │ reports (MD/JSON) + audit hash chain │
                                 └─────────────────────────────────────┘
```

源数据库始终以 SQLite `mode=ro` 打开；运行期不会修改源文件。

## 目录结构

```text
maskline/
├── README.md
├── CHANGELOG.md
├── pyproject.toml
├── Makefile
├── secret.example.txt
├── maskline/
│   ├── __main__.py          # demo / scan / run / resume / reveal / audit
│   ├── config.py            # 路径与 MASKLINE_SECRET_FILE 密钥加载
│   ├── dataset_io.py        # SQLite / CSV 只读访问
│   ├── registry.py          # 数据集指纹、元数据与发现结果入库
│   ├── detectors/           # 正则、校验位、中文姓名/地址启发、打分
│   ├── policies.py          # YAML 加载、严格校验、策略指纹
│   ├── transformers/        # mask/hash/generalize/pseudonym/nullify/round
│   ├── pipeline/            # 流式执行、断点、清单
│   ├── linkage/             # 跨数据集关联风险识别（画像/匹配/图谱/评级/存储）
│   ├── pseudomap.py         # 可逆假名映射
│   ├── audit.py             # 追加式 JSONL 审计链
│   ├── report.py            # Markdown / JSON 报告
│   ├── workflow.py          # 扫描、收尾、审计的共享流程
│   ├── fixturegen.py        # 固定种子合成数据
│   └── demo.py              # 一键演示编排
├── policies/example.yaml
├── scripts/make_fixture.py
├── docs/policies.md
├── docs/threat-model.md
└── tests/
```

## 密钥配置

正常执行带 `hash` 或 `pseudonym` 的策略时，必须通过环境变量指定密钥文件：

```bash
# 1. 在仓库外创建密钥文件
python - <<'PY'
import secrets
print('hmac_salt:', secrets.token_urlsafe(48))
print('pseudonym_key:', secrets.token_urlsafe(48))
PY
# 2. 写入一个仅本人可读的文件，例如 ~/maskline-secret.txt
# 3. 指向它
export MASKLINE_SECRET_FILE=~/maskline-secret.txt
# Windows PowerShell:
# $env:MASKLINE_SECRET_FILE = "C:\secure\maskline-secret.txt"
```

文件格式见 `secret.example.txt`。两个值必须独立且至少 16 个字符。代码和策略只引用密钥名（如 `hmac_salt`），不包含密钥本身。丢失密钥会导致 HMAC 结果无法重现。

## 最小策略示例

```yaml
version: 1
name: customer-masking
datasets:
  - path: "demo.sqlite"
    tables:
      customers:
        columns:
          full_name: {transformer: pseudonym}
          phone:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 4}
          email: {transformer: hash}
          birth_date:
            transformer: generalize
            params: {mode: date, level: month}
```

路径按数据集文件名或完整路径匹配；完整参数与边界见 [docs/policies.md](docs/policies.md)。

## 常用命令

```bash
# 扫描目录或单个文件，登记并输出高/中置信度发现
python -m maskline scan data/raw

# 执行脱敏，写出独立目标库、报告与审计
python -m maskline run --dataset data/raw/demo.sqlite \
  --policy policies/example.yaml --output data/out/demo.masked.sqlite

# 只统计影响面，不写目标库/检查点/映射/报告/审计/元数据
python -m maskline run --dataset data/raw/demo.sqlite \
  --policy policies/example.yaml --dry-run

# 续跑被中断的 run（run_id 在错误信息、报告或清单中）
python -m maskline resume --run-id run-xxxxxxxx-xxxxxx

# 用映射库还原某个假名 token
python -m maskline reveal --token psn_xxxxxxxx

# 校验哈希链（含尾部截断锚点）
python -m maskline audit --verify

# 跨数据集关联风险：生成合成关联数据并一键演示
python -m maskline linkdemo

# 扫描目录，识别跨文件敏感关联组合（增量，无需全量重扫）
python -m maskline linkscan data/raw

# 导出建议脱敏策略（可直接复核后用于 run --policy）
python -m maskline linkscan data/raw --export-policy \
  --ignore-rules policies/linkignore.example.yaml

# 查看最新版本的关联图谱与风险清单
python -m maskline links
```

运行默认使用当前目录作为工作区，可用 `--workspace <dir>` 或 `MASKLINE_HOME` 指定。

## 跨数据集敏感关联风险识别

单数据集识别存在一个盲区：某些字段单独看并不敏感，但多个离线文件通过唯一标识
类字段（手机号、身份证号、会员号等）关联后，组合出的信息属于高度敏感，导致
脱敏规则配置不到位。`linkscan` 整合现有的单库敏感识别、字段指纹与新增的关联
关系建模能力，自动扫描目录下全部离线数据集：

- 识别跨文件的**等值关联**（值集指纹包含度匹配）与**语义关联**（同敏感类型 /
  列名同义词组）；
- 按数据集连通分量聚类，计算关联后**敏感组合**的风险等级（沿用现有
  0.8/0.5/0.2 置信阈值，命中姓名+身份证等组合规则时升至"极高"）；
- 输出关联关系图谱与风险点清单（`reports/linkage/linkgraph-vN.{md,json}`），
  并可导出建议脱敏策略直接对接规则配置；
- 结果版本化存储（`data/linkgraph.sqlite`），数据集新增/修改后自动增量更新，
  无需全量重扫；并发扫描受文件句柄预算约束，损坏/编码异常文件跳过并告警，
  全程写入审计链；支持 YAML 忽略规则排除非关联字段降低误判。

完整说明见 [docs/linkage.md](docs/linkage.md)。

## 幂等、断点与安全边界

- **登记幂等**：同一内容指纹只登记一次。
- **执行幂等**：同一数据集 + 同一策略 + 同一密钥，输出库内容哈希一致。
- **断点续跑**：每批提交目标库后记录 rowid 检查点；`resume` 会使用同一 run_id 继续，重复批次通过删除范围后重插保证至少一次执行不产生重复行。
- **策略变更**：策略指纹基于规范化后的策略内容；变化时 manifest 会标记 `policy_changed: true`。
- **源数据只读**：拒绝把输出路径指向源文件。
- **dry-run** 不创建任何运行期文件。
- **映射库 / 审计头文件 / 密钥文件**都必须单独保护；映射库可直接还原全部假名。

详细风险见 [docs/threat-model.md](docs/threat-model.md)。

## 测试

```bash
pytest -q
```

测试覆盖校验算法正反例、字段发现与误报、六类转换器、端到端执行、dry-run、断点续跑、幂等、假名映射、审计篡改定位、报告告警等。全部测试与演示均不需要网络。

## 常见问题

**`MASKLINE_SECRET_FILE is not set` 怎么办？**
正常 `run` / `resume` 只从该环境变量指向的本地文件读取密钥。演示命令会自动生成 `data/demo-secret.txt`；生产/真实数据请使用自己的密钥文件。

**为什么报告里的源值显示「已隐藏」？**
报告遵循最小暴露原则：配置了策略的敏感列只展示脱敏后的值；疑似敏感但未配置策略的列在源值与目标值位置都不输出原值，同时列入告警。非敏感列展示前后值。

**`dry-run` 真的什么都不写吗？**
是。它不写目标库、检查点、manifest、报告、审计或元数据库；只读取源数据和密钥文件（若策略需要）。

**CSV 也会输出成 SQLite 吗？**
是。本期目标库统一为独立 SQLite 文件；CSV 会被读成一个以文件名命名的表。

**映射库丢了还能还原吗？**
不能。假名是可逆映射而不是加密；映射库本身必须像密钥一样保管，且不应与脱敏输出一起交付。

**能直接连 MySQL / PostgreSQL 吗？**
不能。本期只支持本地 SQLite 与 CSV。
