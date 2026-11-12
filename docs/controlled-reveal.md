# 受控还原（Controlled Reveal）设计与操作手册

假名映射库（`pseudomap.sqlite`）等同于密钥：拿到它就能把假名还原成明文。
为避免"拿到映射库即可无条件还原"，maskline 提供一套**完全离线、双人控制、
全程留痕**的还原机制。它不依赖任何服务器或第三方库，仅使用 Python 标准库的
`hashlib` / `hmac` 原语。

## 1. 角色与信任前提

| 角色 | 持有的密钥 | 职责 |
| --- | --- | --- |
| 操作员 operator | 自己的 operator 私钥（HMAC key） | 发起还原申请，对申请签名 |
| 复核人 reviewer | 自己的 reviewer 私钥（HMAC key） | 独立审批，对申请签名生成带有效期与行数上限的授权 |
| 审计锚点密钥 | keyring 内部 `audit-mac`，不是身份 | 保护单调时钟锚点，并为受控还原审计条目加 MAC |

代码强制：

1. operator 与 reviewer 是**两个不同的 key id**（职责分离，同一身份不能自批自审）；
2. 密钥带角色，operator 密钥签不出授权，reviewer 密钥签不出申请；
3. 所有身份密钥只存在于 `data/keyring/keys/<kid>.key`（权限 `0600`，目录 `0700`），
   清单 `keyring.json` 只保存指纹（kid）、角色、生命周期状态，不含任何秘密材料。

> 对称 HMAC 体系意味着"验证方必须持有同一把密钥"。离线、无 CA、无新依赖的约束下
> 这是明确的设计取舍：双人控制的根信任是**两把密钥由两个不同的人分别保管**，
> 代码保证角色与身份分离，但无法保证物理保管。详见 `threat-model.md`。

## 2. 数据结构

所有工件都是单个 JSON 文件，权限 `0600`。签名只覆盖 `message` 的规范 JSON
（排序键、无空白），因此磁盘上的键顺序或排版变化不影响验签，而任何业务字段
被改动都会使 HMAC 标签失效。

### 2.1 还原申请 `reveal-request`

```jsonc
{
  "message": {
    "type": "reveal-request",
    "version": 1,
    "request_id": "req_...",
    "created_at": "2026-11-12T09:00:00+00:00",
    "operator_kid": "<操作员密钥指纹>",
    "reason": "事件响应 IR-42，需核对客户姓名",
    "scope": {
      "run_id": "run_...",                 // 绑定具体脱敏批次
      "dataset_fingerprint": "<目标数据集指纹>",
      "table": "customers",
      "columns": ["full_name"]            // 列范围（可多列）
    }
  },
  "signature": { "alg": "HMAC-SHA256", "kid": "...", "tag": "<HMAC>" }
}
```

### 2.2 授权文件 `reveal-authorization`

复核人独立签名，携带**过期时间**与**最大还原行数**，并通过 `request_id` 与
`request_hash` 双重绑定到原申请：

```jsonc
{
  "message": {
    "type": "reveal-authorization",
    "version": 1,
    "authorization_id": "auth_...",
    "created_at": "...",
    "reviewer_kid": "<复核人密钥指纹>",
    "expires_at": "2026-11-12T10:00:00+00:00",
    "max_rows": 100,
    "request_id": "req_...",
    "request_hash": "<申请 message 的域分离 SHA-256>",
    "scope": { ... 与申请一致的范围 ... }
  },
  "authorization": { "alg": "HMAC-SHA256", "kid": "...", "tag": "<HMAC>" }
}
```

### 2.3 域分离

不同用途的标签使用不同的固定前缀，杜绝跨工件重放：

- `maskline-reveal-request/v1`
- `maskline-reveal-authorization/v1`
- `maskline-keyring-entry/v1`（密钥文件自检 MAC）
- `maskline-audit-mac/v1`（审计条目 MAC）
- `maskline-monotonic-clock/v1`（时钟锚点 MAC）

## 3. 完整双人流程

```bash
# 一次性：初始化本地密钥环（生成内部审计/时钟 MAC 密钥）
maskline keygen init

# 两位成员各自生成自己的身份密钥（在各自账户/机器上执行并各自保管）
maskline keygen new --name alice --role operator
maskline keygen new --name bob   --role reviewer
maskline keygen list

# 1) 操作员发起申请（数据集指纹由命令现场重算，写入 scope）
maskline reveal-request \
  --operator-kid <alice-kid> \
  --run-id run_xxxx --dataset data/out/customers.masked.sqlite \
  --table customers --column full_name \
  --reason "事件响应 IR-42" \
  --out data/reveal/req-42.json

# 2) 复核人独立审批：限定有效期与最大行数
maskline authorize \
  --reviewer-kid <bob-kid> \
  --request data/reveal/req-42.json \
  --expires-at 2026-11-12T10:00:00+00:00 \
  --max-rows 100 \
  --out data/reveal/auth-42.json

# 3) 执行受控还原（明文只在成功后原子落地）
maskline reveal \
  --request data/reveal/req-42.json \
  --authorization data/reveal/auth-42.json \
  --dataset data/out/customers.masked.sqlite \
  --out data/reveal/customers.plain.sqlite
```

执行阶段的校验顺序（任何一步失败即拒绝并写 `reveal-denied` 审计）：

1. **单调时钟**：检查时钟锚点，回拨或锚点被改即拒（见 §5）；
2. **结构与类型**：记录类型、版本正确；
3. **操作员签名**：用 keyring 中该 operator 密钥验申请 HMAC；
4. **授权绑定**：授权的 `request_id` 与 `request_hash` 必须匹配申请原文；
5. **复核人签名 + 职责分离**：验授权 HMAC，且 reviewer kid ≠ operator kid，
   角色必须分别是 reviewer / operator；
6. **有效期**：当前时间 ≥ `expires_at` 即拒；
7. **范围**：执行范围必须同时被申请范围与授权范围包含（表、列、批次、数据集指纹）；
8. **行数上限**：目标表行数 > `max_rows` 即拒；
9. **重放**：该 `authorization_id` 已在审计链中被消费即拒；
10. **原子认领**：全部通过后先追加 `reveal-claimed`，再产出任何明文。

## 4. 批次绑定

授权与**具体脱敏批次**绑定，换一批数据立即失效。绑定依据：

- scope 中的 `dataset_fingerprint` 必须等于执行时对目标数据集**现场重算**的指纹；
- scope 中的 `run_id` 必须等于该数据集 manifest（`data/manifests/<指纹前16位>.json`）
  记录的脱敏批次 `run_id`；
- 授权表名、列名必须真实存在于该数据集。

因此，对另一份数据集（即使表结构、列名完全相同）重放同一份授权，会因指纹或
`run_id` 不一致而被拒绝（审计原因 `batch-mismatch`）。

## 5. 攻击面与对应措施

| 攻击面 | 措施 | 失败时审计原因 |
| --- | --- | --- |
| 授权文件被篡改（改行数/有效期/范围） | 授权 HMAC 覆盖整个 message，改一个字节标签即失效 | `authorization-signature-invalid` |
| 申请文件被篡改后复用旧授权 | 申请签名失效；授权内 `request_hash` 也不再匹配 | `request-signature-invalid` / `request-hash-mismatch` |
| 授权过期仍使用 | 受保护时钟下比较 `expires_at` | `authorization-expired` |
| **执行中途授权到期** | 每处理一行前复查时钟；到期立即中止，覆写并删除临时明文，写 `reveal-aborted` | `authorization-expired` |
| 机器时钟被回拨以复活过期授权 | MAC 保护的单调锚点记录 last_seen，回拨即拒 | `clock-rollback` / `clock-anchor-tampered` |
| 同一授权重复使用 | 执行前原子 `reveal-claimed` 落链；审计链本身防删改，再次出现即拒 | `authorization-replay` |
| 复核人与操作员密钥混用 / 自批自审 | 密钥带角色且强制两 kid 不同，签发与执行两侧都检查 | `role-mismatch` / `separation-of-duties` |
| 超范围还原（加列、加表、换批次） | 现场重算指纹 + manifest run_id + 范围包含检查 | `scope-mismatch` / `batch-mismatch` |
| 超过最大行数 | 先比对表总行数，流式处理再设逐行硬上限 | `row-limit-exceeded` |
| 密钥文件被替换成他人密钥 | 每个密钥文件含自校验 MAC，替换后加载即失败 | `key-file-tampered` |
| 撤销的密钥继续被使用 | keyring 生命周期状态；revoked 的历史签名也一律拒绝 | `key-revoked` |

## 6. 密钥轮换与吊销

```bash
maskline keygen rotate --kid <kid>   # 置为 rotated：不能再签新工件，但历史签名仍可验
maskline keygen revoke --kid <kid>   # 置为 revoked：连同历史签名一律拒绝
```

- **轮换（rotate）**：用于定期换钥。旧密钥状态变为 `rotated`，无法签发新申请/授权，
  但它在轮换前签发的工件仍能通过验证，保证在途流程不中断。
- **吊销（revoke）**：用于疑似泄露。状态变为 `revoked` 后，该密钥的**所有**签名
  （包括历史签名）都被拒绝。
- 每次生成/轮换/吊销都追加 `reveal-key-event` 审计条目。

## 7. 审计链

所有受控还原事件写入与脱敏运行相同的追加式哈希链 `audit/audit.jsonl`：

- `reveal-key-event`、`reveal-request-created`、`reveal-authorized`
- `reveal-claimed`（授权被消费的原子标记）
- `reveal-completed`（含实际还原行数 `rows_revealed` 与授权上限 `rows_authorized`）
- `reveal-aborted`（中途失败/到期，含中止前已处理行数与原因）
- `reveal-denied`（每次被拒绝的尝试，含稳定原因码 `reason`）

每个受控还原条目还带 `audit_mac`（审计锚点密钥计算），用于在哈希链之外再提供
一层身份可识别的完整性保护。`maskline audit --verify` 会先校验整条哈希链；若
工作区存在密钥环，还会重算每个受控还原条目的 `audit_mac`（业务字段），任何未持
有审计密钥的伪造或篡改都会以 `audit-mac-invalid` 报错。普通脱敏运行条目没有
`audit_mac`，校验时自动跳过。

## 8. 临时明文清理

- 还原结果先写入同目录临时文件（`.reveal.*`，权限 `0600`），**全部成功后才
  `os.replace` 原子改名**为最终输出；
- 任何异常（含中途到期、行数越界、磁盘错误）都会 `secure_delete`：先随机覆写
  再 `unlink`，并写 `reveal-aborted`；
- 注意：在日志/写时复制文件系统上，用户态无法保证物理块被擦除，可保证的是
  **失败后不存在任何明文路径**。强物理销毁需依赖磁盘加密与介质管理。

## 9. 已知边界（不提供的保证）

- 不提供非对称公钥签名、CA、CRL/OCSP、网络时间或 HSM；这些都需要第三方或服务器。
- 能同时改写审计日志、头锚点、时钟锚点并持有密钥环的本机高权限主体，仍可绕过
  控制；应配合文件系统权限、全盘加密、只追加/异地日志归档。
- 授权一旦签发，在过期前无法在线撤销（无服务器）；应急手段是 `revoke` 复核人密钥，
  使其历史签名立即失效。
