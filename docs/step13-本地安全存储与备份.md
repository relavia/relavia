# Step 13 交付文档：本地安全存储与备份

基线：main `359fa70`（Steps 7/8/9/10/11/12/14 已交付）。
Governing source：方案书 §3 原则 2/7（本地优先、无账号无遥测——备份不依赖任何云账号）、§5.5（本地加密存储、导出二次确认、密钥由用户口令派生、可选择不设口令并界面明示）、§8.1（配置加密备份与恢复）、§9.2（凭据保护、内存中尽量缩短明文驻留）、第 14 章 Step 13 原文（交付加密存储、导出二次确认、加密备份恢复；验收：安全自查清单全过）。
主战场：Step 9 在 `app/service/store.go` 标注的替换点——Store 的 Document 编解码。Step 10 的 `app/android` 与全部调用方复用同一 Store，本步 API 只增不改，接缝未动。

## 1. 方案裁定

| 项 | 裁定 | 理由 |
|---|---|---|
| KDF | **Argon2id**（golang.org/x/crypto/argon2），time=3、memory=64 MiB、threads=4、盐 16 B 随机、输出 32 B | 内存硬 KDF 是口令派生的当前最佳实践（OWASP 基线之上取整机交互可接受的参数）；参数随文件头持久化，后续可按设备档位上调而不破格式 |
| AEAD | **XChaCha20-Poly1305**（golang.org/x/crypto/chacha20poly1305） | 24 B 随机 nonce 可安全随机生成（无需计数器状态）；不依赖 AES 硬件指令，低端 Android 机型上性能与功耗更稳；实现出自 Go 官方维护的 x/crypto |
| 密钥层级 | 口令 →(Argon2id)→ KEK →(AEAD 包裹)→ 随机 DEK(32 B) →(AEAD)→ 文档 | 改口令只重包裹 DEK，不重加密全文；平台密钥库包裹的也是同一个 DEK，两条解锁路径互不干扰 |
| AAD 绑定 | 文档密文 AAD=`relavia-store/v1`，DEK 包裹 AAD=`relavia-store-key/v1`，备份 AAD=`relavia-backup/v1` | 防止密文跨用途/跨格式挪用 |
| 无口令模式 | 方案书 §5.5 明文允许：用户可选择不设口令。文件与数据层均带**显式降级标记**（见 §3），与加密模式永不混称 | 原文裁定，非本步自创 |
| 平台密钥库 | 以 `KeyWrapper` 接口预留（见 §5），本步交付接口 + 信封字段 + 解锁路径，真实 DPAPI/Keystore 绑定如实列为未完成项 | 沙箱无 Windows/Android 真机可验，宁可分级标注，不冒充实现 |

新依赖：仅 `golang.org/x/crypto v0.54.0` 由间接依赖转正为直接依赖（BSD-3-Clause，与 Step 2 许可证审计的宽松许可口径一致）；argon2 与 chacha20poly1305 均为其子包，无新增第三方模块。

## 2. 文件格式规范

存储文件（`store.json`，0600，目录 0700）自本步起恒为信封格式 v1：

```json
{
  "format": "relavia-store",
  "version": 1,
  "mode": "passphrase" | "none",
  "degraded": true,                    // 仅 none 模式出现
  "kdf": {"time":3,"memoryKiB":65536,"threads":4,"salt":"<b64 16B>"},   // 仅 passphrase 模式
  "wrappedKey": "<b64 nonce||ct>",     // DEK 被 KEK 包裹
  "platformWrappedKey": "<b64 blob>",  // 可选：DEK 被平台 KeyWrapper 包裹
  "nonce": "<b64 24B>",
  "ciphertext": "<b64>",
  "document": { ... }                  // 仅 none 模式（明文，降级标记同在）
}
```

备份文件格式 v1（独立信封，与存储格式互不通用，AAD 不同）：

```json
{
  "format": "relavia-backup",
  "version": 1,
  "kdf": { ... },
  "nonce": "<b64 24B>",
  "ciphertext": "<b64>"
}
```

备份明文载荷：`{document, exportedAt, storeVersion, nodeCount, sha256}`，其中 sha256 为文档规范 JSON 的 SHA-256，导入时与 nodeCount 一并复验（AEAD 标签之外再加一层载荷内完整性，防的是实现缺陷而非仅防攻击者）。

## 3. 锁定语义与状态机

- 状态（passphrase 模式）：`Locked --Unlock(口令正确)--> Unlocked`；`Unlocked --Lock() / 自动锁定超时--> Locked`。错误口令**不是**迁移：状态不变、无任何文档内容暴露、返回 `ErrWrongPassphrase`。
- 锁定态下：`Snapshot()`/`Settings()` 返回零值文档；`Save()`/`ExportBackup`/`RestoreBackup` 一律拒绝（`ErrStoreLocked`）——杜绝用空文档覆盖密文的销毁路径。
- 自动锁定：`SetAutoLock(d)` 后在读/写路径入口惰性检查（另有 `CheckAutoLock()` 供 UI 定时器调用）；活动（成功读/写/解锁）刷新计时。惰性检查而非后台 goroutine，行为确定、可测。
- 内存卫生：`Lock()` 先用在内存 DEK 重封文档（未保存的修改在锁定后仍可经 Unlock 精确恢复，有单测），再将 DEK 字节清零、明文文档清空；KEK 在每次派生用毕即清零。Go 运行时无法保证堆上无副本，此为尽力口径，如实记录。
- 无口令降级标注（三处一致，不许缺一）：
  1. 文件层：信封 `"mode":"none"` 且 `"degraded":true`；
  2. 数据层：`Store.Protection()` 返回 `{Mode:"none", Degraded:true}`；加密模式返回 `{Mode:"passphrase", Degraded:false}`；
  3. 文案层：`security.no_passphrase_warning` 三语词条明示风险（见 §6）。

## 4. 迁移路径（旧明文 → 加密）

1. `OpenStore` 识别三种形态：信封、旧版裸 JSON 文档、（主文件不可读时的）`.tmp` 恢复候选。旧版裸 JSON 正常加载并标记 `legacy`，数据立即可用，不强制用户当场设口令。
2. 用户执行 `SetPassphrase` 时：全部密码学操作先在内存完成（派生、包裹、密封）；替换写盘走原子写（临时文件 → fsync → rename）；**仅在新密文已完整落盘后**，才把旧文件字节同长度零填充覆写 + fsync，随后 rename 覆盖。覆写口径在此写清：应用层零填充覆写是尽力而为——SSD 磨损均衡与写时复制文件系统可能在闪存层保留旧块，这不是应用能承诺的部分，不在此冒充。
3. 迁移失败不丢数据：写盘任何一步失败 → 内存状态回滚为原模式、原文件字节不变（单测以目录堵住 `.tmp` 路径注入失败，断言原文件逐字节一致、内存数据仍在）。
4. 崩溃窗口：覆写后、rename 前崩溃 → 主文件已零填充不可读，但 `.tmp` 持有完整新信封，`OpenStore` 的 tmp 恢复路径接管（单测覆盖 none 与 passphrase 两种模式）。

## 5. 平台密钥库衔接（如实分级）

| 层级 | 状态 |
|---|---|
| L1 接口与信封：`KeyWrapper` 接口（WrapKey/UnwrapKey）、信封 `platformWrappedKey` 字段、`EnablePlatformUnlock` / `UnlockWithPlatform` 全路径 | ✅ 本步交付，假实现（测试内 XOR fake，仅存于测试文件）单测全过，含落盘后重开仍可平台解锁 |
| L2 Windows DPAPI 绑定（CryptProtectData/CryptUnprotectData，落 `app/platform`） | ⬜ 未实现：沙箱无 Windows 真机，DPAPI 绑定与当前用户上下文绑定，写了也无法实证；接口已定，留待真机步 |
| L3 Android Keystore 绑定（经 Step 10 平台桥） | ⬜ 未实现：同上，留待 Android 真机步 |
| 安全口径 | 平台解锁是「持有设备即可解锁」的便利路径，弱于口令的「所知」因子；UI 呈现时不得与口令模式混称同等安全（已写入接口注释，UI 落地时执行） |

## 6. 备份导入导出

- 导出 `ExportBackup(path, passphrase, confirmed)`：拒绝顺序为 未确认（`ErrExportNotConfirmed`，对应 §5.5 二次确认；确认文案 `security.export_confirm` + 警告文案 `security.export_warning`「配置含凭据，等同密码」三语已入词条）→ 空口令（`ErrBackupPassphraseNeeded`）→ 锁定态（`ErrStoreLocked`）。
- **备份恒加密**：即便存储处于无口令降级模式，备份也必须口令加密——备份的用途就是离开应用目录由用户携带，明文凭据文件不可接受（单测断言降级模式导出的备份无凭据明文串）。备份口令与存储口令相互独立。
- 导入 `ReadBackup` / `RestoreBackup`：格式标识不符 → `ErrCorruptStore`；格式版本更新 → `ErrUnsupportedBackupVer`（含文档版本高于本机 store 版本）；口令错误 → `ErrWrongPassphrase`（AEAD 打开失败）；载荷哈希/节点数对不上 → `ErrCorruptStore`。恢复语义为**全量替换**（回滚到备份点，非合并），替换后按存储当前模式落盘，落盘失败回滚内存文档。
- 全程本地文件进出，无任何云账号参与（§3 原则 2）。

## 7. 安全自查清单与测试结果（Step 13 验收口径）

新增测试 14 个函数（`app/service/secure_test.go` 10 个、`backup_test.go` 4 个），全绿；app 全包回归全绿（service/android/platform/i18n），GOOS=windows 与 GOOS=android(arm64) 交叉编译通过，i18ncheck 全绿（三语各 110 键，缺失/多余/空值 0，硬编码扫描违规 0）。

| # | 自查项 | 结果 | 证据（测试） |
|---|---|---|---|
| 1 | 加密静态存储：文件无凭据明文 | ✅ | TestPassphraseEncryptsAtRestAndLocks（标记串扫描） |
| 2 | 篡改密文任一字节必拒 | ✅ | TestTamperedCiphertextRejected/ciphertext |
| 3 | 篡改包裹密钥必拒 | ✅ | TestTamperedCiphertextRejected/wrappedKey |
| 4 | 错误口令必拒且无部分泄露 | ✅ | TestPassphraseEncryptsAtRestAndLocks（锁定态 Snapshot 为空、NodeByID 无结果） |
| 5 | 锁定态不得写盘（防空文档覆盖密文） | ✅ | 同上（Save → ErrStoreLocked）；备份导入导出锁定拒绝见 TestBackupLockedStoreRefusals |
| 6 | 迁移一致性：节点数与关键字段逐项比对 | ✅ | TestLegacyPlaintextMigration |
| 7 | 迁移失败保留原件（逐字节）且内存数据不丢 | ✅ | TestMigrationFailureKeepsOriginalFile |
| 8 | 备份往返一致性（节点/分组/订阅/设置全量） | ✅ | TestBackupRoundTrip（规范化 JSON 全等 + 重开持久性） |
| 9 | 导出文件不含明文凭据（实证扫描，含降级模式导出） | ✅ | TestBackupRoundTrip、TestBackupFromDegradedStoreIsEncrypted |
| 10 | 导出二次确认与口令强制 | ✅ | TestBackupRoundTrip（两拒绝分支） |
| 11 | 损坏/未来版本备份拒绝 | ✅ | TestBackupTamperAndVersionRefusals |
| 12 | 无口令降级标注（文件/数据层双断言） | ✅ | TestNoPassphraseModeIsMarkedDegraded |
| 13 | 改口令/去口令语义（旧口令失效、降级标记回归） | ✅ | TestChangeAndRemovePassphrase |
| 14 | 手动锁定/解锁循环，未保存状态可恢复 | ✅ | TestManualLockUnlockCycle |
| 15 | 自动锁定（不活动超时） | ✅ | TestAutoLockExpires |
| 16 | 原子写与崩溃恢复（主文件损坏时 tmp 接管，双模式） | ✅ | TestCrashRecoveryFromTempFile |
| 17 | 平台包裹解锁路径（接口级） | ✅（接口级） | TestPlatformWrapperUnlock（真实绑定见 §5 分级，未完成） |

注：service 包测试耗时约 19–30 s，几乎全部来自 Argon2id（64 MiB×3）的真实派生——这是刻意不打折的参数，CI 上同样按此口径跑，不以降低测试参数换取速度。

## 8. 未完成项（如实）

- Windows DPAPI / Android Keystore 真实绑定未实现（§5 的 L2/L3），Step 10/9 的真机步落地时接 `KeyWrapper` 接口即可，存储格式无需变更。
- cmd/UI 尚未接锁定屏与口令设置界面：本步交付数据层全量语义与三语文案（`security.*` 7 键），界面接线随后续 UI 步；`OpenStore` 对加密文件返回锁定态 Store，现有 cmd 入口在未接解锁 UI 前打开加密过的存储将看到空文档——这是锁定语义的应然表现，文档在此明示，接线前用户侧不要在旧构建上启用口令（启用动作本身也只能经新 API 触发，旧构建无此入口，风险闭合）。
- 覆写删除的闪存层残留问题（§4 第 2 点）为业界共同限度，已如实标注口径。
