# 更新清单格式规范：relavia-update/v1（定版）

> 定版方：Step 16（更新机制），2026-11-13。本文件是该格式的**唯一规范源**：
> Step 15 的发行流水线按本规范产出清单与签名，客户端按本规范校验。
> 两步并行开发期间的接口裁定（主会话）：清单格式 `relavia-update/v1`，
> 先落盘者为准——本文件即落盘版。与本文件的差异须上报主会话，不得私自改格式。

## 1. 载体与通道

- 清单是一份静态 JSON 文件，由发行流水线随 GitHub Release 一并发布，
  客户端从固定静态 URL 拉取（默认见 §7）。**没有任何回传**：客户端不向
  清单服务器发送除 HTTP 必需头之外的任何信息（见 §8 隐私口径）。
- 清单与产物均只经 HTTPS 分发。通道完整性由 TLS 提供，但**产物的真实性
  只由 §4 的 Ed25519 签名提供**，不依赖通道（通道被劫持时签名仍须拦住）。

## 2. 清单结构

```json
{
  "format": "relavia-update/v1",
  "version": "0.2.0",
  "versionCode": 200,
  "channel": "stable",
  "seq": 7,
  "publishedAt": "2026-11-14T00:00:00Z",
  "notes": {
    "zh-Hans": "修复……",
    "zh-Hant": "修復……",
    "en": "Fixed …"
  },
  "artifacts": [
    {
      "platform": "windows-amd64",
      "url": "https://github.com/relavia/relavia/releases/download/v0.2.0/relavia-windows-amd64.exe",
      "size": 70485504,
      "sha256": "〈64 位小写十六进制〉",
      "sig": "〈base64，见 §4〉"
    },
    {
      "platform": "android-arm64",
      "url": "https://github.com/relavia/relavia/releases/download/v0.2.0/relavia-android-arm64.apk",
      "size": 72500000,
      "sha256": "〈64 位小写十六进制〉",
      "sig": "〈base64〉"
    }
  ]
}
```

字段口径：

| 字段 | 类型 | 口径 |
|---|---|---|
| `format` | string | 恒为 `relavia-update/v1`，不符即拒绝整份清单 |
| `version` | string | 语义化版本 `MAJOR.MINOR.PATCH`（可带 `-prerelease`），本次发布版本 |
| `versionCode` | int | 单调整数，编码 = `MAJOR*10000 + MINOR*100 + PATCH`（0.2.0 → 200）；同 semver 时以它分先后（Android versionCode 同源） |
| `channel` | string | `stable` 或 `beta`；客户端只接受与自身订阅渠道相同的清单 |
| `seq` | int64 | **发布序号**，同一渠道内随每次发布严格单调递增（从 1 起），是回滚防护的锚（§5） |
| `publishedAt` | string | RFC 3339 UTC 时间；仅作展示与合理性检查（不得晚于客户端当前时间 7 天以上） |
| `notes` | object | 语言码 → 更新说明；至少含 `en`；客户端按当前语言取，缺失回退 `en` |
| `artifacts[]` | array | 每个平台一项；客户端按自身 `platform` 标识选取，无匹配项即「本平台暂无此更新」 |
| `artifacts[].platform` | string | `〈goos〉-〈goarch〉`，如 `windows-amd64`、`android-arm64`、`linux-amd64` |
| `artifacts[].url` | string | 产物下载地址（HTTPS） |
| `artifacts[].size` | int64 | 产物字节数；下载后须与实际一致（不一致即拒绝，防截断/掉包） |
| `artifacts[].sha256` | string | 产物 SHA-256，64 位小写十六进制 |
| `artifacts[].sig` | string | 发行签名，见 §4 |

未知字段忽略（向前兼容）；缺失必填字段、类型错误、`sha256`/`sig` 格式
不合法，一律按「清单损坏」拒绝整份清单，不做部分接受。

## 3. 版本比较

客户端持有自身 `version` + `versionCode`。有更新 ⟺
清单 `version` 的 semver 严格大于自身 semver；semver 相等时，
清单 `versionCode` 严格大于自身 `versionCode`。其余情形（相等、
更旧）均为「已是最新」，不是错误。

## 4. 签名

- 算法：Ed25519（RFC 8032），密钥为项目**发行密钥**，私钥由发行方
  （用户）保管，公钥内嵌客户端。
- 被签消息：**产物 SHA-256 摘要的原始 32 字节**（不是十六进制文本，
  不是整个清单）。即 `sig = base64( Ed25519.Sign(priv, sha256digest) )`，
  `sig` 解码后恒为 64 字节。
- 校验顺序（客户端，任一失败即拒绝并删除已下载物）：
  1. 下载完成后计算产物 SHA-256，与清单 `sha256` 比对（且与 `size` 比对）；
  2. 以内嵌发行公钥验 `sig` 对「第 1 步实算出的摘要字节」成立。
- 语义边界（如实记录）：`sig` 认证的是**内容**（某个摘要对应的字节流
  是发行方签过的）。版本绑定由 §5 的 `seq` 单调性 + §3 的版本比较 +
  HTTPS 通道共同提供；把一份旧的（sha256, sig）对塞进伪造的高版本
  清单，需要先攻破官方清单的托管通道，且仍受 `seq` 锚约束。后续格式
  若升 v2，候选改进是改为对规范化清单摘要签名，届时须走格式升版流程。

## 5. 回滚防护

- 客户端把每个渠道**已接受过的最大 `seq`** 持久化在本地设置中
  （`updateSeenSeq`，按渠道分键）。
- 拉到的清单若 `seq` 小于已存值 → 按「疑似回滚攻击」拒绝整份清单
  （错误码 `update.rollback_detected`），且不更新已存值。
- 清单通过结构校验与本节检查后，已存值更新为该清单的 `seq`
  （即使本次没有可更新产物——序号锚的是「见过的最新清单」）。
- `seq` 相等时，`publishedAt` 不得早于已存清单的发布时间（客户端
  一并持久化 `updateSeenPublishedAt`）；早于即按回滚拒绝。

## 6. 错误码（客户端服务层，UI 据此取本地化文案）

| 错误码 | 含义 |
|---|---|
| `update.manifest_fetch` | 清单拉取失败（网络/HTTP 非 200） |
| `update.manifest_invalid` | 清单格式损坏或字段不合法 |
| `update.rollback_detected` | `seq`/发布时间回退，疑似回滚攻击 |
| `update.no_artifact` | 清单有效但无本平台产物 |
| `update.download_failed` | 产物下载失败（网络中断等） |
| `update.download_canceled` | 用户取消下载 |
| `update.hash_mismatch` | 产物 SHA-256 或 size 与清单不符（已删） |
| `update.signature_invalid` | Ed25519 签名验证失败（已删） |
| `update.install_unavailable` | 本平台安装入口尚不可用（诚实降级） |
| `update.install_failed` | 安装入口执行失败，旧版本保持可用 |

## 7. 默认清单 URL

- stable：`https://github.com/relavia/relavia/releases/latest/download/update-stable.json`
- beta：`https://github.com/relavia/relavia/releases/latest/download/update-beta.json`

（GitHub Releases 的 `latest/download/〈资产名〉` 静态重定向；资产名由
Step 15 流水线按渠道产出 `update-stable.json` / `update-beta.json`。
URL 在客户端设置中可改，改后仍走同一套校验，不降低验签要求。官网
静态镜像可作备用 URL，格式与口径不变。）

## 8. 隐私口径

- 检查时机：①用户在设置中手动点「检查更新」；②用户**主动开启**
  「定期检查」后，启动时至多每 24 小时一次。默认**关**——不开启就
  永不联网检查。绝不静默下载、绝不静默安装：下载与安装都须用户
  在界面上明确确认（方案书 5.5：无强制更新、无静默更新）。
- 请求头：仅 `User-Agent: Relavia/〈自身版本〉`（应用名 + 版本，
  与浏览器 UA 的通行做法一致），不带设备型号、系统版本细节、
  设备 ID、语言偏好等任何其他标识。清单服务器（含 GitHub）会看到
  请求方 IP，这是静态文件分发的固有事实，文档与设置页须如实告知。
- 检查结果只存本地（序号锚、上次检查时间），不上报。
