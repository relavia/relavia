# Step 16 · 更新机制（签名校验的更新检查与手动升级）

> 对应方案书第 14 章 Step 16：「交付签名校验的更新检查与手动升级流程。验收：篡改包被拒绝的负向用例通过。」
> 基线：阶段 1 验收（90b22cb）。本步只动 `app/` 更新相关新文件、三语词条与本文件 + 格式规范；未改 `spec/`、`core/kernel` 接口；未新增任何第三方依赖（仅 Go 标准库 `crypto/ed25519`）。

## 1. 交付物

| 件 | 路径 | 说明 |
|---|---|---|
| 清单格式规范 | `docs/relavia-update-v1.md` | `relavia-update/v1` 规范性文档（先落盘，主会话裁定的 Step 15/16 共同口径）；Step 15 的 `tools/releasetool` 已按本规范实现并在源码注释中引用本文件为 normative spec |
| 更新服务 | `app/service/update.go` | 平台无关：渠道、检查、版本比较、下载、校验链、安装衔接、周期检查节流 |
| 发行公钥配置点 | `app/service/releasekey.go` | 内嵌公钥常量，当前为 **TEST-ONLY** 测试钥（醒目标注），回填点见 §7 |
| 本地状态字段 | `app/service/store.go`（Settings 增 5 字段） | 渠道/周期开关/回滚锚点/上次检查时间，纯本地记账，永不外发 |
| 平台安装入口 | `app/platform/installer.go` + `installer_windows.go` + `factory_*` 的 `NewInstaller()` | 见 §5 |
| 测试 | `app/service/update_test.go`（21 个测试函数）、`app/platform/installer_test.go`（4 个） | 含全部负向用例，见 §4 |
| 三语文案 | `app/locales/{zh-Hans,zh-Hant,en}` 各 +23 个 `update.*` 键（110→133），i18ncheck 全绿 | 含隐私告知文案 |

## 2. 清单格式（relavia-update/v1，要点；全文见规范文档）

- 静态 JSON、仅 HTTPS 分发。默认地址（GitHub Releases `latest` 资产，与 Step 15 流水线产出的 `update-<channel>.json` 资产名一致，已核对）：
- stable：`https://github.com/relavia/relavia/releases/latest/download/update-stable.json`
- beta：`…/update-beta.json`
- 地址用户可配（镜像/官网静态路径），校验要求不随地址放宽。
- 字段：`format`（恒为 `relavia-update/v1`）、`version`（semver）、`versionCode`（= MAJOR×10000+MINOR×100+PATCH）、`channel`（stable/beta）、`seq`（渠道内从 1 起严格单调递增的发行序号）、`publishedAt`（RFC 3339 UTC）、`notes`（语言→说明，`en` 必备）、`artifacts[]`（`platform` = `<goos>-<goarch>`、`url`、`size`、`sha256` 小写十六进制、`sig` base64）。
- 未知字段忽略（前向兼容）；必填字段缺失/非法 → 整份清单拒绝（`update.manifest_invalid`）。

## 3. 校验链（顺序固定，任一失败即拒绝）

```
拉取清单（≤1MiB）→ 结构校验 → 渠道匹配 → publishedAt 不得超前 7 天以上
→ 回滚防护（§6）→ 版本比较（semver 优先，versionCode 并列裁决）→ 选本平台 artifact
→ 流式下载到.part（进度回调、可取消）
→ 大小核对 → SHA-256 与清单比对 → Ed25519 验签（公钥验「实际算出的摘要」的 sig）
→ 全部通过才改名落盘 → 交平台安装入口
```

要点：

- `sig` = 项目发行密钥（Ed25519）对 artifact 的 **SHA-256 摘要原始 32 字节** 的签名（不是对十六进制文本、不是对整个清单）。验签对象是客户端**自己算出的**摘要——因此「清单 sha256 被换 + 清单 sig 是真签名」的组合也会在哈希比对步被拒；「sha256 对、sig 伪造」在验签步被拒。两类攻击各有独立拦截点（均有测试）。
- 校验失败的下载物**立即删除**（含取消时的 `.part` 残片）；测试逐项断言下载目录无残留。
- 语义边界（如实记录）：v1 的 `sig` 认证的是产物**内容**；版本真实性靠 `seq` 单调性 + 版本比较 + HTTPS 通道三者。未来 v2 可升级为对清单规范化摘要整体签名。

## 4. 负向用例逐项结果（全部通过；`app/service` + `app/platform` 测试实跑）

| # | 用例 | 期望 | 结果 |
|---|---|---|---|
| N1 | 产物被篡改 1 字节（服务端供篡改件，清单为真） | `update.hash_mismatch`，下载物删除 | ✅ `TestDownloadTamperedArtifactRejected` |
| N2 | 清单中 sha256 字段被替换（sig 仍为真签） | `update.hash_mismatch`，删除 | ✅ `TestDownloadManifestHashTamperedRejected` |
| N3 | sig 用攻击者密钥伪造（sha256 为真） | `update.signature_invalid`，删除 | ✅ `TestDownloadForgedSignatureRejected` |
| N4 | 回滚攻击：整份旧清单（真签、版本号甚至更高）但 `seq` 更低 | `update.rollback_detected`，锚点不被污染 | ✅ `TestCheckRollbackBySeq`（跨 Updater 实例、经 Store 持久化验证） |
| N5 | 回滚变体：`seq` 相同但 `publishedAt` 更早 | `update.rollback_detected` | ✅ `TestCheckRollbackSameSeqOlderPublished` |
| N6 | 清单格式损坏（非 JSON / format 标记错 / 渠道不符 / seq=0 / sha256 字段非法 / sig 字段非法 / 产物 URL 非 HTTPS / publishedAt 超前 30 天 / 无 artifacts，共 9 个子例） | 全部 `update.manifest_invalid`，且之后真清单仍可正常检查 | ✅ `TestCheckInvalidManifests` |
| N7 | 截断下载（只发一半字节） | `update.hash_mismatch`，不留半成品 | ✅ `TestDownloadTruncatedRejected` |
| N8 | 下载中途用户取消（慢速端点 + ctx 取消） | `update.download_canceled`，`.part` 删除 | ✅ `TestDownloadCanceledLeavesNothing` |
| N9 | 安装器不可用（Windows 占位/未接线现状） | `update.install_unavailable`，**已验签的安装包保留**并返回路径供手动安装 | ✅ `TestApplyInstallerUnavailableKeepsVerifiedPackage` |
| N10 | 安装器执行失败 | `update.install_failed`，安装包保留、当前版本不受影响（安装契约：失败必须保旧版本可用） | ✅ `TestApplyInstallerFailureKeepsPackageAndOldVersion` |
| N11 | 清单拉取失败（连不上） | `update.manifest_fetch` | ✅ `TestCheckManifestFetchFailure` |
| N12 | 新版本无本平台产物 | Check 返回 `Available + NoArtifact`，Download 返回 `update.no_artifact` | ✅ `TestCheckNoArtifactForPlatform` |

正向：下载+双重校验+改名落盘（`TestDownloadAndVerifyHappyPath`）、Apply 把**已验签**文件交给安装器且路径一致（`TestApplyHappyPathHandsVerifiedFileToInstaller`）、Android 桥安装器未注册 binder 时诚实不可用 / 注册后透传路径与错误（`TestBridge*`）。

**版本比较测试**（`TestSemverCompare` 13 例 + `TestNewerRelease` 8 例）：含预发布序（`0.2.0-beta.1 < 0.2.0`、数字标识按数值比 `beta.10 > beta.9`、短列表小于长列表、数字标识 < 字母标识）、`v` 前缀容忍、非法版本串拒绝、同 semver 以 versionCode 裁决（高者胜、低者不算更新）。

**隐私形状测试**（`TestRequestsCarryNoDeviceIdentity`）：测试服务器记录两次请求（清单+产物）的全部头部并断言：`User-Agent` 恰为 `Relavia/<版本>`、无任何 `X-*` 自定义头、无 `Accept-Language`。

**与 Step 15 的跨实现互操作实证**：用本步测试私钥经 Step 15 的 `tools/releasetool manifest` 生成真清单（v0.2.0 / seq 42），再以客户端内嵌测试公钥按本规范验签 → **通过**（`ed25519.Verify = true`）；且已核对 releasetool 的字段集、`versionCode` 编码、`sig` 签名对象与 release.sh 的资产命名（`update-<channel>.json`）、build.sh 的 `-ldflags -X` 盖章点（读 `app/service/update.go` 的 `ClientVersion`/`ClientVersionCode` 默认值）均与本规范一致，无差异待裁。

## 5. 平台安装衔接

| 平台 | 实现 | 状态 |
|---|---|---|
| 抽象 | `service.UpdateInstaller` 接口（`Available() bool; Install(path string) error`）；契约：收到的路径必为已过双重校验的文件；安装失败必须保持当前版本完全可用 | ✅ 已落地，有 Fake 与测试 |
| Windows | `platform/winInstaller` **占位**：`Available() = false`。预期生产行为 = ShellExecute 拉起 Step 15 流水线产出的安装器后由客户端退出让位替换；因沙箱无 Windows 机，拉起-提权-文件占用-失败回滚序列**不可验证**，按诚实口径报不可用（UI 文案 `update.err_install_unavailable` 引导手动运行已验签的包），列为 Step 19 真机项 | ⚠️ 占位 + 真机待验 |
| Android | `platform.BridgeInstaller` + `InstallBinder` 注册表（与 Step 10 的 VPNBinder 同模式）：Go 逻辑层可用性**恰等于** Kotlin 壳是否注册了 binder；壳侧要做的事 = 对已验签的 APK 文件以 `ACTION_VIEW` + `application/vnd.android.package-archive` 拉起系统安装器（`REQUEST_INSTALL_PACKAGES` 的用户授权在壳侧处理） | ⚠️ Go 侧桥与测试完成；Kotlin 壳的 binder 实现待接线（Step 10 壳侧同类待办：libbox 绑定并列） |
| 其他平台 | `UnsupportedInstaller`，诚实不可用 | ✅ |

衔接点定位：`Updater` 的 `Check →（UI 确认）→ Apply` 三段；UI 层只需在设置页接 `service.NewUpdater(UpdaterConfig{Store, Installer: platform.NewInstaller(), DownloadDir})` 并渲染 `UpdateInfo` 与错误码→`update.err_*` 文案，本步未动 UI 页面（任务口径：只做到服务层与 UI 数据接缝，接缝已由测试覆盖）。

## 6. 回滚防护口径

- 锚点 = 每渠道已接受的最高 `seq` 与其 `publishedAt`，持久化在 Store 设置中（`updateSeenSeq`/`updateSeenPublished`），跨重启有效。
- 新清单 `seq` 小于锚点 → 拒绝（`update.rollback_detected`）；`seq` 等于锚点但 `publishedAt` 更早 → 拒绝。锚点**只在清单通过全部校验后**才推进，被拒清单不污染锚点（N4 断言）。
- `publishedAt` 超前当前时间 7 天以上 → 视为时钟/清单异常拒绝（防伪造未来时间戳掩盖回滚）。
- 锚点是本地状态：卸载重装会清零，残余风险由 HTTPS 通道 + 版本比较兜底（与 §3 语义边界一致，如实记录）。

## 7. 正式公钥回填点（Step 15/发行负责人动作）

1. Step 15 流水线已能生成正式发行密钥对（`tools/releasetool keygen`）；**私钥只由发行负责人保管，永不入仓**（入 CI 仅限签名作业的 secret）。
2. 把正式公钥 base64 替换 `app/service/releasekey.go` 中 `ReleasePublicKeyB64` 常量一处，删除 TEST 横幅，重新发布客户端。此后测试钥签出的任何东西都会被正式版拒绝。
3. 本步测试钥：公钥已嵌在 `releasekey.go`（标注 TEST ONLY），私钥只存在于 `app/service/update_test.go` 的测试夹具中（含伪造用第二把钥），永不用于真实发行。

## 8. 隐私与频率口径

- 检查时机二选一，皆为用户侧动作：**手动触发**（设置页「检查更新」），或**可选的定期检查**——开关 `updateAutoCheck` **默认关**（方案书 §5.5「无强制更新、无静默更新」+ 第 9 章零遥测的合流裁定，取更严口径）；开启后至多每 24 小时在启动时查一次（`AutoCheckDue()` 节流，测试覆盖 0/23/25 小时边界）。**无论哪种，都只查、只提示，永不自动下载或安装**；下载与安装必须逐次经用户确认。
- 请求面：仅静态 GET；代码中唯一设置的头部是 `User-Agent: Relavia/<版本号>`（不含系统/设备/地区信息）；不设 Cookie、不带语言头、不回传任何标识。清单宿主会看到请求方 IP——这是静态分发的固有事实，已写入设置页隐私文案（`update.privacy_note`，三语）与本节，不做虚假承诺。
- 检查结果与锚点只存本地。

## 9. 验证记录（本地实跑）

- `go build./...` / `go vet./...` / `go test./...`（app 全包）：全绿；`service`、`platform` 本步新增 25 个测试函数全过（含 12 项负向/边界用例组）。
- i18ncheck：三包各 133 键，missing/extra/empty = 0，硬编码扫描 violations = 0。
- 交叉编译门：`GOOS=windows go build./...` 通过；`scripts/build-android.sh check`（android/arm64）通过；core 模块 build/vet 与 vpngate 插件测试无回归。
- 新依赖：无（仅标准库）。许可证登记：无新增条目需要。

## 10. 未完成 / 待验（诚实清单）

1. **Windows 应用内安装**：占位实现，真机（Win10/11）验证拉起安装器、提权、运行中文件替换、失败回滚后才可启用 → Step 19 真机清单。
2. **Android 壳侧 InstallBinder**：Go 桥就绪，Kotlin 壳的系统安装器意图实现未接线（与 libbox 绑定同批壳侧待办）。
3. **UI 接线**：设置页的更新区（渠道选择、周期开关、检查按钮、进度与错误文案渲染）未做——本步按任务口径只交服务层与接缝；`update.*` 文案 23 键已备齐。
4. **正式公钥回填**：见 §7，等发行密钥由负责人保管产生（Step 15 keygen 已备）。
5. **默认清单 URL 的真实拉取**：GitHub Releases 上尚无正式 release 资产（`update-stable.json`），真链路待首个正式版本发布时验证；本步以本地 TLS 测试服务器 + Step 15 工具跨实现验签完成等价验证。
6. macOS/Linux 桌面端安装入口：当前为诚实不可用（不在 v1.0 首发平台范围）。
