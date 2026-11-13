# Step 15 签名与可复现构建（完成记录）

> 方案书第 14 章 Step 15：交付签名流水线、复现构建文档与第三方
> 验证记录。验收：独立环境按文档复现成功。
>
> 本步由两任执行体接力完成：前任留下未提交的流水线半成品后中
> 断；本记录由接手方先审计、逐项复跑，再补齐缺失后落盘。第 2
> 节是审计结论——前任产出未经复核的部分不计入成果。

## 1. 交付总览

| 件 | 内容 |
|---|---|
| `VERSION` | 版本单一事实源（0.1.0）；编码 MAJOR*10000+MINOR*100+PATCH 与清单规范 §2、客户端 ClientVersionCode 同源 |
| `scripts/release/version.sh` | 由 VERSION 派生 VERSION / VERSION_CODE / GOGIO_VERSION（MAJOR.MINOR.PATCH.CODE） |
| `scripts/release/build.sh` | 三类产物的确定性构建：windows exe / shell 壳 APK / gio 逻辑 APK |
| `scripts/release/release.sh` | 发行组装：构建 → 平台签名段 → 清单生成与自验 → SHA256SUMS + RELEASE-NOTES |
| `tools/releasetool` | 清单生产方工具：keygen / manifest / verify，严格实现 docs/relavia-update-v1.md |
| `scripts/release/repro-check.sh` | 复现检查：两棵隔离导出树双构建比对 SHA-256，三档结论 |
| `scripts/release/zipdiff.py` | APK/ZIP 条目级差异定位（内容差 / 仅元数据差 / 条目序差） |
| `android/app/build.gradle.kts`（改） | 壳版本身份改由仓库根 VERSION 派生，可经 -P 属性覆写（build.sh 传入） |
| `scripts/build-android.sh`（改） | gio 入口改为委托 release/build.sh（单一实现）；check/bind/shell 不变 |
| `.github/workflows/ci.yml`（改） | 新增 repro 作业：releasetool 门 + 三目标复现检查（见 §3） |
| `docs/复现构建验证指南.md` | 第三方验证指南（第一层验签 + 第二层复现的完整步骤） |

确定性构建纪律（build.sh）：Go 工具链由 go.mod 的 go 指令钉
在 1.25.5、模块图由 go.sum 锁定；全部构建带 `-trimpath
-buildvcs=false`，Windows 另加 `-buildid=` 与 `-s -w`；版本以
`-ldflags -X` 盖入 ClientVersion。ClientVersionCode 是 int 变
量、无法用 -X 盖章（工具链实测拒绝），故 build.sh 在构建前断
言源码默认值与 VERSION 一致，不一致即拒绝构建——版本变更必
须以「改 update.go 默认值 + 改 VERSION」的同一提交完成。

## 2. 审计清单（前任半成品，逐项复核）

### 2.1 已成立（复跑验证后采信）

- **tools/releasetool**：源码逐行对照规范 §2/§4——签名单一事
  实源、签名对象为产物 SHA-256 的原始 32 字节（测试含「对十六
  进制文本验签必须不成立」的反向断言）、versionCode 编码、
  seq≥1 强制、重复 platform 拒绝、无钥只出明确警告的未签名草
  稿。测试 7 个函数以 `-count=1` 实跑全过；§5 的演练由接手方
  独立复跑（不只采信其自带测试）。
- **scripts/release/build.sh**：确定性旗标与版本断言设计成立；
  Windows 构建在隔离导出树实跑成功且可复现（§3）。
- **scripts/release/version.sh**：派生口径与规范、客户端、壳
  工程三处一致。
- **VERSION = 0.1.0**：与 app/service/update.go 的
  ClientVersion/ClientVersionCode 默认值（0.1.0 / 100）一致，
  build.sh 断言实跑通过。
- **android/app/build.gradle.kts 的未提交 hunk**：逐行核对，
  全部为版本身份派生（VERSION → versionName/versionCode +
  -P 覆写），属 Step 15；libbox 的 AAR 依赖 hunk 已在 031b611
  入库，本 hunk 与之无交叠。
- **scripts/build-android.sh 的未提交 hunk**：逐行核对，仅
  gio 函数改为委托 release/build.sh，无 libbox 残留（bind 与
  check/shell 段未动）。注意一处语义变化并确认其正确性：
  gogio 的 -version 由 0.1.0.1 变为 0.1.0.100——这是版本编码
  向规范 §2 的 MAJOR*10000+MINOR*100+PATCH 统一（客户端默认
  值 100、壳工程派生值 100 三处已同源），ac66016 记录的
  「versionCode 1」口径就此被规范编码取代，属预期演进、非
  冲突。
- **zipdiff.py**：逻辑成立（内容/元数据/条目序三类差异分开报
  告）；仅一处 f-string 少分隔符的显示瑕疵，接手方顺手修
  正。

### 2.2 半成品（接手方修复，均为实跑发现）

- **repro-check.sh 原样不可用**：它以 `git archive HEAD` 导出
  源码，而流水线文件本身尚未提交——导出树里根本没有
  scripts/release/ 与 VERSION，原样运行只会假失败。已加
  `--worktree` 模式：经临时索引（GIT_INDEX_FILE + write-tree，
  不动真实索引）导出当前工作树，专供「流水线自身的提交前验
  证」；正式发行验证仍默认 HEAD 口径，注释已写明。
- **repro-check.sh 的 shell 目标原样永远失败**：Gradle 壳工
  程按设计强依赖 gitignored 的 libboxbind.aar（libbox 步裁
  定：缺失即构建错误），而任何源码导出都不含 AAR。已改：检
  查前若检出目录已有 AAR，把同一份 AAR 作为共同输入注入两
  棵导出树（报告中明示其 sha256），验证口径为「给定该输入
  的 Gradle 打包复现性」；无 AAR 时明确报 UNVERIFIED (env)
  并给出生成方法，不再误报构建失败。
- **release.sh 从未端到端跑通过**：在无 ANDROID_HOME 的环境
  里，它会在产物构建后**静默以 1 退出**、不产出清单与说明。
  根因是 `set -e` 下三处裸 `&&` 列表（首个测试为假即整表返
  回 1 并杀死脚本）：apksigner/zipalign 探测两行、无钥分支的
  两条 note_status 行、MANIFEST_ARGS 的两行。已全部改为
  if 守卫，并在首处留注释说明该陷阱。
- **release.sh 的状态记录丢消息**：note_status 只写 $1（键
  名），把消息参数丢弃，而 get_status 按「键 + 空格」grep 并
  从第 2 字段切分——RELEASE-NOTES 的「Per-artifact status」
  段因此恒为空。已改为记录「键 + 完整消息」。
- **release.sh 的来源信息两处不实**：java 行会把 shell 的
  「command not found」错误文本混进记录（已改显式判存）；
  go 行记录的是启动器版本（本机 1.23.12），已改为在 app 模
  块目录内取版本，记录有效工具链（1.25.5）。
- **release.sh 的 Windows 签名口径措辞**与 2026-11-13 裁定不
  一致（原文写作「等用户买证书」），已改为既定口径表述（§6）。

### 2.3 缺失（接手方补齐）

- **CI repro 作业不存在**：repro-check.sh 的注释引用了
  「the CI repro job」，而 ci.yml 里并无此作业——悬空引用。
  已按注释承诺补齐（§3）。
- **本步文档与第三方验证指南**：原不存在，已写（本文件 +
  docs/复现构建验证指南.md；release.sh 的 RELEASE-NOTES 里
  对指南的引用就此有着落）。
- **复现性实证**：原无任何双构建记录，已实跑补齐（§3）。

## 3. 复现性结论（逐产物分级）

验证环境（接手方本机沙箱，2026-11-13）：Linux，有效 Go 工具
链 1.25.5（启动器 1.23.12 自动切换）；PATH 无 Android
SDK/NDK/Gradle；检出目录无 libboxbind.aar。导出源为提交前工
作树（临时索引树 0dd8f9e2c6aafed5625cde1ae4979fce28c898fc）；
该树与本步提交树的差异仅为 release.sh（不参与产物构建）与
两份文档，构建输入（build.sh / version.sh / app / core /
plugins / tools）逐字节一致（提交前以树间 diff 机械核对）。
提交后的 HEAD 口径由 CI repro 作业复验。

| 产物 | 分级 | 证据 |
|---|---|---|
| Windows exe | **逐字节复现** | repro-check A/B 两棵隔离导出树（不同绝对路径）双构建哈希一致，且独立诊断导出第三遍构建同哈希：`4b8c825dffa48ba3b80802135baf35b896e891804c009f56a368b85064f7e6fe`（50,421,760 字节）。release.sh 组装 drill 中的第四遍构建同哈希 |
| Android 壳 APK | **未验证（环境）** | 沙箱双重不具备：检出无 AAR（按设计为必需输入）+ Gradle 在沙箱不可用（Step 10 既有实测结论）。证据路径已备：CI repro 作业先 bind 出 AAR、再注入双树构建比对。风险预登记：Gradle 产物含 ZIP 时间戳等元数据，若 CI 显示哈希不同而 zipdiff 仅报元数据差，分级为「内容等价、容器元数据未归一」，归一化列后续工作——在 CI 首跑出结论前不预称可复现 |
| Android gio 逻辑 APK | **未验证（环境）** | 沙箱无 NDK，gogio 构建无法执行（repro-check 报 UNVERIFIED (env)，双遍 rc=3）。证据路径：CI repro 作业（runner 镜像含 NDK）。前提明示：签名 APK 的字节复现要求同一钥——检查时以一次性 TEST-ONLY 钥供双遍共用 |
| libboxbind.aar 本身 | **未验证** | gomobile/NDK 构建不在本步检查范围；其复现性单列挂账，不因壳 APK 的结论被连带宣称 |

过程如实记录：首轮全量 repro-check（03:50 UTC）中 windows 的
A 遍构建以 rc=1 失败、B 遍成功——冷缓存环境下的一次性失败
（工具链与模块首次经代理下载），其日志随检查临时目录被自动
清理、未能留存原文；随后以同一导出树在独立目录复建成功，
正式 A/B 复跑（03:58 UTC）双遍同哈希。故首轮结果不计为复现
性结论，仅在此留痕。

CI repro 作业（新增，口径）：releasetool 的 build/vet/test 为
硬门；windows 复现为硬门；shell/gio 为 continue-on-error 的
取证步（报告恒上传为构件 relavia-repro-reports）——两者的字
节复现尚无 CI 记录，先取证、待证据转绿后再升硬门，不预设结
论。本步提交推送后该作业首跑结果由主会话复核。

## 4. 签名流水线与密钥注入点清单

一切密钥经环境变量注入、只存于发行负责人保管处，永不入库、
永不进 CI 日志。流水线对缺钥一律大声降级，绝不静默出包：

| 注入点 | 用途 | 缺席时行为 |
|---|---|---|
| `RELAVIA_RELEASE_KEY` | Ed25519 发行私钥文件路径（清单签名） | release.sh 在清单步前中止；仅 `--allow-unsigned` 可出明确标示的未签名草稿（客户端会拒绝） |
| `RELAVIA_RELEASE_PUBKEY` | 发行公钥文件路径 | 清单照签，但自验跳过并在 RELEASE-NOTES 与日志中警告 |
| `RELAVIA_ANDROID_KEYSTORE` / `_PASS` / `RELAVIA_ANDROID_KEY_ALIAS` / `RELAVIA_ANDROID_KEY_PASS` | Android 发行钥店 | 壳 APK 保持未签名、gio APK 用 gogio 兜底钥；两者在 RELEASE-NOTES 标为不可分发 |
| `RELAVIA_WIN_PFX` / `RELAVIA_WIN_PFX_PASS` | Windows Authenticode 证书（可选段） | exe 保持未签名——按 §6 裁定这是既定发行口径，不是缺陷 |

工具侧（releasetool）：keygen 生成的私钥文件权限 0600 且拒绝
无 `--force` 覆盖；工具只读钥文件、从不打印私钥。测试钥纪
律：演练与夹具钥一律标注 test-only、只存放在仓库之外（本步
演练钥位于验证机 /tmp，已随记录注明指纹）；Step 16 夹具私
钥只存在于 app/service/update_test.go，其公钥即客户端当前内
嵌的 TEST-ONLY 公钥（app/service/releasekey.go 有醒目横幅）。

发行前置条件（release.sh 不代办、须发行人先行）：在发行检
出目录运行 `scripts/build-android.sh bind` 生成
libboxbind.aar，否则壳 APK 构建按设计失败、组装大声中止。

seq 的事实源是该渠道上一份已发布清单的 seq（release.sh 强
制要求 --seq 或 RELAVIA_UPDATE_SEQ，不给不发）。

## 5. 演练记录（test-only 密钥，接手方 2026-11-13 实跑）

**演练 A — keygen 与钥注入链（新生成测试钥）**
- `releasetool keygen` 生成测试钥对：公钥
  `sd/ezwGzm5aRBNk2nDov9vz5NtlKwBX2O6m+OdkAA+M=`，指纹
  `SHA256:CCfSy8gYwfgWXPxI2aL+Uy5bcV7r8QEjqqP7iR8S1G4=`；
  私钥 0600、落在仓库外。
- 对 §3 的已复现 exe 生成清单（v0.2.0 / code 200 / stable /
  seq 42，与 Step 16 记录同参数）：`releasetool verify
  --dir` 输出 `signature OK, file hash OK` 与 `manifest OK`。
- 负向：产物第 1024 字节处改 1 字节后 verify 以
  `HASH MISMATCH`（实算 9330fb08… 对清单 4b8c825d…）拒绝，
  退出码 1。

**演练 B — 跨实现一致（Step 16 客户端验生产方字节）**
- 先决核对：从 update_test.go 取出的夹具私钥所派生公钥与客
  户端内嵌 ReleasePublicKeyB64 逐字一致（指纹
  `SHA256:vBpVvEd01fIy/a29DenfMm6TdyMTN4eIXvtVVXWROdY=`）。
- 以夹具私钥经 releasetool 生成清单（v0.2.0 / seq 1，产物为
  同一 exe 字节），写入临时客户端测试（不入库、跑后已删）经
  客户端真实路径验证：`UpdateManifest.Validate()` 通过 →
  `Updater.Check` 检出更新 → `Updater.Download` 以内嵌公钥
  完成 size/SHA-256/Ed25519 全链校验并落盘一致 →
  篡改 1 字节的产物被客户端以 `update.hash_mismatch` 拒绝。
  **结论：生产方（releasetool）与消费方（客户端服务层）跨实
  现一致，Step 16 的同结论经独立复跑再次成立。**
- 过程中的一个真实发现：清单 artifact 的 url 必须是
  https——客户端 Validate 对 http 占位地址直接拒绝
  （`url is not https`），与规范 §1「只经 HTTPS 分发」一
  致；演练占位地址改用 https 后通过。属演练设置问题、非格
  式分歧。

**演练 C — release.sh 端到端（注入夹具钥）**
- 修复前：静默中途退出（§2.2），只出 exe、无清单无说明。
- 修复后：退出码 0，产出 exe + `update-stable.json`（独立以
  releasetool 复验通过）+ SHA256SUMS + release-pubkey.txt +
  RELEASE-NOTES；状态段如实记录：windows 未签名（§6 口
  径）、gio/shell 本环境 MISSING、无 Android 钥店、清单已签
  且自验通过（含文件复算）。

## 6. 发行签名口径（2026-11-13 用户裁定，定版）

- SignPath Foundation 条款明文不受理 security-circumvention
  类工具且为裁量审核——本项目属该类，**按不可用规划、不递
  交**。
- 付费代码签名证书（OV/EV）需实名身份验证，与本项目的安全
  姿态冲突，**不作为路径**。
- 故 Windows 发行既定口径为：**未签名 exe + Ed25519 签名更
  新清单 + 官网公布 SHA-256**。Authenticode 在流水线中保留
  为可选段（注入证书即启用），当前不启用。
- Android 发行钥店由发行负责人保管、仅注入使用；发行公钥
  （Ed25519）回填点为 app/service/releasekey.go 单一常量
  （Step 16 §7）：正式钥对以 `releasetool keygen` 在负责人
  环境生成，私钥不出该环境，公钥替换常量并删除 TEST 横幅
  后重发客户端——此动作属发行负责人，本步只备好工具与点
  位，未替负责人生成正式钥。

## 7. 第三方验证记录（首份）

按 docs/复现构建验证指南.md 执行（执行人：本步接手方；
时间：2026-11-13 03:50–04:03 UTC；环境：§3 所述沙箱）：

1. 第一层：对演练产物执行指南 §2 全流程——sha256 与清单条
   目一致；releasetool verify 验签与复算通过（演练 A/C 两
   套清单）；篡改负向被拒（演练 A）。
2. 第二层：以指南 §3 的 repro-check 从干净导出树双构建
   windows 目标——逐字节复现成立（哈希见 §3）；shell/gio
   在本环境按指南口径记 UNVERIFIED (env)，其全环境复验由
   CI repro 作业承接（指南已注明该路径）。
3. 指南本身的可执行性即本记录：步骤与仓库脚本一一对应，
   无指南外操作。后续每次正式发布应由非发行人按指南复验并
   把记录追加到发布说明。

## 8. 官网/仓库侧签名政策说明要点（交 Step 17 / 主会话）

站点仓不在本步改动范围；官网下载页与仓库 README 应刊载的
签名政策要点如下（Step 17 落地时逐字采用或经主会话核准后
改写）：

- 本项目 Windows 程序**不带 Authenticode 签名**（发布者显
  示为未知）——这是刻意且公开的发行政策，原因与替代验证方
  式链接到本文件 §6 与验证指南；不要写成「即将补上」。
- 每个 Release 附 `SHA256SUMS` 与签名的 `update-<channel>
  .json`；下载页给出发行公钥指纹（正式回填后更新）与
  docs/复现构建验证指南.md 的链接，鼓励按指南验签/复现。
- 客户端内更新走同一签名链自动校验（指回 Step 16 文档）。
- 「其他任何站点提供的安装包均非官方」——官网既有声明与此
  政策并列刊载。
- Android：壳与逻辑 APK 以发行钥店签名（负责人保管）；钥
  店证书指纹在正式发行时随发布说明公布，供带外核对。

## 9. 未完成与挂账

1. **正式发行钥对未生成、公钥未回填**——发行负责人动作
   （§6），工具与点位已备；在此之前一切「已验签」都只对
   TEST-ONLY 钥成立，文档与客户端横幅均已如实标注。
2. **shell/gio 的 CI 复现首跑证据未出**——待本步提交推送后
   由 repro 作业产生，主会话复核；若 shell 出现仅元数据差
   异，按 §3 预登记口径分级并另立归一化工作。
3. **libboxbind.aar 自身复现性未验**（§3）。
4. **真机/发行环境项不在本步**：真实发行时 release.sh 的
   Android 签名段（apksigner 实签）与 Windows 可选签段未在
   本环境实跑（无钥店/证书），属首次正式发行时的现场验收
   项，不预称通过。
5. spec/ 独立许可证文本、双 spec 镜像收敛等阶段 1 挂账与本
   步无关，未动。

## 10. 回归记录（接手方实跑，2026-11-13）

- core：build / vet / test 全绿（kernel、mock、killswitch、
  parsers、routecfg、singbox、specnode）。
- app：vet（Linux + GOOS=windows）全过；test 全绿
  （android、i18n、libboxbind、platform、service）；本机
  `go build ./...` 仅两处 cmd 入口的宿主链接因沙箱缺 Gio 桌
  面系统库（libEGL 等，CI 以 apt 步骤补齐）失败——环境边
  界、非代码问题；Windows 交叉构建（CI 同命令）成功。
- plugins/vpngate：build / vet / test 全绿。
- tools/releasetool：build / vet / test（-count=1）全绿。
- i18ncheck：三语各 133 键、missing/extra/empty 均为 0、扫
  描违规 0。
- scripts/build-android.sh check：通过（android/arm64 交叉
  编译门，含 libboxbind）。
- spec 校验：正例全过、反例 9/9 拒绝。
