# OpenVPN 3 安卓构建尖峰（阶段 2 证据）

- 前置门：`docs/openvpn3许可证审查.md` 结论「可接（取 MPL-2.0 一侧）」。本尖峰只回答一个问题：这库能不能在我们的构建链里为安卓编出来、产物多大、依赖各是什么许可证。
- 版本锚：上游 `OpenVPN/openvpn3` 钉死提交 `0c1ce172fe918b05463d71e682a0c2f2d8fe7899`（master HEAD，vcpkg.json version-string 3.12）。升级版本须重跑许可证原文核对（审查文档 §4 义务 5）。
- 沙箱限制（如实）：本机只有 Android SDK 34（build-tools / platform-tools），**没有 NDK**。因此 arm64-v8a 的交叉编译实证无法在本地完成；本地做到的是「同一份构建胶水在宿主机全链路跑通 + 上游核心在宿主机完整链接 + 产物在 JVM 中真实加载运行」，安卓交叉构建以 CI 作业草案交付（见 §5），合并前须在 CI 上实跑一次并回填本文件。

## 1. 构建形态（先说清一个上游事实）

上游 CMake 的 SWIG 目标只产 **Python** 绑定；Java 绑定没有上游现成目标——这是下游集成的标准自维护胶水（ics-openvpn 等均如此自维护）。我们的胶水（仓内 `android/openvpn3/`）：

- `build-openvpn3-android.sh`：每个 ABI 一遍：git 钉死提交 → SWIG 生成 Java + JNI wrapper → vcpkg 以安卓 triplet 装依赖 → CMake 交叉编译 → strip 后 .so 拷入 `android/app/src/main/jniLibs/<abi>/`，生成 Java 源码拷入 `android/app/src/main/java/net/openvpn/ovpn3/`（两处产物都已 git-ignore，不入库，构建时生成）。
- `CMakeLists.txt`：目标 `ovpn3android`（SHARED），源 = 上游 `client/ovpncli.cpp` + 生成的 `ovpncli_wrap.cpp`（+ 其头 `ovpncli_wrap.h`，SWIG 与 cpp 同目录产出，脚本须一并拷入构建目录）+ 上游 `javacli/android/cpu.cpp`。

尖峰中在胶水上实测修正过的点（都已写回上述两文件）：

1. SWIG 调用：`swig -c++ -java -package net.openvpn.ovpn3 -outdir <java> -o <wrap.cpp> -I<src> -I<src>/client <src>/client/ovpncli.i`（脚本实文为准）。该 .i 在 SWIGJAVA 下引入 swiginterface 并开 directors，是 Java 绑定的唯一正确入口。
2. 编译定义对齐上游自身 ovpnclilib 的实测定义集（从其 CMake 产物核出）：`USE_ASIO`（核心头期望的 openvpn_io 别名由此来，缺之必挂）、`HAVE_JSONCPP`、`HAVE_LZ4`、`USE_OPENSSL`、`ASIO_STANDALONE` 等；**不**定义上游测试配置的 `OPENVPN_FORCE_TUN_NULL`（我们要真 TunBuilder 路径）。
3. `javacli/android/cpu.cpp` 要求 `OPENVPN_PACKAGE_ID` 令牌（拼其 CPUUsage JNI 导出名）：给 `org_relavia_client`；本项目不提供该 Java 类，该导出闲置，无害。上游文件零修改（许可证审查义务：不改上游文件）。
4. lz4 / xxHash 的 CMake config 在 vcpkg 下有、Ubuntu 包下无：CMakeLists 里这两项 `find_package(... QUIET)` + 链接行按 TARGET 存在与否回退普通库名，两边可编。
5. 非安卓（宿主机证据构建）时 `find_package(JNI)` 补 jni.h；安卓下 NDK sysroot 自带。
6. **LZO 保持缺席**：宿主机配置时上游报告「lzo not found, skipping lzo compression tests」——LZO 是 GPL-2.0-only 红线依赖，构建链里永不引入（审查文档 §3）。

## 2. 本地实证（2026-11-14，沙箱宿主机 x86-64）

| # | 证据 | 结果 |
|---|---|---|
| E1 | SWIG 4.2.0（apt）按 §1 命令生成 | 42 个 Java 源（包 `net.openvpn.ovpn3`）+ `ovpncli_wrap.cpp`（409,343 B）+ `ovpncli_wrap.h` |
| E2 | 生成 Java 以 javac（JDK 17）编译 | 零错误，46 个 class 产出 |
| E3 | 上游自身 CMake 宿主机配置 + 构建其 ovpncli 目标（依赖 asio/fmt/jsoncpp/lz4/xxhash/OpenSSL 均 apt 件） | 配置完成（仅测试子目录缺 libnl/libcap，补装后通过）；`ovpncli` 可执行链接成功，2,038,976 B——核心库本体可编可链 |
| E4 | 用仓内 `android/openvpn3/CMakeLists.txt` 构建 JNI 目标（宿主机变体，系统依赖代替 vcpkg） | `libovpn3android.so` 构建成功：未 strip 8,073,840 B，**strip 后 5,841,936 B**；`Java_net_openvpn_ovpn3_*` JNI 导出 540 个 |
| E5 | JVM 功能冒烟：`System.load` E4 的 .so，子类化 `ClientAPI_OpenVPNClient`（director 回调），`eval_config` 评两个 profile | 合法 profile：`error=false`；乱写 profile：`error=true`，核心原文报错 `ERR_INVALID_CONFIG: option_error: remote option not specified`——产物不是空壳，是能干活的核心 |

E4 的体积是宿主机 x86-64 数：arm64-v8a 产物通常同量级或略小，**每 ABI 约 5–6 MB（strip 后）量级**，以 CI 实产回填为准，不得把宿主机数直接当安卓数对外引用。APK 现有多 ABI 臃肿问题（KI 挂账）下，发布构建建议只出 arm64-v8a + armeabi-v7a 两 ABI，x86_64 仅模拟器调试用。

## 3. 依赖清单（THIRD_PARTY_NOTICES 草案，合并时并入主文件）

以下为合并进 `THIRD_PARTY_NOTICES.md` 的草案文本（本分支不直接改主文件，避免与在飞批次冲突）：

| 组件 | 版本/来源 | 许可证 | 用法 |
|---|---|---|---|
| OpenVPN 3 core | 提交 `0c1ce17…`（3.12） | **MPL-2.0**（双许可中取此侧；见 `docs/openvpn3许可证审查.md`） | 静态编入 `libovpn3android.so`，进程内 |
| asio | vcpkg `arm64-android` | BSL-1.0 | 头文件库，核心网络层 |
| fmt | vcpkg | MIT | 格式化 |
| jsoncpp | vcpkg | MIT（或公有领域双选，取 MIT） | 配置/JSON |
| lz4（库） | vcpkg | BSD-2-Clause | 压缩（仅库；其 GPLv2 的 CLI 部分不入） |
| xxHash（库） | vcpkg | BSD-2-Clause | 哈希（仅库） |
| OpenSSL | vcpkg（3.x） | Apache-2.0 | TLS。本项目取 OpenSSL 而非 mbedTLS：与桌面端一致，且 AGPL §7 例外在本侧（MPL）本不需要 |
| SWIG | 4.2.0（构建工具） | GPL-3.0（工具，不分发其代码；生成 wrapper 依 SWIG 惯例归使用方条款） | 仅构建期 |

注：构建期工具与测试期组件（gtest 等）不进 APK，不列入分发登记。

## 4. 钉死与复现

- 脚本内 `OPENVPN3_COMMIT` 环境变量可覆盖、默认钉死上述提交；克隆后校验 HEAD 一致才继续。
- vcpkg 以 baseline 钉版（脚本用 vcpkg 仓自身提交钉版，CI 草案中固定 `VCPKG_COMMIT`）；依赖版本漂移须在尖峰文档留痕。
- SWIG 版本钉 4.2.0（生成代码与 SWIG 运行时强相关，换版本须重跑 E1/E2/E5）。

## 5. CI 作业草案（yml 片段，合并时并入 `.github/workflows/ci.yml`，本分支不直接改）

```yaml
  openvpn3-android:
    name: openvpn3 (android arm64 spike)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
      - name: Install SWIG 4.2 + build tools
        run: sudo apt-get update && sudo apt-get install -y swig cmake ninja-build
      - name: Setup Android NDK
        uses: nttld/setup-ndk@v1
        id: ndk
        with:
          ndk-version: r27c
          add-to-path: false
      - name: Checkout vcpkg (pinned)
        run: |
          git clone https://github.com/microsoft/vcpkg.git /tmp/vcpkg
          git -C /tmp/vcpkg checkout 2024.12.16
          /tmp/vcpkg/bootstrap-vcpkg.sh -disableMetrics
      - name: Build libovpn3android (arm64-v8a)
        env:
          ANDROID_NDK_HOME: ${{ steps.ndk.outputs.ndk-path }}
          VCPKG_ROOT: /tmp/vcpkg
        run: ABIS=arm64-v8a android/openvpn3/build-openvpn3-android.sh
      - name: Report artifact
        run: ls -la android/app/src/main/jniLibs/arm64-v8a/
      - uses: actions/upload-artifact@v4
        with:
          name: libovpn3android-arm64
          path: android/app/src/main/jniLibs/arm64-v8a/libovpn3android.so
```

合并验收口径：该作业在 CI 上绿 + 产物 .so 存在且体积回填本文件 §2，才算阶段 2 在安卓目标上闭环；在此之前阶段 2 的状态是「宿主机全链路实证 + 安卓作业草案」。

## 6. 未验项（如实）

- arm64-v8a / armeabi-v7a / x86_64 交叉编译：未跑（无 NDK），靠 §5 作业。
- Gradle 把 .so 与生成 Java 打进 APK 的全链路：随合并后 CI 的 android 作业验证（本分支 Kotlin 已过手工编译门，见接线文档）。
- 真机加载 .so（JNI_OnLoad、符号解析）：真机门。
