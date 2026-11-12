# 贡献指南（Contributing）

感谢你对 Relavia 的兴趣。本项目是开源、非盈利项目，按项目方案书与 GOVERNANCE.md 治理。

## DCO 签署（必需）

本项目采用 **DCO（Developer Certificate of Origin 1.1）**，不要求 CLA 与版权转让。**每个提交必须带 `Signed-off-by:` 行**，表示你认证该贡献符合以下 DCO 条款：

> Developer Certificate of Origin
> Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

操作方法：提交时使用 `git commit -s`，Git 会自动追加
`Signed-off-by: Your Name <your@email>`。缺少签署的贡献在补签前不会被合并。

## 提交与评审流程

1. 先开 Issue 或讨论说明要解决的问题与思路；涉及协议矩阵增减、统一模型大版本、许可证或商标事项的，须先走 RFC（见 GOVERNANCE.md），不要直接提交代码。
2. 从主分支拉取你的工作分支，改动保持聚焦：一个 PR 只解决一件事。
3. 提交前在本机跑通与你改动相关的检查：
   - `core/` 改动：在 `core/` 下执行 `go build ./...`、`go vet ./...`、`go test ./...`；
   - `spec/` 改动：执行 `python3 spec/tests/validate.py`（注意 `spec/` 模型已冻结，变更须遵守 spec/VERSIONING.md）。
4. 提交 PR，说明背景、改动与自测结果；由对应领域维护者评审，评审意见处理完并获批准后合并。
5. 新增第三方依赖前，须先核对许可证与 GPL-3.0-or-later 的兼容性，并在 THIRD_PARTY_NOTICES.md 登记（先例见 docs/step2-许可证审计.md）。

## 约定

- 提交信息简洁说明「做了什么、为什么」，并带 DCO 签署行。
- 代码以 GPL-3.0-or-later 贡献；文档与规范另按其目录的授权说明。
- 参与即同意遵守 CODE_OF_CONDUCT.md。
- 安全问题请走 SECURITY.md 的私密通道，不要公开提交。
