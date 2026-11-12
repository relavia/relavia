# Relavia

**希望所有人都可以看见不一样的世界。**

爱称：「眼睛」。

开源、非盈利的跨平台代理客户端：统一导入、管理和使用各主流协议的节点配置，支持用户自填、订阅导入与授权公共源插件，内核可插拔并渐进自研。

## 状态

**阶段 0 地基中，未发布。** 本仓库目前只有立项文档、统一节点模型（已冻结）与内核适配层接口（待评审），尚无可用的客户端软件。请勿将本仓库的任何内容视为已发布产品。

Relavia 是通用网络工具，不提供、不内置任何节点或订阅服务；用户须自行确保其使用符合所在地法律法规。

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/项目方案书-v0.1.md](docs/项目方案书-v0.1.md) | 项目方案书（定位、架构、协议矩阵、许可证与治理裁定、分步实施计划） |
| [docs/step1-命名候选与检索结论.md](docs/step1-命名候选与检索结论.md) | Step 1：命名候选与初步敲除检索结论 |
| [docs/step2-许可证审计.md](docs/step2-许可证审计.md) | Step 2：拟集成组件许可证审计（硬门禁，有条件通过） |
| [spec/README.md](spec/README.md) | 统一节点模型 v1（已评审冻结）说明 |
| [spec/unified-node-model.schema.json](spec/unified-node-model.schema.json) | 统一节点模型 JSON Schema |
| [spec/VERSIONING.md](spec/VERSIONING.md) | 统一节点模型版本规则 |
| [core/README.md](core/README.md) | 内核适配层接口与 mock（Step 6，待评审） |
| [GOVERNANCE.md](GOVERNANCE.md) | 治理：角色、继任、RFC 流程、DCO |
| [SECURITY.md](SECURITY.md) | 安全政策与漏洞报告方式 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南（DCO 签署、提交与评审流程） |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | 行为准则 |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | 第三方组件与许可证义务清单 |

## 仓库结构

- `core/` — 内核适配层（Go）：接口定义与 mock 实现。
- `spec/` — 统一节点模型规范、示例与校验脚本（已冻结，只按其版本规则变更）。
- `docs/` — 方案书与各 Step 交付文档。
- `.github/workflows/` — CI 基线（core 构建/测试 + spec 校验）。

## 许可证

本项目代码以 **GPL-3.0-or-later** 发布，见 [LICENSE](LICENSE)。文档与规范（`spec/` 下的统一模型等）采用宽松条款单独授权，以便其他项目兼容实现（方案书 10.1）；各目录如有单独的许可证说明，以该说明为准。第三方组件的许可证与分发义务见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 商标提示

代码开源不等于品牌开源。**Relavia** 名称与 Logo 不随代码开源：未经许可，不得以 Relavia 名义分发修改版（修改版须改名），以防冒牌客户端（方案书 10.2）。完整的商标政策文件（TRADEMARK.md）由阶段 0 Step 3 交付，本节为占位说明，政策定版后以该文件为准。

## 已知待办

- **GitHub 组织名与公开仓库**：组织名 `relavia` 的占用状态由 Step 3 并行核查中，本仓库目前仅为本地仓库，未推送任何远程；公开仓库创建与远程推送为后续动作。
- **Go module 路径迁移**：`core/go.mod` 现为中性占位 `openproxy/core`。待 GitHub 组织名确认后，须将 module 路径迁移为组织名下的正式路径，并同步更新 `core/` 内全部 import 路径与 CI 配置；迁移完成前不要新增对该占位路径的外部引用。
- **商标政策与正式检索**：见 Step 3（商标检索结论、商标政策草案、Logo 方向）。
