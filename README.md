> **开发入口**：产品当前是**个人授权的自主安全研究工作台**。先读 [开发总纲](docs/development-charter.md)、[前端 MVP](docs/frontend-mvp.md) 与 [当前实施状态](docs/implementation-status.md)。

<div align="center">

<img src="./README/banner.png" alt="Cairn Banner"/>

# Cairn

### 面向状态空间搜索的问题求解引擎 · 个人授权安全研究工作台

</div>

Cairn 是一个通用问题求解引擎，并已落地为**个人授权的安全研究工作台**。它不预设工作流——给定**起点（Origin）**与**目标（Goal）**，在一个未知状态空间中自主搜索路径。当前两个已验证的问题域：

1. **自主安全研究（研究工作台，本仓库当前重心）**——一次授权后，Agent 在授权范围内自主完成黑盒 / 白盒 / 联动研究：读授权代码、发现接口与交互、提出并验证假设、保存证据、生成报告、修复后复测。
2. **CTF / 通用任务**——继承原引擎的 `Bootstrap / Reason / Explore` 调度与黑板协作。

> 本仓库为 **[oritera/Cairn](https://github.com/oritera/Cairn)** 的分支，由 **[XVSHIFU](https://github.com/XVSHIFU)** 维护，内置**简体中文本地化**。原漏洞挖掘平台已移除；当前以研究工作台为本。

---

## 快速开始（Linux / WSL2 Ubuntu，40 秒内可跑）

```bash
export PATH="$HOME/.local/bin:$HOME/.nvm/versions/node/v22.23.1/bin:$PATH"   # 若用 nvm 装 node 的 pi
git clone --branch main https://github.com/XVSHIFU/Cairn.git ~/Cairn
cd ~/Cairn && uv sync --project cairn --group dev

# ① 后端服务（默认 8000；首次会自动建库 + 迁移）
cairn/.venv/bin/cairn serve --db-path ~/cairn-data/cairn.db --host 127.0.0.1 --port 8000

# ② 研究执行器（认领并运行 queued 研究；这里用 pi 驱动连你的 OpenAI 兼容网关）
cairn/.venv/bin/cairn research-worker \
  --db-path ~/cairn-data/cairn.db \
  --workspace-root ~/cairn-data/research-workspaces \
  --driver pi

# ③ 浏览器打开研究界面
open http://localhost:8000/research          # WSL 里 Windows 浏览器直接可用

# 就绪态检查（available=true 需有可用驱动 claude 或 pi + worker 正在心跳）
curl -s http://127.0.0.1:8000/api/research/runtime
```

> 无 `--driver` 时默认走 **claude**（需已登录的 `claude` CLI）。用 pi 时你的 pi 需已连上 LLM 网关（如 DeepSeek 兼容端点 / 公司 `llm-router`），且该网关为 **OpenAI 兼容**即可。

**研究工作流一次性用法（页面闭环）**
1. **新建研究**：填**网址**（黑盒）/ 本地**代码目录绝对路径**（白盒）/ 两者都填（联动）。
2. **确认一次授权**：核对目标、排除项、允许动作、以及时长/请求/费用上限——授权快照固化，Agent 无权超越。
3. **执行**：worker 在 bwrap 沙箱里运行，逐步产出 `evidence`；可**暂停/续跑**、预算耗尽可**追加预算续跑**（继承原授权）。
4. **收尾**：完成时生成**不可变报告**；目标变化自动**重新排队复测**；confirmed findings 沉淀为跨会话经验。

---

## 研究工作台（当前重心）

面向研究者，常驻本机运行。用户给出目标与材料、**一次确认授权范围**，Agent 自主完成探索、验证、证伪与报告；用户可观察证据、补充方向、暂停和续跑。

### 三种研究模式

| 材料 | 模式 | 完成内容 |
|------|------|----------|
| 网站 / 域名 / IP | 黑盒 | 种子资产、接口与交互发现、假设提出与动态验证、请求/响应证据 |
| 本机代码目录 | 白盒 | 语言/框架自动识别、入口/权限/数据流审计、`file:line` 坐标与版本绑定、审计报告 |
| 代码 + 已运行环境 | 联动 | 代码/路由/请求映射、静态疑点动态验证、基线/变体对照、修复后复测 |

系统依据材料自动识别模式（`web` / `code` / `combined`）。

### 执行与边界

- **真实执行链**：网页创建的研究由独立后台 `research-worker` 认领并实际运行（`queued → running → evidence → completed/report`），不是接口演示。
- **受控边界**：bubblewrap 沙箱——`/repo` 只读挂载授权代码、`/workspace` 可写、宿主 home 不可见；逐请求计数的出站强制代理（LD_PRELOAD `connect()` 拦截，直连也无法绕过），仅放行授权目标与模型网关，越界/配额耗尽即拒绝。
- **一次授权**：授权快照版本化；暂停/续跑/追加预算继承原授权；成本/时长/请求/步数均为硬约束，结算前遥测。
- **可靠性**：失败**分类 + 有界恢复**（仅瞬态 provider/超时自动重排队）；**经验反馈**（confirmed findings 与失败教训注入后续同类目标）；**变化触发复测**（目标代码/url 指纹变化自动重排队）；**自动收束**（预算/步数耗尽时收束为 `completed` + 报告，如实注明未验证项、不编造发现）。

### 可插拔 Agent 驱动

| 驱动 | 默认 | 网络 | 状态 |
|------|------|------|------|
| **claude**（`claudecode`） | ✅ 默认 | Anthropics | 默认且充分验证 |
| **pi** | — | OpenAI 兼容（DeepSeek 等） | **一等驱动**，真实 WSL 单会话已验证（白盒 code 端到端，含 `llm-router`） |
| **codex / mock** | — | — | 接线复用，真实输出未验证 |

```bash
cairn research-worker --driver pi                          # 显式指定
CAIRN_RESEARCH_DRIVER=pi cairn research-worker             # 环境变量覆盖默认
cairn research-worker --driver pi --once                    # 只认领一次（脚本/验收）
```

**诚实标注（重要）**：
- pi 驱动下，**研究结果质量取决于你所连模型**。已针对实际暴露做兼容：当模型漏掉必填布尔 `awaiting_input` 时安全缺省 `false`（**绝不伪造完成**，`terminal` 仍严格）。
- pi 驱动每步**无状态**（依托 worker 每步把全量 evidence/上下文重注入提示词续跑）。
- pi 不回报 `total_cost_usd`，费用无法从信封读取，按「费用待核对」挂账。
- `--driver codex`/`--driver mock` 已接线复用，但**真实研究输出尚未验证**；真正出版前请在已授权目标上做一轮真实单会话冒烟。

---

## CTF 平台接入

内置 CTF 比赛平台自动接入：拉题 → 建项目 → Agent 解题 → 自动提交 flag。

- **Bridge**：`cairn ctf-bridge --server http://127.0.0.1:8000`。
- **适配器**：`cairn/src/cairn/ctfbridge/adapters/` — `dasctf`、`ctfd`，可经 `ChallengeSource` 扩展。
- **预算护栏**：按难度档位限制单项目消耗。

### 通用调度 / 中文提示词 / 测试

- 通用 Dispatcher（CTF/通用）：`cairn dispatch --config dispatch.yaml`（可容器或本地模式）。
- 中文提示词：`dispatch.yaml` 里 `runtime.prompt_group: "zh-CN"`（英文 `"default"`）；研究提示词在 `default/` 与 `mock/`。
- 回归测试（无须 Docker/真实模型）：`uv run --project cairn --group dev pytest`。

> ⚠️ `dispatch.yaml` 与 SQLite 数据（`*.db`）可能含平台凭证，已在 `.gitignore` 排除，**切勿提交**。

---

## 工作原理（通用引擎）

引擎基于**黑板架构**：显式“事实-意图”图，三种原语 **Fact / Intent / Hint**；三种任务由同一 Worker 执行：**Bootstrap**（开始直接求解）、**Reason**（读全图决定下一步）、**Explore**（认领意图并报告发现）。Worker 通过共享黑板协作（Stigmergy），无直接通信。

```
   Cairn Server (facts/intents/hints) ──  Dispatcher（调度/写协议/管理容器）
                                             └── Worker containers（每项目 OODA 循环）
```

支持的通用 Worker 后端：**Claude Code / Codex / Pi**。

---

## 成绩

**腾讯云黑客松 · AI 渗透测试挑战赛 · 第二届**：610 支队伍 / 1,345 名参赛者，**54/54 唯一 AK 全解队伍**，最终第 3 名。该流水线赛前从未测试，比赛当天凌晨首次上线，无训练、无调参、无预定义 Agent 角色。

## 延伸阅读

- [最强 AI 渗透测试智能体：腾讯云黑客松唯一 AK 队伍复盘](https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA)
- [无路之路：从渗透测试到通用问题求解的 Cairn AI](https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w)
- [开发总纲](docs/development-charter.md) · [实施状态](docs/implementation-status.md)

---

## 免责声明

Cairn 是通用问题求解引擎，支持渗透测试、CTF 解题、安全评估与漏洞研究工作流。**仅应在你拥有明确授权（目标所有者事先许可）的环境中运行**。未经授权的安全测试、利用或数据访问可能违法并造成损害。开发者与贡献者不对滥用、误用、损害、损失或由此产生的法律后果负责。

## ⚖️ 许可与致谢

本项目基于 **GNU AGPLv3** 许可开源，供个人与学习用途使用。商业使用请向原作者申请商业许可；提交 PR 即同意你的贡献可在 AGPL-3.0 与本项目商业许可下使用。

本分支由 **[XVSHIFU](https://github.com/XVSHIFU)** 维护，原始项目及所有功劳归于 **[leixiao / oritera/Cairn](https://github.com/oritera/Cairn)**。