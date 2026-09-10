> **开发入口**：产品当前是**个人授权的自主安全研究工作台**。请先阅读 [开发总纲](docs/development-charter.md)、[前端 MVP](docs/frontend-mvp.md) 与 [当前实施状态](docs/implementation-status.md)。

<div align="center">

<img src="./README/banner.png" alt="Cairn Banner"/>

# Cairn

### 面向状态空间搜索的问题求解引擎 · 个人授权安全研究工作台

</div>

Cairn 是一个通用问题求解引擎，并已落地为**个人授权的安全研究工作台**。它不预设工作流——给定**起点（Origin）**与**目标（Goal）**，在一个未知状态空间中自主搜索路径。当前两个已验证的问题域：

1. **自主安全研究（研究工作台，本仓库当前重心）**——一次授权后，Agent 自主完成授权范围内的黑盒 / 白盒 / 联动研究：理解目标、读授权代码、提出并验证假设、保存证据、生成报告、修复后复测。
2. **CTF / 通用任务**——继承原引擎的 `Bootstrap / Reason / Explore` 调度与黑板协作。

> 本仓库为 **[oritera/Cairn](https://github.com/oritera/Cairn)** 的分支，由 **[XVSHIFU](https://github.com/XVSHIFU)** 维护，内置**简体中文本地化**。原漏洞挖掘平台已移除；当前以研究工作台为本。

---

## 研究工作台（当前重心）

面向个人研究者，在 Kali 等本机运行。用户给出目标与材料、**一次确认授权范围**（目标/排除项、代码目录、运行环境、允许动作、时长/请求/费用上限），Agent 自主完成探索、验证、证伪与报告；用户可以观察证据、补充方向、暂停和续跑。

### 三种研究模式

| 材料 | 模式 | 完成内容 |
|------|------|----------|
| 网站 / 域名 / IP | 黑盒 | 建立种子资产、发现接口与交互、提出假设、动态验证、请求/响应证据 |
| Kali 本地代码目录 | 白盒 | 语言/框架自动识别、入口/权限/数据流审计、**`file:line` 坐标**与版本绑定、审计报告 |
| 代码 + 已运行环境 | 联动 | 代码/路由/请求映射、静态疑点动态验证、基线/变体对照、修复后复测 |

系统会自动依据材料识别模式（`web` / `code` / `combined`），无需用户预选语言或框架。

### 执行与可靠性

- **真实执行链**：网页创建的研究由独立后台进程 `cairn research-worker` 认领并实际运行（`queued → running → evidence → completed/report`），不是接口演示。
- **受控执行边界**：bubblewrap 沙箱——只读挂载授权代码 `/repo`、可写会话工作区 `/workspace`、宿主文件系统不可见；逐请求计数与定域的出站强制代理（LD_PRELOAD `connect()` 拦截，直连也无法绕过），仅允许授权目标，越界/配额耗尽即拒绝。
- **一次授权**：授权快照版本化；暂停/续跑/预算追加继承原授权，不允许重启刷预算。预算（成本/时长/请求/步数）是硬约束，结算前遥测、耗尽后可明确追加预算续跑。
- **失败分类 + 有界恢复**：把执行失败归类（provider 限流 / 超时 / 预算耗尽 / 协议 / 权限 / 执行异常），仅瞬态错误在有界次数内自动重排队，永久失败立即终止。
- **经验反馈**：每轮 confirmed findings 与失败教训沉淀为经验，注入后续同类目标的提示词（带来源引用，仅供参考、非本会话证据）。
- **变化触发复测**：对目标代码/url 计算稳定指纹并建基线；内容变化时把完成的会话自动重新排队复测，复核先前发现是否仍成立。
- **自动收束**：非终态步骤在预算/步数耗尽、无法再开新步骤时自动收束为 `completed` + 报告（如实注明未验证项，不凭空编造发现）。

### 可插拔 Agent 驱动

研究工作流复用共享的 Driver 注册表，支持切换 Agent 后端：

- 默认 **claude**（`--driver claudecode` / 环境变量 `CAIRN_RESEARCH_DRIVER=claudecode`）。
- 可选 **codex / pi / mock**（`--driver codex` 等），复用各驱动已有的命令构造与结果解析。
- claude 为默认且已充分验证；**codex/pi/mock 已接线复用，但真实研究输出质量尚未验证**。

---

## CTF 平台接入

内置 CTF 比赛平台自动接入：拉取题目 → 建项目 → Agent 解题 → 自动提交 flag。

- **Bridge 进程**：`cairn ctf-bridge --server http://127.0.0.1:8000`。
- **适配器**：`cairn/src/cairn/ctfbridge/adapters/` — `dasctf`、`ctfd`，可经 `ChallengeSource` 扩展。
- **预算护栏**：按题目难度档位限制单个项目消耗。

---

## 部署

**环境要求**：macOS 或 Linux、Python ≥ 3.12、[`uv`](https://docs.astral.sh/uv/)、已登录的 `claude` CLI（研究工作流默认）；Docker 仅容器执行模式需要（本地模式不需要）。

### 启动（本地模式）

```bash
# 1) 后端服务 :8000
uv run --project cairn cairn serve --db-path ~/.local/share/cairn/cairn.db

# 2) 研究工作台后台执行器（认领并运行 queued 研究；默认 claude）
uv run --project cairn cairn research-worker --db-path ~/.local/share/cairn/cairn.db

# 3) 通用 Dispatcher（CTF / 通用任务调度；可另行配置）
uv run --project cairn cairn dispatch --config dispatch.yaml

# 4) CTF 平台桥接（可选）
uv run --project cairn cairn ctf-bridge --server http://127.0.0.1:8000
```

研究工作台页面：`http://<host>:8000/research`。

常用参数：

```bash
# 指定工作区根目录、扫描间隔
cairn research-worker --workspace-root ~/.local/share/cairn/research-workspaces --interval 5

# 只跑一轮认领/执行后退出（适合脚本与验收）
cairn research-worker --once

# 切换 Agent 驱动
cairn research-worker --driver codex
```

> 注意：`dispatch.yaml` 与 SQLite 数据文件（`*.db`）可能含平台凭证，已在 `.gitignore` 中排除，**切勿提交**。

### 方式二：Docker Compose（容器模式，用于通用 Dispatcher）

```bash
docker pull ghcr.io/astral-sh/uv:python3.13-trixie
docker compose up --build   # cairn-server:8000 + cairn-dispatcher
```

研究工作台执行器通常在宿主机本地运行（需要访问已登录的 `claude` CLI 与真实文件挂载）。`dispatch.yaml` 的 `runtime.execution` 可选 `local` / `container`。

### 中文提示词

Dispatcher（CTF / 通用任务）提示词支持中英文切换：`dispatch.yaml` 中 `runtime.prompt_group: "zh-CN"`（英文用 `"default"`），Web 界面右上角一键切换。研究工作台提示词位于 `default/` 与 `mock/`。

### 测试

无需 Docker 或真实模型端点即可运行回归测试：

```bash
uv run --project cairn --group dev pytest
```

---

## 工作原理（通用引擎）

引擎基于**黑板架构**：显式的“事实-意图”图，三种原语：

| 概念 | 含义 |
|------|------|
| **事实（Fact）** | 已确认的客观发现 |
| **意图（Intent）** | 已声明但尚未执行的探索方向 |
| **提示（Hint）** | 人类注入的判断，下轮被 Agent 吸收 |

三种任务类型由同一个 Worker 执行：**Bootstrap**（开始直接求解）、**Reason**（读全图决定下一步）、**Explore**（认领意图并报告发现）。Worker 通过共享黑板协作（Stigmergy），无直接通信。

```
   Cairn Server (facts/intents/hints)  ──┬──  |     Cairn Api   |
             ▲                          │     └─────┬──────────┘
             └───── Read / Write ───────┘           │
                                Dispatcher (调度/写协议/管理容器)
                                   └── Worker containers (per project, OODA loop)
```

支持的通用后端：**Claude Code / Codex / Pi**。

---

## 成绩

**腾讯云黑客松 · AI 渗透测试挑战赛 · 第二届**：610 支队伍 / 1,345 名参赛者，**54/54 唯一 AK 全解队伍**，最终排名第 3。该流水线比赛当天凌晨才首次上线，无训练、无调参、无预定义 Agent 角色。

---

## 延伸阅读

- [最强 AI 渗透测试智能体：腾讯云黑客松唯一 AK 队伍复盘](https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA)
- [无路之路：从渗透测试到通用问题求解的 Cairn AI](https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w)
- [开发总纲](docs/development-charter.md) · [实施状态](docs/implementation-status.md)

---

## 免责声明

Cairn 是通用问题求解引擎，支持渗透测试、CTF 解题、安全评估与漏洞研究工作流。**仅应在你拥有明确授权（目标所有者事先许可）的环境中运行**。未经授权的安全测试、利用或数据访问可能违法并造成损害。本项目开发者与贡献者不对滥用、误用、损害、损失或由此产生的法律后果负责。

## ⚖️ 许可与致谢

本项目基于 **GNU AGPLv3** 许可开源，供个人与学习用途使用。商业使用请向原作者申请商业许可；提交 PR 即同意你的贡献可在 AGPL-3.0 与本项目商业许可下使用。

本分支由 **[XVSHIFU](https://github.com/XVSHIFU)** 维护，原始项目及所有功劳归于 **[leixiao / oritera/Cairn](https://github.com/oritera/Cairn)**。