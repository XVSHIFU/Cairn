<div align="center">

<img src="./README/banner.png" alt="Cairn Banner"/>

# Cairn

### 不止是 AI 渗透测试 — 面向通用状态空间搜索的问题求解引擎

</div>

Cairn 是一个通用问题求解引擎。它不定义角色、不预设工作流。给定一个 **起点（Origin）** 与一个 **目标（Goal）**，它在一个未知的状态空间中自主搜索路径。AI 渗透测试只是其中一个已验证的问题域。

> 本仓库为 **[oritera/Cairn](https://github.com/oritera/Cairn)** 的分支，额外内置了 **简体中文本地化**（中文 Agent 提示词 + 中英双语 Web 界面），详见 [中文支持](#中文支持)。

---

## 什么是 Cairn？

渗透测试本质上是对 **近乎无限状态空间的有向搜索**：

- **起点（Origin）**：已知（目标 IP、目标系统）
- **目标（Goal）**：明确（拿到 shell、夺取 flag）
- **路径（Path）**：未知

这种结构并不局限于渗透测试。漏洞研究、数学证明、CTF 解题 —— 任何"起点明确、成功条件明确、中间路径未知"的问题都具有相同形态。Cairn 正是为这一类问题而生，渗透测试是它第一个被验证的领域。

引擎基于 **黑板架构（Blackboard Architecture）**，核心是一个显式的"事实-意图"图，只需三种原语：

| 概念 | 含义 |
|------|------|
| **事实（Fact）** | 一条已确认的客观发现，写入黑板 |
| **意图（Intent）** | 一个已声明但尚未执行的探索方向 |
| **提示（Hint）** | 人类随时注入的判断，下一次读取时被 Agent 吸收 |

图从 `origin` 向 `goal` 生长：每个新 Fact 都是一块垫脚石，每个 Intent 都是迈向未知的一步。

Agent Worker 运行 **OODA 循环** —— 观察（Observe）完整图、定向（Orient）当前状态、决策（Decide）下一步意图、行动（Act）探索并写回新 Fact。Worker 没有固定角色，任务由运行时根据图状态动态生成，而非预定义岗位说明。

Agent 之间仅通过共享黑板协作（**Stigmergy / 涌现式协作**），无直接通信，无信息孤岛。

## 工作原理

三种任务类型，均由同一个 Worker 执行：

| 任务 | 作用 | 输出 |
|------|------|------|
| **Bootstrap** | 项目开始时直接尝试求解问题 | 事实 + 可能的 Complete |
| **Reason** | 读取完整图：目标是否达成？下一步该探索什么？ | Complete / 新意图 / no-op |
| **Explore** | 认领一个意图，执行探索，报告发现 | 一条事实 |

系统架构：

```
          ┌──────────────────────────────────┐
          │           Cairn Server           │
          │      Facts + Intents + Hints     │
          └─────────────────┬────────────────┘
                            │
                     Read / Write API
                            │
          ┌─────────────────┴────────────────┐
          │             Dispatcher           │
          │   调度任务、管理容器、写协议     │
          └──────────┬───────────────┬───────┘
                     │               │
     ┌───────────────┴──┐     ┌──────┴──────────────┐
     │  Worker Container│     │  Worker Container   │
     │   (Project A)    │     │   (Project B)       │
     │  ┌────┐  ┌────┐  │     │  ┌────┐  ┌────┐     │
     │  │ W. │  │ W. │  │     │  │ W. │  │ W. │     │
     │  └────┘  └────┘  │     │  └────┘  └────┘     │
     └──────────────────┘     └─────────────────────┘
```

- **Cairn Server**：仅维护图的一致性。
- **Cairn Dispatcher**：读取图、调度任务、拉起/销毁 Worker 容器，是协议的唯一写入方。每个项目拥有独立的 Worker 容器，容器内多个 Agent Worker 并发运行；Agent Worker 只接收提示词并返回结构化输出。
- Worker 也可以直接跑在调度器所在宿主机上（**本地模式**，无需 Docker），见 [部署](#部署)。

支持的 Worker 后端：**Claude Code**、**Codex**、**Pi**。

## 中文支持

本分支在原版基础上加入了两层简体中文本地化，均可随时切换回英文：

| 层面 | 英文（原版） | 中文（本分支） |
|------|-------------|---------------|
| **Agent 提示词** | `runtime.prompt_group: "default"` | `runtime.prompt_group: "zh-CN"`（改 `dispatch.yaml`，重启生效） |
| **Web 界面** | 右上角 `EN` | 右上角 `中文` 按钮（无需改配置，浏览器记住选择） |

**提示词层**：`cairn/src/cairn/dispatcher/prompts/zh-CN/` 内含 5 个中文提示词模板，在原版英文指令基础上新增 `## Language` 规则，强制 Agent 产出的 `fact.description`、`intent.description`、reason 文本一律使用简体中文；JSON 键名、枚举值、`fact/intent` 的 id、技术标识符（IP/URL/CVE/路径/命令）保持原样不变。

**界面层**：`index.html` 整站文案中英双语，右上角 `EN / 中文` 一键切换，按浏览器语言自动默认，选择持久化在浏览器 localStorage。

**预构建成品**（`dist/` 目录）：

- `cairn-zh-CN-0.2.1.zip` — 中文独立增量包。下载原版 Cairn 后解压到项目根、运行 `./install.sh` 即可切换中文，无需改任何 Python 代码。
- `Cairn-0.2.1-zh.zip` — 完整中文版整包，开箱即用。

## 部署

**环境要求**

- macOS 或 Linux
- Python ≥ 3.12
- `uv`（Python 包管理器，参考 https://docs.astral.sh/uv/ ）
- Docker（仅容器执行模式需要，本地模式不需要）
- 已登录的 `claude` / `codex` / `pi` CLI（本地模式需要）

**拉取 Worker 容器镜像**（两种部署方式都需要，本地模式除外）：

```bash
docker pull --platform=linux/amd64 ghcr.io/oritera/cairn-worker-container:latest
```

创建你的调度器配置并填入 LLM 端点与 API key：

```bash
cp dispatch.example.yaml dispatch.yaml        # 容器模式
# 或
cp dispatch.local.example.yaml dispatch.yaml  # 本地模式
```

### 方式一：本地模式（无需 Docker，推荐）

Worker 直接跑在调度器宿主机上，复用本机已配置好的 `claude` / `codex` / `pi` CLI——无需 Docker，也无需在配置里写 API key。

```bash
# 仓库根目录一键起停
./cairn-local.sh start      # 启动 server(:8000) + dispatcher
./cairn-local.sh status     # 查看进程与 API 状态
./cairn-local.sh stop       # 停止
./cairn-local.sh restart    # 重启

# 或手动
uv run --project cairn cairn serve                          # 后端 :8000
uv run --project cairn cairn dispatch --config dispatch.yaml # 调度器
```

本地模式通过 `runtime.execution: local` 开启（参见 `dispatch.local.example.yaml`）。调度器启动时检查每个配置的 Worker CLI 是否可执行，并提示它们必须已登录。每个项目在 `local.workspace_root`（默认：调度器当前目录）下获得独立工作目录。**请直接在宿主机上运行调度器，不要放进 Docker**——Agent 将以你的用户权限运行且无沙箱。

漏洞分析 profile 采用更严格边界：本地运行必须关闭任意宿主环境继承，且不允许使用仍可读取宿主文件的本地 Codex driver；生产配置优先使用 `enforce_isolation: true` 的容器模式。Worker 的 stdout/stderr 都有字节硬上限，超限会终止整个进程组并按失败处理。

### 方式二：Docker Compose（容器模式）

```bash
docker pull ghcr.io/astral-sh/uv:python3.13-trixie
docker compose up --build
```

这会启动 `cairn-server:8000`，待其通过健康检查后启动 `cairn-dispatcher`。dispatcher 挂载项目根目录的 `dispatch.yaml`，通过宿主机 docker.sock 连接 Docker。数据持久化到 `./datas/cairn/`。

漏洞分析容器使用只读根文件系统、删除全部 Linux capabilities、`no-new-privileges`、PID/内存/CPU 上限及有界 `/tmp`。已有项目容器不满足同一隔离版本时会拒绝复用，需由运维移除后按当前配置重建。

### 方式三：手动

```bash
# 启动 server
uv run --project cairn cairn serve

# 运行 dispatcher
uv run --project cairn cairn dispatch --config dispatch.yaml

# 仅做启动健康检查
uv run --project cairn cairn dispatch --config dispatch.yaml --startup-healthcheck-only
```

### 启用中文提示词

```yaml
# dispatch.yaml 中
runtime:
  prompt_group: "zh-CN"     # 英文则用 "default"
```

重启 server 与 dispatcher 后生效。

### 测试

无需 Docker 或真实模型端点即可运行快速回归测试：

```bash
uv run --project cairn --group dev pytest
```

## CTF 平台接入

Cairn 内置了 CTF 比赛平台自动接入：拉取题目 → 建项目 → Agent 解题 → 自动提交 flag。

- **Bridge 进程**：`uv run cairn ctf-bridge --server http://127.0.0.1:8000`（与 server/dispatcher 并列运行）。
- **适配器**：`cairn/src/cairn/ctfbridge/adapters/` — 目前含 `dasctf`（西湖论剑/DasCTF）与 `ctfd`（CTFd 通用）两个实现，可通过 `ChallengeSource` 基类扩展新平台。
- **配置**：接入凭证通过设置页或 `PUT /ctf/config` 写入（`base_url` + `token` + `adapter`），模型配置复用 `dispatch.yaml` 的 worker 环境。
- **Flag 提交**：自动剥离 `DASCTF{...}` / `flag{...}` 外壳，只提交花括号内内容；`auto_submit` 控制是否自动提交。
- **预算护栏**：设置页 `budget_easy/medium/hard` 按题目难度档位限制单个项目的 intent 消耗，防止失控解题烧 token。
- **网关代理**：`scripts/llm_proxy.py` 提供一个路径剥离的反向代理，用于必须走平台 LLM 网关（要求精确 URL）的场景。

> 注意：`dispatch.yaml` 与 SQLite 数据文件（`*.db`）含平台凭证，已在 `.gitignore` 中排除，**切勿提交**。

## 成绩

**腾讯云黑客松 · AI 渗透测试挑战赛 · 第二届**

610 支队伍 · 1,345 名参赛者 · 来自全国顶尖高校与安全厂商

| 指标 | 数值 |
|------|------|
| 解题数 | **54 / 54 —— 唯一 AK 全解队伍** |
| 最终排名 | 第 3 名 |

> 该系统在赛前从未经过测试。完整流水线在比赛当天凌晨 4 点才首次上线。无训练、无调参、无领域定制工具。零 MCP 工具、零 RAG、零预定义 Agent 角色。

## 延伸阅读

- [最强 AI 渗透测试智能体：腾讯云黑客松智能渗透测试挑战赛（第二届）唯一 AK 队伍复盘](https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA)
- [无路之路：从渗透测试到通用问题求解的 Cairn AI](https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w)

## 免责声明

Cairn 是一个通用问题求解引擎。尽管它支持渗透测试、CTF 解题、安全评估与漏洞研究工作流，但仅应在**你拥有明确授权**的环境中运行。

你需自行对使用方式负责。未经系统/网络/应用/数据所有者或运营者事先明确许可，请勿使用 Cairn 对其进行操作。未经授权的安全测试、利用或数据访问可能违法并造成损害。

本项目开发者与贡献者不对任何滥用、误用、损害、损失或由此产生的法律后果负责。使用本项目即表示你同意确保你的活动符合所在司法辖区的所有适用法律、法规、合同义务及专业/组织政策。

## ⚖️ 许可与致谢

本项目基于 **GNU AGPLv3** 许可开源，供个人与学习用途使用。

**商业使用**：如需在商业或专有环境中使用本项目而不承担 AGPL-3.0 开源义务，请联系原作者获取商业许可。

**贡献**：提交 Pull Request 即表示你同意你的贡献可在 AGPL-3.0 与本项目商业许可下被使用。

本分支由 **[XVSHIFU](https://github.com/XVSHIFU)** 维护，原始项目及所有功劳归于 **[leixiao / oritera/Cairn](https://github.com/oritera/Cairn)**。
