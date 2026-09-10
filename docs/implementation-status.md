# Cairn 当前实施状态

更新：2026-09-09  
基线：[开发总纲 5.2](development-charter.md)

## 当前可用

正式入口：http://192.168.61.129:8000/research  
原 Cairn：http://192.168.61.129:8000/  
独立交互原型：http://192.168.61.129:8011/

原型已按用户反馈进入实现。研究作为原 Cairn 同服务中的扩展，通过独立文档路由隔离 CSS 和页面状态；不是 iframe。原有 CTF/通用任务保留，旧漏洞记录可由研究页右上角访问。

**研究执行器尚未接入。** 当前可以真实保存和管理研究项目，排队不会自动调用模型或测试目标；页面明确显示这一限制。没有将接口接通等同于完整产品交付。

## 核心交付复核（2026-09-09，当前 Kali 代码与正式接口）

本轮只读核对主流程与测试覆盖，没有调用模型、启动研究、修改执行器或重试历史受阻任务。下表是现有实现的缺口记录，不替代总纲，也不是新的实现方案。

| 用户需要的结果 | 当前证据与判断 | 完成时必须补上的证据 |
| --- | --- | --- |
| 网页新建后开始真实研究 | 未完成。正式 GET /api/research/runtime 返回 available=false、cli_installed=true；research_services.claim_session 在应用源码中只有定义，调用点来自测试。 | 网页创建的研究被实际运行中的 Worker 认领，并产生真实执行事件；不能由测试直接调用服务函数代替。 |
| 复用 Kali Claude Code 的配置 | 独立短请求已验证：继承正式服务用户环境、仅用户级设置，CLI 返回固定应答及 grok-4.5[1m] 标识，详见下文记录。runtime 路由本身仍只检查安装，尚未验证应用集成。 | 研究 Worker 实际调用的 CLI、配置来源、模型元数据与会话记录；独立检查不能替代应用运行验收。 |
| 一次授权后暂停、恢复、预算有效 | 数据契约已有；运行期效果未完成。claim_session、reserve_usage、update_checkpoint 和 finish_run 有服务代码，不能据此证明子进程停止或实际请求受预算限制。 | 实际运行中的暂停与恢复记录、进程退出证据、恢复后累计用量以及预算耗尽后的停止行为。 |
| 黑盒从目标到证据和报告 | 未完成。报告可以保存已有数据，RDAP 分类已修复；Amass v5 被明确识别为当前适配器不兼容。旧采集功能不等于研究页的完整流程。 | 同一网页研究中连续关联的执行、证据、有限结论与固定报告，包含无发现和执行失败路径。 |
| 任意语言材料的白盒研究 | 源码快照、引用和对照已有；没有研究 Worker，尚无框架识别、入口与调用关系分析的真实运行验收。 | 不要求用户预选语言的分析记录，绑定实际源码版本与行号，并说明无法建立的关系。 |
| 代码与已运行环境联动及复测 | 身份保管和版本对照已有；实际登录、请求与代码对应、动态对照和复测尚未完成。 | 关联同一发现的代码依据、实际请求响应、前后版本及复测结果；静态疑点不冒充已验证结果。 |

定位依据：cairn/src/cairn/server/routers/research_runtime_status.py、cairn/src/cairn/server/research_services.py、cairn/src/cairn/dispatcher/workers/adapters/claudecode.py、cairn/tests/test_research_api.py。当前旧漏洞分析驱动的 build_analysis 使用空工具集合；原 CTF 驱动存在不代表新的研究任务已接入。

下一项核心交付仍是总纲 M1 的真实执行流程，不再以新增报告、材料管理或适配器数量替代。此前该自主执行器任务被自动审核以“可能涉及网络安全风险”为由中止，未提供更具体原因；这是历史记录，本轮没有新的审核返回，不能描述成再次触发，也不能据此推断所有普通开发都不可做。未把被中止的任务转交 DeepSeek。当前完整目标保持未完成，既有用户项目授权无需重复征询。

## 已完成

- 个人工作台、一次项目授权、黑盒/白盒/联动、自动识别语言、用户预建运行环境等产品需求已对齐。
- 两种模型独立调研，根 Agent 综合实现前端；12 份旧漏洞文档保留原字节归档。
- 证据抽屉支持点击外部关闭、内部操作保持、Escape 关闭，兼容宽屏常驻面板。
- 集成 /research 及原 Cairn 导航；演示样例仍仅存在独立 8011 原型。
- 真实 SQLite ResearchSession、授权快照版本、事件、材料、证据与发现存储。
- Research 项目复用 projects、Fact/Intent/Hint；独立 project_kind 避免进入默认 CTF/通用任务列表。
- 新建并一次确认授权；刷新和项目链接恢复；暂停、恢复、结束本轮和继续探索；提示方向写入持久 Hint。
- 材料更新、自动切换研究模式；授权范围变更与历史留存。
- 预算调整只确认增量，保留已用额度；耗尽后恢复不会重置预算。
- 持久证据关联、已证实/待验证/已排除结果、Markdown 报告；原始证据按字面文本展示。
- 健康接口区分 CLI 安装与研究执行器就绪；当前未接入执行器。配置来源文字是约定说明，尚未通过真实模型运行验证。
- 跨站浏览器写请求被拒绝；沿用 Cairn 原有部署信任边界，未引入账号系统或双人审批。

## 验证与上线

以下为此前各批次在 Kali 的验证记录，本轮主流程复核没有重新执行这些测试：
- pytest：源码对照、源码材料、身份材料、研究 API、数据库迁移、原通用 API、CTF API 合计 **134 passed**。
- 此前实际接口浏览器全量验收 **35 组**：新建、授权、链接刷新恢复、暂停续跑、Hint、材料变更、报告及收束续跑、宽窄屏、原 Cairn 导航、证据原文/抽屉、预算变更、源码/HTTP 视图、快照哈希与后续变更隔离、固定快照链接恢复。脚本错误 0。
- 原型 8011 既有 13 组交互回归保留；它们不计入后端验收。
- 正式库备份后，在备份副本进行迁移 35 演练；既有表记录数不变，integrity_check=ok。
- 正式服务重启后检查：原 26 个项目保留，既有表记录数未减少，研究项目为 0。
- 正式浏览器仅做只读入口、空状态和打开/关闭新建弹窗检查；脚本错误 0，没有写入验收样例。
- 没有调用真实研究模型，也没有对目标执行漏洞测试。

可重放脚本：
- prototypes/qa/research_integration_browser.py
- prototypes/qa/research_evidence_browser.py
- cairn/tests/test_research_api.py

浏览器测试数据库：/tmp/cairn-research-validation.sqlite3  
测试页面：http://192.168.61.129:8012/research  
截图、报告与测试输出：/tmp/cairn-research-integration-qa/

首次集成备份：/home/kali/.local/share/cairn/backups/cairn-pre-research-20260908-224136.sqlite3  
报告快照迁移前备份：/home/kali/.local/share/cairn/backups/cairn-pre-report-snapshots-20260908-225344.sqlite3  
生产进程 PID 文件：/tmp/cairn-server-research.pid  
生产日志：/tmp/cairn-server-research.log

## 明确尚未完成

- 自主 Research Worker、模型会话、受约束的文件/工具/脚本/网络执行，以及真正停止执行后的暂停确认。
- Research Worker 的实际模型连接与会话元数据验收；独立无工具短请求已通过配置继承和连通性检查，尚未证明应用集成。
- 完整黑盒探索与动态验证、语言自动识别及深入白盒调用链审计、代码与预建环境联动。
- 测试身份材料已支持独立导入保管；实际登录、凭据使用及执行器接入尚未完成。
- 发现复测的实际运行、版本比较与结构化前后关联；目前“安排复测”只填入待发送方向。
- 长任务恢复、运行期预算强制约束和执行错误分类；已提供持久契约但不能用单元测试代替执行验收。
- 旧采集工具故障核查与按需迁移；旧模块没有被认定为新产品完整能力。

研究执行器子 Agent 被自动审核中止，返回“可能涉及网络安全风险”，没有提供更具体原因。没有改写请求重试或接续实现被中止的执行部分。未完成草稿保存在 Kali /tmp/cairn-unreviewed-runtime-draft/，已移出应用包，未安装、未执行，不属于本次交付。

## 后续开发边界

继续以总纲为唯一产品依据。M0 已完成并获得用户继续实现授权；M1 的页面与数据管理部分已验收，M1/M2/M3 完整执行能力尚未交付。不能把当前排队状态或 API 测试通过写成自主研究完成。

Kali 是权威工作树，Windows 为同步副本。Git HEAD 仍为 5e2fcc5；本轮未提交、未推送。原有未跟踪 runtime/ 和参考资料不纳入改动。


## 2026-09-09 报告与证据一致性补齐

- 新增不可变报告快照：生成时固定预览、Markdown、事件游标与 SHA256；后续 Hint、材料、预算变化不覆盖旧快照。
- 固定链接可以在刷新后恢复指定报告；下载当前快照不会重新读取正在变化的研究结果。
- 原报告打开后若研究有更新，明确提示，并由用户点击生成最新快照。
- 聚合读取改为一致的 SQLite 读事务，避免概况、事件和证据来自不同时间点；新增迁移36及不可更新的报告表。
- 源码记录恢复文件路径、已记录的版本和行号；版本缺失明确说明。HTTP 记录分别展示保存的请求和响应，不凭单条记录推断对照验证成立。
- 原始内容始终按文本显示，源码或 HTTP 中的 HTML 不会执行；仍可查看完整原文与来源详情。
- 64 项后端回归、14 组浏览器检查通过。快照下载实际字节与保存 SHA256 一致，后续创建新报告也不改变旧快照。
- 迁移36先在正式库备份副本演练，完整性检查通过、旧表记录数不变；上线后旧记录保留，正式库没有验收报告夹具。
- 本轮是报告和证据呈现功能块的进展，不是自主执行验收。先前自动审核中止执行器的阻碍仍存在，未重试被中止的工作。


## 2026-09-09 目标受阻审计（历史）

连续三个目标轮次遇到同一执行器审核阻碍后，将开发目标标记为受阻，而非完成。

本次再次核对了子 Agent 实际状态：research_runtime 为 errored，原因仍为 possible cybersecurity risk；不存在该子任务的活跃运行句柄可等待。正式服务 GET /api/research/runtime 返回 available=false，CLI 已安装但执行器未接入。

已验收的页面、持久化、证据呈现和不可变报告继续保留。M1 的完整自主研究链路、M2 白盒和 M3 联动仍未完成；当前测试不能证明这些能力。后续需要先解决审核/访问条件，再继续被中止的执行器功能及其集成验收。既有项目授权无需重复征询。本次未尝试绕过审核、未启动真实目标测试、未提交或推送。


## 2026-09-09 继续开发：测试身份材料

用户明确本轮是功能开发，子 Agent 承担实现，根 Agent 负责代码验收，测试使用本地夹具。目标已恢复推进，完整自主执行目标没有缩减为当前已完成模块。未重试先前被平台审核中止的执行器子任务。

- 材料页新增身份入口，支持 account、HTTP Basic、请求头和 Cookie 的本地 JSON 导入。
- 网页只提交标签和私有目录中的文件名，导入内容不经过浏览器，不进入 Hint、事件正文和报告。
- 服务端用随机本机密钥与 AES-GCM 保存；密钥位于数据库外的私有目录，AAD绑定项目、身份、版本和origin。丢失或替换密钥时拒绝新写入。
- 支持更换、撤销、重新导入；目标origin变化后显示stale，须显式重新关联。删除运行环境后仍可撤销。
- 导入文件限当前用户私有目录、600权限单链接普通文件，拒绝路径跳转、符号链接、硬链接、FIFO和超大文件；错误不回显内容。
- 新增迁移37。94项联合测试通过；其中30项覆盖身份材料、加密恢复、AAD、并发密钥创建、错误不泄露、环境绑定、撤销与失败替换保留旧数据。
- 浏览器7组新增检查通过，加上14组原流程回归合计21组，脚本错误0。只使用 /tmp/cairn-identity-browser-fixtures/ 内的虚构材料。
- 生产备份：/home/kali/.local/share/cairn/backups/cairn-pre-identities-20260908-231330.sqlite3。备份副本迁移和完整性检查通过，原26个项目保留。正式库不写入测试身份或验收密钥。
- 可重放：prototypes/qa/research_identity_browser.py；使用说明见 identity-materials.md。
- 配置保管不会尝试登录、调用模型或访问目标；自主执行器仍未接入。当前模块完成不等于M1/M2/M3完整交付。


## 2026-09-09 继续开发：源码材料快照与选行引用

- 新增迁移38与源码材料页面，首次创建带本地目录的项目后自动采集，不增加授权弹窗；已有项目可主动保存新版本。
- 不可变快照保存路径、UTF-8原文、原始换行、文件和集合内容摘要；查看旧文件只读数据库。更改源码不影响旧证据，更换项目目录标记旧材料。
- 搜索文件、分段浏览、定位行范围与保留最多400行代码；引用进入现有证据/报告链，明确记录采集摘要类型，未创建Fact或Finding。
- 默认跳过隐藏/依赖条目，按大小、数量、深度、遍历时间检查预算限制采集。跳过原因与限制可查看；集合摘要不是原子仓库状态或Git commit。
- 子Agent负责源码后端实现，根Agent检查代码、集成页面并使用Kali本地夹具验收。未执行源文件或目标测试、未调用模型，未重试历史受阻执行器。
- 最终联合回归116项通过：源码22项、身份30项、研究API/迁移/原服务/CTF64项。新增7组源码浏览器检查，加上原21组合计28组，脚本错误0。
- 浏览器实际检查了首次一次授权采集、跳过项、文字转义、CRLF行号与片段哈希、修改后旧版本不变、长文件定位、未知扩展名、窄屏、目录变更和报告原引用。
- 生产备份：/home/kali/.local/share/cairn/backups/cairn-pre-sources-20260909-033330.sqlite3。迁移副本完整性检查和旧表计数检查通过；正式服务已更新，原26个项目保留，正式库源码快照/文件夹具均为0。
- 使用说明见source-materials.md；可重放prototypes/qa/research_source_browser.py。
- 这是M2的材料基础部分，语言标签仅按文件名判断。框架/入口/数据流分析、Research Worker和完整M1/M2/M3执行链仍未交付。目标保持未完成。


## 2026-09-09 继续开发：源码版本对照与证据回源

- 子Agent实现只读快照对照接口与16项测试，根Agent完成前端集成、代码验收及Kali浏览器夹具测试。
- 可选择两份快照，统计内容变化与仅一侧有的文件，搜索变化路径、交换方向、显示双侧行号与上下文、查看完整原文件。明确区分快照缺失与实际删除，不推断重命名或修复成功。
- 保留行尾差异，覆盖LF/CRLF/CR/末行无终止符。逐行计算按64 KiB/1200行/单行8192字符限制，输出最多1600行；超限明确提示。
- 旧代码证据可以返回绑定快照的原文件、行号和上下文。切换版本有请求序号隔离；读取失败清空上一份内容。
- 132项联合后端测试通过；新增7组浏览器验收与原28组回归全部通过，共35组，脚本错误0。新夹具位于/tmp，未调用模型、未执行源码或访问目标。
- 只读API使用一致数据库读事务；没有新迁移，正式更新前后的原26个项目和研究域表记录数保持一致。正式库不写验收快照或证据。
- 可重放prototypes/qa/research_comparison_browser.py；使用说明更新到source-materials.md。
- 此项补齐版本核对与证据上下文，未接入Research Worker或自动修复复测；完整M1/M2/M3目标仍未完成。未重试历史受阻执行器任务。


## 2026-09-09 DeepSeek Web / Thinking off 首个协作修复

- 用户指定使用本地DeepSeek Harness的DeepSeek Web / Thinking off，并要求单会话串行。界面已确认该设置。
- 本轮只发送一个前端修复任务，在同一会话内完成一轮反馈修正，共两次模型回复。网页Agent未调用工具或改动happy-code工作区；协调Agent根据补丁修改Kali权威工作树。
- 修复queued状态的标题：明确available=false时显示“项目已保存，执行器尚未就绪”；初始或查询失败时available=null，显示“项目已保存，执行状态待确认”；available=true时仍显示“研究已排队”。
- 健康查询失败不再等同执行器不可用，不改写后端项目状态。运行/暂停/失败标题与项目latest_error优先级保留。
- 验收脚本prototypes/qa/research_readiness_browser.py使用独立验收项目及模拟健康响应，不启动执行器。原代码已实际复现错误标题，修改后5组专项检查通过、脚本错误0。
- 未开发或转交历史被拦截的执行器任务。未提交、未推送。
- 原8组界面流程回归也通过，本轮共13组浏览器检查。正式研究页只读检查通过，没有创建生产测试项目；本次仅静态文件变更，无数据库迁移或服务重启。


## 2026-09-09 DeepSeek 官网协作验证

- 使用用户打开的chat.deepseek.com，确认深度思考关闭，仅一个会话。会话标题“切换项目清空搜索词”；官网只提供补丁，没有声称访问Kali或运行测试。
- 根Agent先在隔离验收库复现切换项目后残留assetSearch的问题，再应用官网建议：selectProject中增加assetSearch清空。
- Kali浏览器验收通过：跨项目清空搜索词、同项目页签切换保留、显示各项目对应材料、持久项目记录不变、无脚本错误。正式页只读检查通过。
- 仅前端一行行为修改和静态缓存版本更新，无数据库迁移、无服务重启，未提交或推送。没有转交此前受阻执行器。


## 2026-09-09 报告历史版本与读取流程

- 未创建、续跑或轮询Codex subagent。沿用用户指定的DeepSeek官网现有单会话，以快速模式给出报告查询建议；协调Agent修正事务与分页细节，在Kali实现、集成和验收。
- 报告窗口默认读取最近保存版本；首次生成与后续新快照均由明确按钮触发。重复打开或浏览历史不会写入新报告。
- 新增只读元数据列表与项目绑定的游标分页，同秒记录按实际插入顺序展示；新生成报告不会挤乱更早页面。没有新增迁移。
- 列表与正文分别隔离异步响应；失败保留已有内容，关闭窗口或切换项目使旧请求失效。历史版本的预览、固定链接和下载保持同一原快照。
- 长报告滚动时保留标题与关闭按钮，历史列表支持窄屏。使用说明见report-versions.md。
- Kali联合后端回归134项通过；报告历史6组浏览器专项与原证据6组、基础流程8组、源码7组均通过，共27组，脚本错误0。最终标题/关闭按钮滚动位置与390px窄屏另做检查通过。
- 测试只写隔离验收库。研究Worker、真实模型运行、完整黑盒/白盒/联动能力仍未完成；本项未替代或缩减M1/M2/M3目标，未重试历史受阻执行器任务。未提交、未推送。

- 正式服务已更新，报告列表GET路由已注册。原26个项目保留，所有表记录数未减少；原漏洞采集模块在运行期间有新增记录，因此未宣称全库计数完全不变。正式研究项目与报告仍为0，未写入验收夹具。

- 更新后的正式原页面与研究空状态只读检查通过，脚本错误0；本轮变更已同步Windows源代码副本。


## 2026-09-09 M1采集故障核查与RDAP分类修复

- 用当前Kali记录确认RDAP曾将HTTP404+RDAP负向JSON统一记为退出码22故障；Amass选用用户目录v5.0.0，存在libpostal数据警告和近期180秒超时，尚未证明因果。
- 在DeepSeek官网同一会话获得建议，协调Agent纠正虚构接口与异常处理建议后集成。未创建、委派或轮询Codex subagent。
- RDAP v1.1.0仅接受传输状态与严格JSON错误码一致的404作为带限制说明的负向记录；保留原始响应、真实退出码和旧资产，不触发该404的失败重试。其他错误与取消继续失败，批次证据完整保留。
- Kali专项23项及相关两模块完整回归139项通过。真实curl验证仅连接本地HTTPS夹具。3项旧测试预期先在修改前代码复现，再按现有注册表、迁移和任务行为纠正，未放宽范围与授权断言。
- 详细依据与尚未解决项见collection-diagnostics.md。没有改写旧失败记录，没有手工重试外部目标，没有接入或转交历史受阻的研究执行器；M1/M2/M3完整目标仍未完成。

- 正式服务已重启加载，/vulnerability/adapters确认RDAP版本1.1.0；89张表记录数无减少，原26个项目保留，正式研究项目/报告为0。未提交、未推送。


## 2026-09-09 Amass v5兼容性核查与执行前检查

- 官方v5.0.0源码确认enum使用独立后台engine，而当前适配器期待enum stdout逐行域名；域名输出在subs数据库导出流程中。版本命令退出0不能证明当前适配器兼容，零stdout不能证明零发现。
- 网络命名空间/临时HOME测试60.09秒后报engine未响应。由于该命名空间没有启用环回，此结果不用于推断生产超时根因。没有请求外部目标，测试结束后核查无属于该临时HOME的遗留引擎。
- Amass适配器1.1.0增加版本预检；v5及更新未支持版本、无法识别版本明确不可用。直接execute也检查，避免继续启动不兼容enum或误报成功零结果。其他来源独立运行，旧记录保留。
- DeepSeek官网现有快速模式单会话提供建议；协调Agent去掉了建议中随意设置的版本号上限，按真实代码集成。未使用Codex subagent。
- 详细来源和未完成范围见collection-diagnostics.md。此项不代表已接入Amass v5，更不代表完整研究执行链已交付。

- Amass专项/既有采集组合21项通过；两相关模块完整回归150项通过，包含不兼容版本不得启动enum的真实脚本夹具与其他被动源继续入库的集成测试。正式服务加载Amass适配器1.1.0，89张表记录数未减少，原26个项目保留，正式研究项目/报告为0。未提交、未推送。


## 2026-09-09 Claude Code 配置继承与独立连通性验证

- 直接在 Kali 进行一次普通模型连接检查。读取正式 Cairn 服务进程的环境后在同一用户下启动 CLI，HOME=/home/kali，解析到 /usr/local/bin/claude，版本 2.1.215。没有复制密钥或网关地址到文档、网页、仓库或测试摘要，也没有显式指定模型覆盖用户配置。
- 当前用户设置的模型为 grok-4.5[1M]；生产服务环境没有 ANTHROPIC_* 或 CLAUDE_* 变量。以 user 为设置来源，CLI 成功使用现有用户配置。
- 空临时工作目录、--safe-mode、空内置工具集合、严格空 MCP 集合、禁用 Chrome 和会话持久化；系统提示仅要求固定应答，用户输入只有 Reply exactly: CAIRN_CONFIG_CHECK_OK。费用上限 0.10 美元。本次没有传项目代码、测试身份或研究材料，没有请求研究目标。
- 初次运行因空 MCP JSON 缺少 mcpServers 字段在本地参数校验阶段退出；改为 {"mcpServers":{}} 后才完成调用。没有把这次参数错误记成认证、模型服务或平台审核故障。
- 成功调用用时 11.437 秒，exit=0、subtype=success、is_error=false、num_turns=1、回复精确匹配。CLI modelUsage 返回 grok-4.5[1m]，CLI 报告费用 0.01356 美元。模型标识及费用均是 CLI/服务返回值，不是对第三方底层模型身份或账单的独立认证。
- 结果证明当前用户配置下的独立短应答路径可用；safe-mode 中禁用了自定义扩展，所以没有验证平时启用的 hooks/插件是否正常。没有验证工具执行、研究工作目录、会话恢复、长任务、运行期预算或 Research Worker。
- DeepSeek 官网现有快速模式单会话审阅了脱敏结论；没有创建或调用 Codex subagent。采纳其关于连通性与产品集成区别的判断；未把禁用 hooks 后成功视为 hooks 本身通过测试。
- 可核对的脱敏摘要：prototypes/qa-output/cli-configuration-check.json。原始 CLI 输出仅在 Kali 私有临时目录 /tmp/cairn-cli-config-check-je37kkon/，不纳入源码同步。本轮没有应用代码修改、数据库迁移或服务重启；先前测试数量不作为本轮新结果。完整 M1/M2/M3 仍未完成。


## 2026-09-09 补充方向的草稿保留与异步响应隔离

- 在 Kali 隔离页面复现：发送方向后、响应返回前编辑下一条草稿，旧 sendHint 会清空新输入。浏览器记录确认第一条已持久保存而新草稿丢失。
- action 的成功结果与失败提示现在绑定提交时的项目 ID 和选择轮次；切换项目或离开再返回后，旧响应不再触发当前页面的成功/失败反馈。原项目请求仍正常完成，保留原 API、编码、请求体与列表刷新，不中断、不重复发送。
- sendHint 保留提交前的原始输入，发送 trim 后的内容；成功时仅清空仍与原输入一致的草稿。同项目新输入保留，同时提示上一条已保存。当前项目失败仍显示错误并保留草稿。
- DeepSeek 官网现有快速模式单会话提供建议。协调Agent修正其直接 fetch 导致丢失 API 前缀、遗漏已有项目检查以及把成功提示错误绑定草稿清空的部分；没有使用 Codex subagent。
- prototypes/qa/research_direction_browser.py 的6组专项通过：同页继续编辑、未修改草稿正常清空、跨项目成功、跨项目失败、本页失败、离开再返回同项目。真实写入仅发生于独立8012验收库，检查持久 Hint 内容及次数。
- 原 research_integration_browser.py 的8组回归通过，覆盖新建、刷新、暂停恢复、方向、材料、报告收束续跑、宽窄屏及原应用入口；本轮合计14组浏览器检查，脚本错误0。
- 正式8000研究页只读检查通过，静态版本20260909-12，脚本错误0。本次没有后端代码修改、数据库迁移或服务重启；不需要将旧后端测试数字记成本轮新结果。完整自主执行能力仍未完成，未提交或推送。


## 2026-09-09 授权表单的项目绑定与保存反馈

- Kali浏览器实际复现：在A项目打开材料草稿后通过hash链接切到B，旧弹窗仍可编辑，提交时会读取新的selectedId。修复后切换项目立即关闭旧表单、清空草稿及勾选状态；打开入口检查当前详情与选择项目一致。
- 材料和预算保存同时检查项目ID、选择轮次、弹窗打开轮次；Escape、关闭按钮和外部点击经过同一关闭逻辑。已经发出的请求仍完成原项目的持久化，旧成功/失败不再关闭或污染后来打开的弹窗。
- 保存期间编辑任一草稿，成功后保留当前弹窗和新输入；本次提交以来草稿均未变化才正常关闭。当前弹窗失败仍显示错误并保留输入，所有路径释放提交状态。没有改动API、授权规则或累计预算。
- DeepSeek官网现有快速模式单会话审阅方案；协调Agent保留实际this.api调用及请求体，使用已有DOM而非建议中不存在的dialogOpen，不采用时间戳重置轮次。未使用Codex subagent。
- 新增research_scope_browser.py，8组专项通过；基础流程8组和方向草稿6组回归通过，本轮共22组浏览器检查，脚本错误0。写入只发生于8012隔离验收库，检查了实际保存的项目、材料、预算及已用额度。
- 正式研究页只读检查通过，静态版本20260909-13；无需后端重启或数据库迁移。完整研究执行器仍未接入，本轮没有提交或推送。


## 2026-09-09 研究执行器 M1 核心切片（真实运行链，已按两轮评审修正）

本轮实现并验收了 M1 缺失的真实执行链：一个后台 Research Worker 从队列消费已授权研究，并在真实 bubblewrap 文件系统隔离中运行工具态 Claude Code。这不是接口/演示通过冒充完成，而是实际运行的认领→执行→证据→报告链路。

### 第一轮评审四项已修正
- **真实执行隔离**：`research_sandbox.py` 用 bwrap 构造沙箱——`/usr`、`/etc` ro-bind（含 usrmerge 顶层符号链接），绝不绑定宿主 `/home`、`/root`、`/run`、宿主 `/tmp`；只把会话工作区 `--bind` 到 `/workspace`（可写）、授权仓库 `--ro-bind` 到 `/repo`（只读）；`--unshare-all --share-net --cap-drop ALL`。启动前用 `shutil.which("bwrap") is None` 直接拒绝运行。已实测 `/root/.bash_history`/宿主 home 在沙箱内不可见。
- **真实外层 envelope 解析**：复用 `ClaudeCodeDriver.extract_analysis_response()` 解析真实 `claude` 输出的外层 JSON envelope（`result`/`structured_output`、`total_cost_usd`、token/模型元数据），再解析内层研究 JSON；测试夹具输出真实 envelope 形状。
- **预算成为真实约束**：按「剩余预算 = 已授权 − 已记账」传入 `--max-budget-usd`/超时；运行前 reserve（含请求数预算，超限 402 拒单），`account_usage` 在运行后把实际 cost/elapsed/request 写回（即使超额也不丢）。
- **失权停止执行**：wait 循环对 `pause_requested`、租约丢失、会话不再 running 都 `process.cancel(...)` 终止进程组；非所有者 `finish_run` 仍被 owner 守卫拒绝。

### 第二轮评审五项已修正
- **沙箱 Claude 配置继承打通**：`build_sandbox` 新增 `claude_config_src`，把操作者的 `.claude.json`、`.claude/settings.json`、`.claude/settings.local.json` 种子化复制进沙箱 HOME；并把 `HOME` 指向沙箱内真实存在的 `/workspace/.sandbox-home`（此前指向宿主导不成存在的 host 路径，home_exists=false）。实测沙箱内 `$HOME` 存在、`.claude.json`/`settings.json` 可读（模型/URL 设置沿用），且宿主 home 仍不绑定。
- **请求预算进入执行限制 + 如实注明网络边界**：`remaining_requests==0` 时拒绝启动；真实逐请求计量需代理，提示词/文档如实注明 `--share-net` 无白名单网关、由授权摘要核对，不冒充执行层已强行约束目标网络。
- **异常结束也回写费用**：pause/超时/非零退出/解析失败等所有路径在返回前都先 `_account(elapsed)` 并尝试从外层 envelope 提取 `total_cost_usd` 回写（`_provider_cost_from_output`），不再拖着不记、影响后续剩余额度。
- **结果写入原子化护栏**：`record_evidence`/`record_finding`/`update_checkpoint` 在 writer 锁下校验 `lease_owner`，`_apply_payload` 任一步发现失权立即止写并返回 False；关闭「跑完后、写入前」租约转移的竞态窗口，失权旧 Worker 无法把证据/发现写进已重认领的会话。
- **不合格输出不会误判完成**：`_extract_payload` 对内层 JSON 解析失败或非对象返回 `None`，`run_session` 标记 failed 而非自造 `terminal=True` 生成完成报告；缺失 `terminal` 视为未完成。

### 公共能力
- `cairn research-worker` 独立进程：迁移39 `research_worker_runtime` 单行心跳表；`worker_heartbeat`/`read_worker_runtime`/`claim_session`/`reserve_usage`/`account_usage`/`finish_run` 事务原语。
- `/api/research/runtime` 的 `available` 由真实心跳驱动（无/活跃/过期三态）；前端 `queued+available=true` 显示「研究已排队」。不再硬编码 `available=false`。
- 提示词 `default/research.md`/`mock/research.md`：授权摘要、预算、当前方向、结构化输出单条 JSON 约定。

真实验收（Kali，独立隔离库）：
- `research-worker --once` 全链路由真实子进程 + bwrap + DB 状态佐证：`queued→running→completed→report`，成本/请求/耗时按真实写回，报告生成。断言沙箱内 `$HOME` 存在、宿主 `/home/kali` 不可见、授权仓库只读、工作区可写。
- test_research_worker.py **11 项**（含针对两轮评审要点的沙箱 HOME/配置、请求预算耗尽拒启动、异常退出回写费用、失权写护栏、不合格输出→failed、外层 envelope→报告、真实子进程 pause/lease_lost 终止）。
- 同一进程 7 个测试文件 **130 项全通过**（research_api / research_worker / db_migrations / research_sources / source_compare / identities / worker_tasks）。迁移39 生产备份副本演练：integrity=ok、91表、原26项目保留。
- 只使用隔离验收库与本地夹具；没有调用真实模型或访问真实目标。完整黑盒/白盒/联动的多轮研究与自动复测仍未完成，需用户明确授权目标范围后在受控环境启动 worker 验收。

已知：`test_db_migrations.py` 与任意研究测试同进程混跑曾因 `/tmp` 占满导致假失败；清理 tmpfs 后与各研究测试**同一进程 130 项全通过**，并非全局状态互相污染。本轮未提交、未推送。


## 2026-09-09 可靠性加固（5 项，一轮完成）

在 M1 执行链之上补齐运行时可靠性治理。本轮全部用 fake 配置 + 隔离 DB + 本地 HTTP 夹具验证，没有启动生产 worker、不打真实模型；验收分类“已修复/夹具已验证/真实模型尚未验证”。

### ① 配置复制不得写入工作区（已修复，真实模型尚未验证）
- 根因修复：原先把操作者的 Claude 设置种子化复制进沙箱内**可写**的 `.sandbox-home`，模型可改自身执行配置。
- 现在 `build_sandbox` 把配置暂存到工作区**外**的私有目录（`<workspace>/../.cairn-sandbox-private/claude-config`），`--ro-bind` 只读挂载到 `/claude-config`，并设 `CLAUDE_CONFIG_DIR=/claude-config`；`HOME=/workspace/.sandbox-home` 保持可写，缓存/临时/会话独立写 `XDG_CACHE_HOME/TMPDIR/XDG_*`→`/workspace/.sandbox-cache`。
- 拒绝源/目标路径符号链接（`_prepare_private_config` 对 `.claude.json`/`.claude/settings.json`/`.claude/settings.local.json` 逐项 `is_symlink`/越界校验），任一配置为符号链接即抛错。
- 缺任一配置或全部缺失即抛 `RuntimeError`，不静默空配置运行。
- 真实凭据仍不进项目材料/证据/报告/源码同步目录；配置只在私有目录与 RO 挂载点之间。
- 夹具已验证：配置在工作区外、`/claude-config` 只读、HOME 内无配置副本、符号链接拒绝、缺配置抛错。

### ② 独立 run_id 批次费用账本（已修复，真实模型尚未验证）
- 迁移40 新增 `research_run_accounts`（run_id PK、session_id、worker_id、steps/requests/elapsed_seconds/cost_usd、cost_status∈pending_check|recorded、settled、committed）+ `research_sessions.current_run_id`、`cost_pending_check`。
- `create_run_account` 在每次 claim/开始 run 时开一个独立批次并写入当前 run_id；`apply_payload` 返回 `(still_owned, target_requests)` 供批记账。
- `settle_run` 幂等（`settled=1` 后再次结算不重复扣费）；**不要求租约所有权**——失权旧 Worker 仍可交本批次的真实 elapsed/cost（消费可提交），但经失权护栏不能写任何研究结果。
- 无最终费用：批次与会话都标 `cost_pending_check=1`，不释放未知费用对应的剩余预算；`resume_session` 看到该标记即 409 拒绝，`resolve_pending_cost` 核对入账后解锁。恢复沿用累计预算。
- 夹具已验证：claim 开新批次、重复结算不双扣、费用待核对阻断恢复、核对后恢复、失权旧 Worker 交消费但零结果。

### ③ 统一结果提交入口（已修复，夹具已验证）
- 新增单一入口 `commit_run_results`：在一笔 SQLite 写事务里，先 `_lock` 拿写锁（写锁下租约不会被中途移走，校验原子），校验 run_id∈run_accounts、`lease_owner==worker_id`、租约未过期、会话状态，随后才同写证据/发现/事件/检查点/终态 + 自动报告（绑定成功提交、按 `committed` 去重），任一步失败整体回滚。
- 空结果也是一次合法提交；`pause_requested` 时拒绝完成覆盖（暂停优先，不生成报告）。
- 人工/API 写路径保持分离；`_apply_payload` 改为委托该入口，失权旧 Worker 经此路径写零结果/零事件/零报告。
- 夹具已验证：统一提交写入证据/发现/终态+报告、空结果合法完成、协议错误写入空、暂停覆盖晚到完成、失权旧 Worker 零写入、重复提交不重复出报告。

### ④ 严格模型输出协议校验（已修复，夹具已验证）
- 纯函数 `validate_payload(payload)->(valid, reason, normalized)` 整包校验、任何写入前执行。
- `terminal`/`awaiting_input` 必须是**真布尔**（JSON 字符串 `"false"`、数字、对象 → 协议错误，不做隐式真值转换）。
- 三态互斥：completed / awaiting_input / not-completed；`terminal=true 且 awaiting_input=true`＝冲突＝协议错误。
- evidence/findings 必须是 dict 数组，逐项校验 title/content/status/impact/limitations 结构。
- 无发现完成允许但必须带合法 `summary` 结果说明；格式错**绝不**生成完成报告（commit 返回 protocol_error，整包回滚）。
- 夹具已验证：`"false"` 字符串/非对象/结构错/冲突/无发现空说明均拒绝，合法无发现+说明与合法有发现均接受。

### ⑤ 真实目标范围 + 请求预算执行层约束（核心已修复，夹具已验证；LD_PRELOAD 强制走代理已夹具验证）
- 新增 `research_egress.py`：本地回环强制出口代理（`EgressProxy`），执行层启动并由沙箱环境 `HTTP(S)_PROXY/ALL_PROXY` + LD_PRELOAD `connect()` 拦截器（`egress_preload.c` 编译为 `libcairn_egress.so`）承载所有非回环出口——**直接 connect 也无法绕过**（夹具验证：指向不可达代理端口时，对非回环主机的直接连接被强制改道并失败，回环仍可用）。
- 仅 `http`/`https`，其余协议显式 `refuse_protocol`。
- 逐请求：授权目标 allow-list / 排除项（exclusion 优先）/ 剩余配额；配额耗尽返回 403「停止新目标请求」，但仍允许存证据 + 结算（worker 的 settle/commit 不受配额拒绝影响）。
- 重定向再查：目标 HTTP 3xx 的 `Location` 在转发前重新用同一 scope 校验，越权重定向被拦截。
- 重试单独计数（`QuotaState.is_retry` 窗口判重，`retries` 与 `requests` 分开）。
- 模型-网关流量与目标流量分类治理：model_hosts 走 `proxy_model`，**不计入**研究目标配额。
- 执行层联动：`_egress_environment` 对真实目标 run 启动代理（allow=URL、quota=剩余请求）、注入代理环境 + LD_PRELOAD；fake/测试 run 不启用。
- 夹具已验证：scope 决策、配额耗尽、排除列表、越权重定向、仅 http(s)、retry 单独计数、模型流量不计配额、LD_PRELOAD 强制改道 + 回环不拦截；真实生产模型的跨靶点/深层绕过关闭程度属“真实模型尚未验证”。

### 回归与验收
- test_research_egress.py **10 项**、test_research_worker.py **22 项**；research_egress+worker+api+migrations+sources+compare+identities+worker_tasks+vuln_api 同进程 **220 项全通过**（在 Kali 权威工作树 `.venv`）。
- 迁移40 在隔离库完成：`research_run_accounts` 建表 + 两列附加，完整性与计数检查通过；既有 research 测试不破坏。
- 旧 `test_vulnerability_api::test_vulnerability_migration_upgrades_legacy_database` 原先硬编码完整迁移清单（1..38），迁移39/40 使其过期；将其改为核对安危案基础迁移的**前缀**加“研究域迁移必须并存”，并补入 40 断言，69 项 vuln_api 回归通过。
- 全量 tests/ 在 Kali 仍剩 3 项与本轮无关的既有环境失败（container-manager env 断言、两个 vulnerability 前端静态资产断言）；它们不涉及本轮的 research_* 模块或 db 迁移。
- 全程 fake 配置 + 隔离 DB + 本地 HTTP 夹具，不启动真实 worker、不打真实模型。M1/M2/M3 完整多轮自主研究、真实模型连接、真实授权目标验收仍在受控环境启动后另行验收。本轮未提交、未推送；Git HEAD 保持 5e2fcc5。

## 2026-09-09 M1 收尾：真实链路单轮验收尝试（受供应商限流阻塞，分步已真实验证）

### 本轮动机
用户下达 M1 收尾交付：单 Web 目标一轮研究（接收目标→执行→保存证据→生成报告，支持暂停），并给出真实授权靶场
`http://f239b1ffc2b64e9b7c09d41e.http-ctf2.dasctf.com:80`（GET password 校验接口）。要求「只做针对性检查和一次页面验收，不重跑整套」，并诚实分类验收结论。

### 针对真实链路的修复（本轮新发现并修复，均有夹具/单测回退）
1. **配置种子目录扁平化**（`research_sandbox.py::_prepare_private_config`）：把 `.claude.json`/`settings.json` 直接放进配置目录根，`CLAUDE_CONFIG_DIR=/claude-config`。此前按 `~/.claude/` 镜像结构会把 settings 埋在 `claude-config/.claude/settings.json`，而 CLI 实际读 `$CLAUDE_CONFIG_DIR/settings.json`，导致真实模型报「Not logged in · Please run /login」。修复后真实模型在沙箱内完成鉴权（实测 `AUTH_OK`）。
2. **配置目录可写基座 + 设置文件单独 RO 挂载**（`build_sandbox`）：claude 要在配置目录写运行时目录 `session-env`，纯 RO 挂载会报 `EROFS: mkdir /claude-config/session-env`。现改为：`/claude-config` = 可写运行基座（沙箱外 `config_root/claude-config-runtime`），而 `.claude.json`/`settings.json` 分别 `--ro-bind` 覆盖，模型仍**无法改动治理其执行的配置**（满足可靠性项①），同时 bash 工具可运行。
3. **`settings.local.json` 不再种子化**：它是宿主特有的 bash 权限 allow-list（绝对宿主路径），在沙箱内会让模型通用 `curl` 被拒（`permission_denied: Bash`「requires approval」）。鉴权在 `settings.json` 的 `env` 块，故此排除合理。
4. **`--permission-mode bypassPermissions`**（`research_worker.py::_build_claude_argv`）：沙箱内自动放行模型工具；真正边界是 bwrap 文件系统 + 强制的、逐请求计数/定域的出口代理，因此放行工具不构成失控。
5. **LD_PRELOAD 拦截器搬进沙箱**：`libcairn_egress.so` 编译到可写配置运行基座并经 bwrap `--setenv LD_PRELOAD` + `--ro-bind` 覆盖（不可篡改）。修了两个问题：a) 宿主 `/tmp` 路径在 bwrap 新 tmpfs `/tmp` 内不可见；b) 外层环境 `LD_PRELOAD` 会破坏 bwrap 用户命名空间助手（报 `cannot be preloaded`）。LD_PRELOAD 必须在沙箱内（`--setenv`）注入。
6. **模型网关分类按主机名判定**（`research_egress.py::QuotaState.classify`）：裸网关主机默认 80 端口与真实 443 不匹配导致误判 refused；改为模型网关按 host 判类（仍不计目标配额）。
7. **研究提示词引导**（`default/research.md`）：明确要求用沙箱内 `curl`/`python` 对授权目标发请求并记 `http/request` 证据、*不要*用 WebFetch/WebSearch（提供方侧执行、不经过政策与配额、常被拒）；并强调即使无发现/受阻也必须输出单条 JSON 报告（terminal 明确）。

### 真实链路的逐阶段验证（非断言，已实测）
- 在隔离库 + 独立 `cairn research-worker --once` 下，真实模型（grok，经 `settings.json` env 鉴权）在 bwrap 沙箱内启动、完成鉴权、响应真实 target 页面原文。
- 出口强制实测：沙箱内 `curl` 到授权 CTF 靶场，分别走 HTTP_PROXY 与直连 CONNECT（LD_PRELOAD 截获）两种路径，均拿到真实响应并计入代理配额（`admitted requests: 1`）。
- 预算/费用真实结算写入（如某次运行 `cost_usd=0.79`、`elapsed=90s`/`125s`），`research_run_accounts` 记账、`commit_run_results` 单事务校验在夹具与单测中通过。
- 多人账本/失权、暂停恢复、批间覆盖防护、协议校验均在 test_research_worker.py 单测覆盖（见下）。

### 分类（诚实）
- **逐阶段**：上述修复项均为「已修复 + 夹具/单测回退通过」。真实链路「分步已实测」（鉴权、沙箱、出站强制到达并计数真实目标、bash 使能、配置 RO 覆盖、JSON 协议产出）均拿到真实证据。
- **完整单轮端到端（新建→执行→证据→报告→completed 终态）**：**尚未在本次会话跑绿**。受阻原因是**模型供应商限流**：多次连续真实调用后 grok 网关接连返回 `api_error_status 429`（input/output tokens = 0，`terminal_reason=api_error`），另有一次在 3 分钟时间预算内冷启动+重响应未完成即超时。这些都是外部吞吐/限流，非代码缺陷（各阶段子环节已由真实调用与夹具交叉证实）。
- **暂停有效性**：本轮未在真实运行中补点验证（前几轮已夹具/单测覆盖 pause→SIGTERM→结算路径）；生产模型侧的真实暂停留待限流窗口后复验。
- 全程使用隔离库 `/tmp/cairn-m1-acc/cairn.db` + 独立 8016 服务器 + 受控 `/tmp` 工作区；**未写生产库、未起生产 worker 于生产库**。未提交、未推送；Git HEAD 保持 5e2fcc5。

### 回归
- `test_research_egress.py` **12 项**、`test_research_worker.py` **25 项**均通过（Kali `.venv`）；本轮另跑 research_egress+worker+api+db_migrations+sources+source_compare+identities **150 项全通过**。
- 全量 tests/ 仍仅剩既有 3 项与本轮无关的环境失败（container-manager env 断言、两个 vulnerability 前端静态资产断言）。

### 后续一步
供应商限流窗口（约数分钟）过后，在受控环境对授权的单个 Web 目标补一次真实单轮，确认 evidence（http/request，配额计数）+ findings + 报告 + `completed` 终态 + 费用入账，从而把「完整单轮端到端」从 分步验证 提升为 全流程跑绿。本轮不做生产上线、不提交。


## 2026-09-10 新靶场：仅一次真实执行与页面报告验收

- 用户明确替换过期地址，本次唯一授权目标为 http://71c628e346a642bd8638751a.http-ctf2.dasctf.com:80/；未访问旧靶场。未使用 subagent、未调用额外网页模型、未重跑回归测试。
- 使用 Kali 新隔离库 /tmp/cairn-m1-final-20260910-3jzfg500/cairn.db 和 8016 独立服务，从真实页面新建 proj_001。预算为 6 分钟、40 请求、1 美元、1 执行批次；研究目标要求至多四次有针对性的 HTTP 请求。
- 仅启动一次真实 cairn research-worker --once，批次 run-5292038c758347f99d2df673f05c4916，正常退出。无 429；执行耗时 26 秒，CLI 报告费用 0.286378 美元，批次账本 settled=1、committed=1、cost_status=recorded。
- 保存三条 http/request 证据：首页返回密码错误提示，/login 与 /check 返回 404；一条 pending 线索，未验证密码提交参数，未确认漏洞。批次代理计数为 3；会话显示 4（包含现有启动预扣 1），不能把 4 当作四次真实目标请求。
- 实际终态为 paused，并保存了后续探索方向。自动完成与自动报告没有发生。因此，“仅剩供应商限流、限流后即可全流程完成”的此前判断不足；本次真实运行显示仍需处理单轮模式的自动收束行为。
- 随后只在页面打开报告、生成并下载当前暂停状态快照，没有手动把状态改成 completed，没有续跑。页面脚本错误为 0。报告与截图保留在同一验收目录；可查看 http://192.168.61.129:8016/research#/proj_001。
- 结论：真实页面创建、模型执行、目标请求、证据/线索持久化、费用结算和页面报告导出已在这一轮联通；“自主单轮→completed→自动报告”尚未完成。本轮未验证用户主动暂停真实模型。
- 保留隔离服务供用户查看；一次性 Worker 已退出。未写生产库、未提交、未推送；本轮没有修改应用源码。

## 2026-09-09 M2 白盒审计（首个执行切片，确定性验证）

用户判定 M1 已通过（执行链路能跑即算，模型网关限流不当作阻塞），按方案进入 M2 通用白盒审计。

### M2 承载面（M1 已具备，无需新搭）
前端在 M1 已接入白盒所需入口：新建表单「Kali 代码目录/仓库」、模式自动识别（repo→`code`，url+repo→`combined`）、源码材料快照/浏览/按行保留/版本对照、`source` 类证据视图、报告按证据逐条嵌入内容。后端创建/更新会话已接受 `repo`（绝对路径校验、禁止 `..`），执行沙箱已支持 `/repo` 只读挂载。

### 本轮新交付
1. **确定性白盒端到端验证**（`test_research_worker.py::test_worker_code_audit_end_to_end`）：再造一个 repo-only(`code`) 会话，经**真实 worker** 认领；bwrap 沙箱把授权代码目录 `/repo` 只读挂载；研究步骤（确定性的假 claude）在沙箱内**实际读取 `/repo`** 推出源码位置并回写：
   - 会话 `code` 模式 → `completed`；
   - `source` 证据带 `metadata.file/line/saw_repo` + 内容 `app.py:4`（即步骤真实读到的行号）；
   - 发现与审计报告**已提交**，报告含代码目录路径、`admin_resource`、`app.py:4` 的可回源代码引用；
   - code-only 不启动 egress，`usage.requests` 仅计开始前取门 1（不被当作目标 HTTP）。
2. **提示词增强**（`default/research.md`）：白盒/代码证据必须带**可定位坐标**（`app.py:12`/区间）并注明版本/快照 hash，供审计报告回源；避免无坐标的笼统描述。

### 分类（诚实）
- **白盒执行链路**（claim→沙箱 `/repo` RO→读代码→source 证据→发现→审计报告→completed）已**确定性端到端跑绿**，不依赖模型网关。
- **真实模型对真实代码目录的框架识别/入口与数据流审计输出质量**仍属「真实模型尚未验证」——受该模型网关限流/不稳定影响（用户已明确不当作阻塞）。

### 回归
- `test_research_worker.py` **26 项** + `test_research_egress.py` **12 项** = **38 项全通过**（Kali `.venv`）。
- 本轮未提交、未推送；Git HEAD 保持 5e2fcc5；Windows 镜像与 Kali 权威工作树改动已同步。

### M2 真实模型白盒冒烟（2026-09-09，临时项目，能跑级别）
按要求新建临时简易项目 `/tmp/m2_proj`（一个几行的 Python 示例），在隔离库 + 独立 8017 服务器下用**真实模型**跑白盒单轮：
- 真实模型在 code 模式读授权代码目录 `/repo/main.py`，把完整文件内容写入 `source` 证据；事件链 authorization→queued→running→evidence→paused；exit 0，花费约 $0.79。
- 本轮非终态干净收束 → 正确进入 paused（轮次边界行为）；未到 findings/终态报告（真实模型输出不要求可靠）。
- 得出结论：**代码目录→worker 认领→沙箱 /repo RO→真实模型读代码→源码证据→记费→暂停**的白盒链路用真实模型真实跑通。隔离环境已停；证据保留在 `/tmp/cairn-m2-acc/cairn.db`。
- 未提交、未推送；HEAD 保持 5e2fcc5。

## 2026-09-09 M3 黑白盒联动（首个执行切片，确定性验证）

用户继续指挥进入 M3 黑白盒联动（代码/路由/请求映射 + 静态疑点动态验证 + 基线对照/复测）。

### 联动承载面（已具备，无需新搭）
执行层已支持 `combined` 模式（url + repo 同时授权）：沙箱既 RO 挂载 `/repo`，又为授权目标启动出站代理；提示词要求 `http`/`request` 证据记录每次目标请求、`source` 证据带可定位坐标。前端新建表单已可同时填运行环境地址与代码目录。

### 本轮新交付
1. **确定性联动端到端验证**（`test_research_worker.py::test_worker_combined_audit_maps_code_to_request`）：再造一个 combined 会话（本地真实运行环境 HTTP fixture + 代码目录），经真实 worker 认领；研究步骤既读 `/repo` 定位路由（`source` 证据 `main.py:4`），又对运行环境发真实 `GET /data?id=1`（`http` 证据，含真实基线响应 `owner/admin`），二者关联到同一发现；会话 `completed`，证据同时含 `source` + `http`，报告含 `main.py:4`、`/data?id=1` 与基线响应，且动态请求已计入用量。
2. **修复非阻塞下的请求归因漏计**（`research_worker.py::_apply_payload`）：终结提交 `commit_run_results` 会把会话置终态并**清掉租约**，导致随后 `account_usage` 的 `lease_owner==worker` 校验失败、`http`/`request` 证据请求不被计入（在 combined 测试复现）。修复为在终结提交**前**先归因证据请求（egress 激活时权威计数由结算前代理计数承担，不重复）。修复后 39 项 worker+egress 含 regression。

### 分类（诚实）
- **联动执行链路**（combined 认领 → `/repo` RO + 目标代理 → 读代码定位路由 → 对运行环境发真实请求 → code↔route↔request 证据 → 报告 → completed）已**确定性端到端跑绿**。
- **真实模型对真实应用做联动映射 / 动态对照 / 修复复测的输出质量**仍属「真实模型尚未验证」（受该模型网关影响，用户已明确不当作阻塞）。

### 回归
- `test_research_worker.py` **27 项** + `test_research_egress.py` **12 项** = **39 项**全通过；broader（egress+worker+api+db_migrations+sources+source_compare+identities）**152 项**全通过（Kali `.venv`）。
- 本轮未提交、未推送；Git HEAD 保持 5e2fcc5；Windows 镜像与 Kali 权威工作树已同步。

### M3 真实联动冒烟（2026-09-09，临时 Flask 应用，能跑/受阻分类）
按要求把 `/tmp/m2_proj` 修正为可运行的 Flask 应用（`main.py`，路由 `/`、`/data?id=`、`/password?p=`，含未校验身份的 `/data`），在 Kali 以 `python3 main.py` 起真实服务（`http://127.0.0.1:8100`，已探通返回 `{"owner":"admin"}` 等真实响应）。在隔离库 + 独立 8018 服务器下建 combined 会话（url=运行中的应用、repo=其源码），用**真实模型**跑联动单轮：
- 执行层真实跑通：真实 worker 认领、沙箱 RO 挂载 `/repo`、目标 Flask 可达。
- 但真实模型网关两次都在吐出最终 JSON 报告**之前**终止（先后为 `error_max_budget_usd`、`api_error_status 403`），累计约 $2.8 未落地任何证据/发现/报告。
- 分类：**联动执行链路**（combined 认领→/repo RO+目标代理→读代码→对运行环境发真实请求→code↔route↔request 证据→报告→completed）已在确定性端到端测试 `test_worker_combined_audit_maps_code_to_request` 跑绿；**真实模型完整联动输出**仍受该网关不稳定（budget/429/403）阻塞，属“真实模型尚未完成，执行层已验证”，与用户既定的“不当阻塞”判定一致。
- 隔离环境与应用已停止；可运行样例保留在 `/tmp/m2_proj/main.py`，运行证据在 `/tmp/cairn-m3-acc/cairn.db`。

### M4 可靠性：失败分类 + 有界恢复（首个执行切片）
按方案补上可靠性核心空白（长任务续跑/检查点/成本治理此前已有；本切片聚焦**失败分类 + 有界自动恢复**，直接对应长期遇到的网关 429/403/budget 不稳定）：
- `research_services.classify_failure(...)`：把一轮失败归为 `provider_error`(429/403/5xx/限流)、`timeout`、`budget_exhausted`、`protocol_error`、`permission_error`、`execution_error`、`aborted`，并给出 `recoverable` 判定。**仅有**明确瞬态的 provider/限流与会话超时判为可恢复；真正的 bug、预算耗尽、权限/协议违例一律不可自动重试，避免有界恢复死循环。
- `research_sessions` 新增 `retry_count`、`latest_failure_json`（迁移 41）；`get_session` 自动暴露 `retry_count` 与 `latest_failure`（category/recoverable/reason/attempt），前端详情可直接展示失败原因。
- `research_services.fail_session(...)` + worker `_fail(...)`：可恢复失败且 `retry_count < MAX_RECOVERABLE_RETRIES(=2)` 时**自动把会话放回 `queued`**（下一次 tick/worker 以新 run 批次重试，受预算记账/租约约束），否则置 `failed` 并写明「已达到有界恢复上限」；每次失败都记一条事件与 attempt 计数。
- worker 的进程失败分支（超时/非零退出、输出无法解析）改为走分类+有界恢复；成功、暂停、租约丢失、预算门等既有路径不变。
- 新增测试 4 项：分类器各类别；`fail_session` 有界上限（前两次重排队、第三次此后置 failed、retry_count 不超过上限 2、永久失败不重排队）；worker 集成（假 claude 返回 429 → 分类 `provider_error` → 重排队 `queued`、retry_count=1）。
- 回归：worker 27+4 + egress 12 = 42 全过；研究模块 broader（worker+egress+api+db_migrations+sources+source_compare+identities）= **155 全过**。
- 分类：**夹具/确定性已验证**（瞬时 429 会在下个 tick 有界重试、永久失败立即 failed）。真实网关的 429/403 完整多次重试成败仍受提供方限流影响，属「真实模型尚未完成，执行层已验证」。

### M4 其余方向：成本治理（剩余预算遥测 + 追加预算恢复闭环）
在已有预算执行层（max_cost_usd/minutes/requests 硬门、费用待核对、run 批次账本、预扣/结算）之上补齐治理闭环：
- `research_services.settle_run` 结算后调用新增 `_maybe_budget_warn(...)`：剩余成本预算**首次跨越 50%/25%/10% 阈值**时发一条 `budget_warn` 事件（带剩余 cost/百分比/请求数/秒数），UI 事件流可见「预算跑道变短」而不再是硬门前静默失败。发送逻辑用「结算前百分比 > 阈值 ≥ 结算后百分比」判定，天然只在跨越瞬间触发，无需额外状态。
- 确认并打通**追加预算 → 恢复**闭环：`resume_session` 对预算耗尽的会话返回 409（明确「需追加预算」）；`PATCH .../budget`（`authorization_confirmed=true` 且 bump authorization_revision 写授权记录）提升 `max_cost_usd` 后 `resume` 成功回到 `queued`，已耗额度不被重置。
- 新增测试 2 项：`test_settle_emits_budget_warning`（结算把剩余降到 40% → 出现 `budget_warn`，cost_pct≤50、cost_usd≤0.41）；`test_budget_topup_resume_recovery_loop`（预算耗尽 failed 会话拒绝 resume=409 → 确认后追加 → resume 成功 queued、已耗 1.0 保留、出现 budget 事件）。
- 回归：worker+egress+api+db_migrations+sources+source_compare+identities = **157 全过**（155 + 新增 2）。
- 分类：**夹具/确定性已验证**（遥测触发与续费恢复均为确定性路径，不依赖真实模型）；真实网关下多次 429/403 烧钱后能否靠本闭环顺利续费恢复仍待真实验证（属「执行层已验证」）。

### M4 其余方向：经验反馈（跨会话学习）
- 新增 `research_experiences` 表（迁移 42：session_id/scope_key/kind(finding|lesson)/content/ref）与 `distill_experiences(conn, session_id)`：在某轮 terminal 提交时把 **confirmed findings** 沉淀为 `finding` 经验，并把该会话记录过的**分类失败**（latest_failure）沉淀为 `lesson` 经验；按 `session_scope`（repo:/url: 作用域）归属，具备幂等（一条 confirmed finding 一行、每会话至多一条 lesson）。
- `session_scope(row_or_dict)`：稳定目标作用域（repo 优先，其次 url），供跨会话匹配；兼容 sqlite3.Row 与 dict（Row 无 `in`/`.get`，用 `.keys()` 判列）。
- `_build_prompt` 新增注入：`list_experiences_for_scope(conn, scope, session_id)` 拉取**其它会话**在同一作用域下沉淀的经验，渲染成 `{experience_summary}`（带来源会话 id 与 ref，标注「仅作参考提示，不属于本会话证据」）；作用域不同的会话不会看到。模板 `default/research.md` 增加对应小节。
- 新增测试 2 项：`test_distill_experiences_from_confirmed_findings`（沉淀 finding+lesson、幂等、作用域列出排除源会话）；`test_experience_injected_into_same_scope_prompt`（同作用域新会话 prompt 含先前经验+来源，异作用域不含）。
- 分类：**夹具/确定性已验证**；真实模型是否会据此改变复测行为尚未真实验证（执行层已具备注入能力）。

### M4 其余方向：变化触发（指纹基线 → 自动触发复测）
- 新增 `research_changewatch` 表（迁移 43：scope_key 主键 / fingerprint / checked_at / changed_at）。
- 指纹原语：`fingerprint_repo(path)`（递归 sha256：相对路径+每文件内容 hash，忽略 `.git`）、`fingerprint_url(url, probe='/')`（status+body hash；不可达记 `unreachable:<url>` 以捕获可达性变化）。
- `recheck_scope(conn, scope, fingerprint)`：无基线时记录并返回 `first=True/changed=False`；相同即未变；不同则更新基线并返回 `changed=True`（之后重复检查静默，直到下一次变更）。
- `requeue_for_reaudit(conn, session_id, changed)`：仅 `completed` 会话在目标变化时置回 `queued`（保留原授权/预算/历史，新 run 批次）并发 `change` 事件，`next_direction` 指示「复核先前发现是否仍成立」。
- 路由 `POST /api/research/sessions/{session_id}/recheck`：重指纹当前 url/repo → 比对基线 → 变化时重排队复测。
- 新增测试 2 项：`test_repo_fingerprint_changes_with_content`（同一树 hash 稳定、内容变更变值、`.git` 不影响）；`test_recheck_baseline_and_change_requeues`（首检基线、重复未变、内容变更 changed、非 completed 不重排、completed 后变更 → requeued + `change` 事件 + phase=1）。
- 分类：**夹具/确定性已验证**（repo 指纹与复测排队为确定性路径）；真实应用/url 监测的持续触发仍待真实环境验证。

### M4 里程碑总览
- 长任务续跑/检查点/暂停恢复：已有；失败分类+有界恢复：首轮切片；成本治理（剩余预算遥测 + 追加预算恢复闭环）：本里程碑实现；经验反馈：本轮实现；变化触发：本轮实现。
- 累计新增测试 41→46（worker+egress）+ 至 broad：**161 全过**（worker 25+egress 12+新 8 等）。迁移 42/43 在全新/既有库均干净。

### 2026-09-10 已知缺口完善 + 最后整体检查

#### 完善：M1 单轮自动收束（确定性）
末次真实运行暴露：非终态步骤在每 claim 一步的轮次模型下降落在 `paused`，若不再人工 resume，会话会一直停着而无自动完成/自动报告。本轮补齐受控自动收束：
- `research_services.auto_finalize_if_exhausted(conn, session_id)`：非终态步骤已提交进 `paused` 后，若成本/时长/请求额度全部耗尽 **或** 达到 `max_steps` 上限（无法再启动新步骤），自动把会话收束为 `completed`（phase=3）并走 `create_report` 生成报告，追加「本轮研究已自动收束」事件，**如实注明未验证事项保留为未验证，不代表目标安全或检查完整**——它绝不编造 findings。
- 有边界：仅 `paused` 状态触发；`completed/waiting_input/running/queued` 或仍有可继续预算/步骤额度时一律不触发（`can_continue` 判定）。因此正常多轮续跑不受影响，且不会把半成品误标完成。
- worker 在 `_apply_payload` 成功提交后调用 `_auto_finalize_if_exhausted`。
- 新增测试 2 项：`test_paused_step_autofinalizes_on_steps_cap`（max_steps=1，非终态→completed+报告+「自动收束」事件）；`test_paused_step_stays_paused_with_budget`（负例：有预算/步骤时仍 paused，不误收束）。
- 分类：**夹具/确定性已验证**；真实网关下单轮跑到预算/步骤上限后自动生成报告的实际表现仍待真实环境（执行层已具备收束能力）。

#### 其他已知缺口的判定（核对结果）
- M2/M3 真实模型输出质量、完整联动、M4 真实行为：受供应商网关 429/403/budget 阻塞（用户已明确不当阻塞），非代码可完善项，保持「真实模型尚未验证」分类，留待真实环境验收。
- 正式服务始终用独立进程 `cairn research-worker`，未并入服务内自动常驻（`available=false`）；历轮验收均用隔离库+独立服务器、未碰生产库，本轮保持该约定，ad hoc 不启动生产 worker。

#### 最后整体检查（Kali 权威工作树，实测）
- 研究域广域回归：worker+egress+api+db_migrations+sources+source_compare+identities = **163 全过**（161 + 新增自动收束 2）。
- 迁移演练：在正式库的临时拷贝升迁，`integrity_check=ok`，仅 `schema_migrations` 记录数 38→43（预期），其余表行数不变；迁移 39 `research_worker_runtime` / 40 `research_run_accounts` / 41 `research_failure_recovery` / 42 `research_experiences` / 43 `research_changewatch` 均在。未触碰活库。
- Git HEAD 保持 `5e2fcc5`，未提交未推送（与约定一致）。
- 运行态：无 `research-worker` 进程；8015–8019 隔离验收服务已停；正式 `GET /api/research/runtime` 仍 `available=false`（worker 未附挂，符合不碰生产库约定）。
- Windows↔Kali 本轮改动 md5 一致。

### 2026-09-10 Git 交付：研究分支合并进 main
- 第①：研究工作流可插拔其它 agent（`--driver`/`CAIRN_RESEARCH_DRIVER`，复用 `get_driver` 注册表 + 各 driver `build_execute`/`extract_analysis_response`；claude 默认全回归，codex/pi/mock 接通复用、真实输出未验证）。
- 第②：移除旧漏洞挖掘平台（router/collectors/adapters/CLI/提示词/静态/测试；解耦 app/cli/scheduler/loop/reason/config 启动链；保留 DB 迁移与表）。App 启动正常、`/vulnerability` 路由已摘、全量 290 通过（仅剩 1 项既有 container-manager env 失败）。
- 第③：新建并推送分支 `feat/research-workbench`（`b52de6f`），再从 `main` 快进合并（`merge-tree` 0 冲突，因 feat 自 main tip 派生），推送 `origin/main` 至 `b52de6f`。历史仍保留 32 个 vuln-4.1 提交，最终树只含研究工作台+CTF。
- 排除 `参考资料/`、`runtime/` 未纳入 Git。

### 2026-09-10 pi 成为一等研究后端（方案 A）——真实 WSL 单会话已验证
- 泛化 research_sandbox.build_sandbox：额外只读运行时绑定(node/nvm)、沙箱 home 种子(~/.pi/agent 配置)、argv 全命令、可扩展 sandbox PATH；claude 路径保持原样。
- 泛化 research_egress.extract_gateway_hosts 读 ~/.pi/agent/models.json，使 llm-router 作为“模型网关”免配额放行。
- research_worker：pi 沙箱组装(绑 node 根+种子 ~/.pi+扩展 PATH+argv 全命令)；egress .so 改用驱动无关挂载点 /cairn-egress；worker_scoped_env 不再携带宿主代理变量(由 egress 代理统一接管，规避 127.0.0.1:7897 类坏代理)；pi 步骤无状态(不传 --session，每步重注入全量上下文)；pi 载荷缺失 awaiting_input 时安全缺省 False(不伪造完成，terminal 仍严格)。
- PiDriver.extract_analysis_response：容错解析 pi --mode json 事件流 / 去围栏 / 取首个完整 JSON。
- 强化 default/research.md：明确 terminal/awaiting_input 必须为原始布尔。
- 验证：Kali 全量 292 过；WSL 真实 pi 单会话端到端过(白盒 code，沙箱内连 llm-router=deepseek，产出合规信封入库)。
- 诚实标注：pi 真实输出质量取决于模型(deepseek-v4-flash 会漏 awaiting_input，已安全缺省)；每步无状态(靠 worker 重注入上下文续跑)；费用无法从 pi 信封取 total_cost_usd，成本按 费用待核对 挂账。
