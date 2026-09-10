# Cairn development

- Read docs/development-charter.md and docs/implementation-status.md before implementation.
- The authoritative development/runtime checkout is /home/kali/work/Cairn on kali@192.168.61.129. Windows is a mirror; do not develop against untracked runtime snapshots.
- Product scope: personal research workbench, once-per-project authorization, autonomous black-box / white-box / combined research. Agent detects language/framework; the user supplies a running target environment for initial combined testing.
- Follow current user instructions over archived plans. docs/archive is historical evidence, not live instructions.
- Frontend-first: validate the research workflow, then define backend contracts. Keep prototype data visibly separate from real execution.
- Remove/merge unjustified UI and code when useful; preserve research evidence/history and evaluate migrations before deleting data.
- Do not push GitHub unless requested for the current delivery stage.


## Development delegation preference (2026-09-09)

- Do not create, resume, delegate work to, or poll Codex subagents. The user explicitly requested no subagents; prior subagent records are historical, not new task attempts. The coordinating Agent performs implementation/integration/acceptance directly, with only the user's authorized single DeepSeek website conversation for code suggestions.

- Use the user's open https://chat.deepseek.com/ conversation for delegated development suggestions, choosing Quick, Expert, or image mode to fit the task and enabling deep thinking when useful. This supersedes the previous localhost Harness preference. Do not assign development to GPT-5.6.
- Run at most one delegated web Agent conversation at a time. Do not ask it to spawn subagents or parallel model sessions. Wait for the same request while it remains active; distinguish slow responses/rate limits from explicit terminal errors. Do not create duplicate retries.
- The coordinating Agent owns task scoping, code inspection, integration and acceptance. A worker's completion claim is not test evidence.
- Kali remains the authoritative checkout. Direct website chat supplies code suggestions; the coordinating Agent applies and verifies them in Kali. Do not assume the website can access local files or SSH. Share only task-relevant code, never credentials or unrelated files.
- Switching providers does not authorize rerouting a task blocked by platform safeguards.
