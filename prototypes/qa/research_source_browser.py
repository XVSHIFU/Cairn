"""Source material UI acceptance using temporary text fixtures, no source execution."""
from pathlib import Path
import hashlib
import json
import tempfile
from playwright.sync_api import sync_playwright, expect

BASE="http://192.168.61.129:8012"
OUT=Path("/tmp/cairn-research-integration-qa")
OUT.mkdir(exist_ok=True)
fixture=Path(tempfile.mkdtemp(prefix="cairn-source-ui-"))
repo=fixture/"source";repo.mkdir()
other=fixture/"other";other.mkdir()
original=b'# Fixture text only\r\nprint("stored text")\r\n<b>literal source</b>\r\n'
(repo/"sample.py").write_bytes(original)
(repo/"notes.unknown").write_text("first\u2028second\nthird\n")
(repo/"long.txt").write_text("\n".join("line "+str(i) for i in range(1,652))+"\n")
(repo/".env").write_text("HIDDEN_FIXTURE_CANARY")
(repo/"node_modules").mkdir()
(repo/"node_modules"/"ignored.js").write_text("dependency fixture")
(repo/"binary.dat").write_bytes(b"\0\1")
(repo/"linked.txt").symlink_to(other/"outside.txt")
(other/"outside.txt").write_text("OUTSIDE_FIXTURE_CANARY")
checks=[];errors=[];external=[]
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True)
 page=browser.new_page(viewport={"width":1440,"height":1000})
 page.on("pageerror",lambda e:errors.append(str(e)))
 page.on("request",lambda r:external.append(r.url) if r.url.startswith(("http:","https:")) and not r.url.startswith(BASE+"/") else None)
 page.goto(BASE+"/research")
 page.get_by_test_id("new-project").click()
 page.locator('[x-model="draft.title"]').fill("源码材料浏览器夹具 "+fixture.name)
 page.locator('[x-model="draft.objective"]').fill("只验收材料固定、显示与选行，不执行源文件。")
 page.get_by_role("textbox",name="代码目录或仓库",exact=True).fill(str(repo))
 page.locator('[x-model="draft.authorized"]').check()
 with page.expect_response(lambda r:r.url.endswith("/sources") and r.request.method=="POST") as created:
  page.get_by_role("button",name="授权并开始研究").click()
 snapshot=created.value.json();assert created.value.status==201,snapshot
 sid=snapshot["session_id"] if "session_id" in snapshot else page.url.split("#/")[1]
 endpoint=BASE+"/api/research/sessions/"+sid
 page.get_by_role("tab",name="研究材料",exact=False).click()
 expect(page.locator(".source-summary")).to_contain_text("3 个文件")
 expect(page.locator(".source-summary")).to_contain_text("跳过项")
 data=page.request.get(endpoint).json()
 assert data["authorization"]["revision"]==1 and not data["findings"] and not data["evidence"]
 assert page.locator("dialog[open]").count()==0
 checks.append("initial authorization also saves source version; no second consent or fabricated finding")
 page.get_by_test_id("source-browser").click()
 dialog=page.locator("#source-dialog")
 dialog.locator(".source-limitations summary").click()
 expect(dialog.locator(".source-limitations")).to_contain_text(".env")
 expect(dialog.locator(".source-limitations")).to_contain_text("不是 Git commit")
 assert "HIDDEN_FIXTURE_CANARY" not in dialog.inner_text()
 assert "OUTSIDE_FIXTURE_CANARY" not in dialog.inner_text()
 dialog.get_by_label("搜索源码文件").fill("sample")
 dialog.locator('button[title="sample.py"]').click()
 expect(dialog.locator(".source-code-block .code-line")).to_have_count(3)
 expect(dialog.locator(".source-code-block")).to_contain_text("<b>literal source</b>")
 assert dialog.locator(".source-code-block b").count()==0
 page.screenshot(path=str(OUT/"sources-desktop.png"),full_page=True)
 checks.append("file search, raw text and line numbers; omitted files and capture limits visible")
 dialog.get_by_label("代码起始行").fill("2")
 dialog.get_by_label("代码结束行").fill("3")
 with page.expect_response(lambda r:r.url.endswith("/evidence") and r.request.method=="POST") as preserved:
  dialog.get_by_role("button",name="保留所选代码").click()
 assert preserved.value.status==201,preserved.value.text()
 eid=preserved.value.json()["evidence_id"]
 expect(dialog).not_to_be_visible()
 data=page.request.get(endpoint).json()
 evidence=next(e for e in data["evidence"] if e["id"]==eid)
 assert evidence["content"]==b'print("stored text")\r\n<b>literal source</b>\r\n'.decode()
 assert evidence["metadata"]["sha256"]==hashlib.sha256(original).hexdigest()
 assert evidence["metadata"]["snapshot_id"]==snapshot["id"]
 assert evidence["metadata"]["line_start"]==2 and not data["findings"]
 expect(page.locator(".evidence-pane .line-number").first).to_have_text("2")
 expect(page.locator(".evidence-pane .code-line:visible")).to_have_count(2)
 checks.append("selected original CRLF lines saved with snapshot and hashes, without a finding")
 (repo/"sample.py").write_text("new stored content\n")
 page.get_by_test_id("source-browser").click()
 with page.expect_response(lambda r:r.url.endswith("/sources") and r.request.method=="POST") as recaptured:
  dialog.get_by_role("button",name="保存新快照",exact=True).click()
 newer=recaptured.value.json();assert newer["digest"]!=snapshot["digest"]
 expect(dialog.get_by_label("源码快照版本")).to_have_value(newer["id"])
 dialog.get_by_label("搜索源码文件").fill("sample")
 dialog.locator('button[title="sample.py"]').click()
 expect(dialog.locator(".source-code-block")).to_contain_text("new stored content")
 dialog.get_by_label("源码快照版本").select_option(snapshot["id"])
 dialog.get_by_label("搜索源码文件").fill("sample")
 dialog.locator('button[title="sample.py"]').click()
 expect(dialog.locator(".source-code-block")).to_contain_text('print("stored text")')
 old=page.request.get(endpoint+"/sources/"+snapshot["id"]+"/file",params={"path":"sample.py"}).json()
 assert old["content"].encode()==original
 current=page.request.get(endpoint).json()
 assert next(e for e in current["evidence"] if e["id"]==eid)==evidence
 checks.append("new capture changes content version; old snapshot and selected evidence remain unchanged")
 dialog.get_by_label("搜索源码文件").fill("long")
 dialog.locator('button[title="long.txt"]').click()
 expect(dialog.locator(".source-code-block .code-line")).to_have_count(300)
 dialog.get_by_role("button",name="下一段").click()
 expect(dialog.locator(".source-code-block .line-number").first).to_have_text("301")
 dialog.get_by_label("代码起始行").fill("640")
 dialog.get_by_label("代码结束行").fill("650")
 dialog.get_by_role("button",name="定位",exact=True).click()
 expect(dialog.locator(".source-code-block .line-number").first).to_have_text("601")
 dialog.get_by_label("搜索源码文件").fill("notes")
 dialog.locator('button[title="notes.unknown"]').click()
 expect(dialog.locator(".source-code-block .code-line")).to_have_count(3)
 checks.append("bounded large-file view, range positioning and unknown-extension UTF-8 files")
 page.set_viewport_size({"width":390,"height":844})
 assert not page.evaluate("document.documentElement.scrollWidth>innerWidth")
 box=dialog.bounding_box();assert box["x"]>=0 and box["x"]+box["width"]<=391
 dialog.locator(".source-limitations").evaluate("(el)=>el.open=false")
 page.screenshot(path=str(OUT/"sources-mobile.png"),full_page=True)
 dialog.get_by_role("button",name="关闭源码材料").click()
 checks.append("source material dialog fits narrow viewport")
 page.set_viewport_size({"width":1440,"height":1000})
 page.get_by_test_id("pause").click()
 expect(page.locator(".run-banner")).to_contain_text("研究已暂停")
 page.locator(".scope-button").click()
 page.get_by_text("追加或更改研究材料",exact=True).click()
 page.get_by_label("更新代码目录").fill(str(other))
 page.locator('[x-model="scopeDraft.authorized"]').check()
 page.get_by_role("button",name="保存材料变更").click()
 expect(page.locator("#scope-dialog")).not_to_be_visible()
 expect(page.locator(".source-summary")).to_contain_text("旧快照仍可查阅")
 page.get_by_test_id("source-browser").click()
 expect(dialog.locator(".snapshot-notice")).to_be_visible()
 dialog.get_by_role("button",name="关闭源码材料").click()
 page.get_by_test_id("report").click()
 page.get_by_test_id("generate-report").click()
 with page.expect_download() as download:
  page.get_by_role("button",name="导出 Markdown",exact=True).click()
 download.value.save_as(str(OUT/"source-report.md"))
 report=(OUT/"source-report.md").read_text()
 assert "sample.py" in report and hashlib.sha256(original).hexdigest() in report
 assert snapshot["digest"] in report and "captured_files_digest" in report
 assert not errors,errors
 assert not external,external
 checks.append("material changes mark old snapshots; report retains original source reference; no script errors or external requests")
 (OUT/"sources-results.json").write_text(json.dumps({"checks":checks,"errors":errors,"external":external,"session_id":sid},ensure_ascii=False,indent=2))
 browser.close()
print(json.dumps({"checks":checks,"errors":errors},ensure_ascii=False))
