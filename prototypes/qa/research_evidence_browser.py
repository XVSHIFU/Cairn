"""Evidence/budget UI checks using explicitly labelled fixtures in the isolated DB."""
from pathlib import Path
import json
import hashlib
from cairn.server import db, research_services as s
from cairn.server.research_models import CreateResearch
from playwright.sync_api import sync_playwright, expect

BASE="http://192.168.61.129:8012"
db.configure(Path("/tmp/cairn-research-validation.sqlite3"))
with db.get_conn() as conn:
    session=s.create_session(conn,CreateResearch(title="证据展示验收夹具",objective="仅检查持久证据渲染，不代表目标测试。",repo="/tmp/cairn-research-material-fixture",url="http://example.test",authorization_confirmed=True))
    sid=session["id"]
    evidence=s.record_evidence(conn,sid,"code","验收文件片段","<b>plain text, never HTML</b>\n~~~~\n",{"path":"sample.txt","line_start":1,"source":"browser-test-fixture"})
    http=s.record_evidence(conn,sid,"http","HTTP 展示验收夹具","Fixture HTTP archive; no request was sent.",{"request":"GET /fixture HTTP/1.1","response":"HTTP/1.1 418 Fixture\n\n<b>literal response</b>","status_code":418,"method":"GET","url":"http://example.test/fixture","source":"browser-test-fixture"})
    finding=s.record_finding(conn,sid,"证据显示检查","仅浏览器夹具，尚未验证任何漏洞。",evidence_ids=[evidence["id"],http["id"]],limitations="不可作为目标评估结果。")
    s.pause_session(conn,sid)
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    page=browser.new_page(viewport={"width":860,"height":1000})
    errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
    page.goto(BASE+"/research#/"+sid)
    page.get_by_role("tab",name="发现",exact=False).click()
    page.locator(".finding-card").click()
    expect(page.locator(".evidence-pane")).to_have_class("evidence-pane evidence-mobile-open")
    page.locator(".chain-item").first.click()
    expect(page.locator(".code-line").first).to_contain_text("<b>plain text")
    page.get_by_role("button",name="查看完整原文",exact=True).click()
    expect(page.locator(".artifact-original")).to_contain_text("<b>plain text")
    assert page.locator(".http-code b").count()==0
    page.locator(".evidence-pane-heading").click()
    expect(page.locator(".evidence-pane")).to_have_class("evidence-pane evidence-mobile-open")
    page.locator(".evidence-backdrop").click(position={"x":220,"y":260})
    expect(page.locator(".evidence-pane")).not_to_have_class("evidence-pane evidence-mobile-open")
    assert page.url.endswith("#/"+sid)
    page.locator(".finding-card").click()
    page.keyboard.press("Escape")
    expect(page.locator(".evidence-pane")).not_to_have_class("evidence-pane evidence-mobile-open")
    page.set_viewport_size({"width":1440,"height":1000})
    page.locator(".scope-button").click()
    page.get_by_text("调整预算上限",exact=True).click()
    page.get_by_label("总请求上限",exact=True).fill("400")
    page.locator('[x-model="budgetDraft.authorized"]').check()
    page.get_by_role("button",name="保存预算",exact=True).click()
    expect(page.locator("#scope-dialog")).not_to_be_visible()
    expect(page.locator(".statusbar")).to_contain_text("400 请求")
    data=page.request.get(BASE+"/api/research/sessions/"+sid).json()
    assert data["budget"]["requests"]==400 and data["usage"]["requests"]==0
    assert data["authorization"]["revision"]==2
    page.locator(".chain-item").first.click()
    expect(page.locator(".code-version")).to_contain_text("未记录，无法确认代码版本")
    page.get_by_role("button",name="依据链",exact=True).click()
    page.locator(".chain-item").nth(1).click()
    expect(page.locator(".http-record")).to_contain_text("418")
    expect(page.locator(".http-record")).to_contain_text("<b>literal response</b>")
    assert page.locator(".http-record b").count()==0
    page.screenshot(path="/tmp/cairn-research-integration-qa/evidence.png",full_page=True)
    page.get_by_test_id("report").click()
    page.get_by_test_id("generate-report").click()
    expect(page.locator(".report-status")).to_contain_text("已保存快照")
    report_url=page.get_by_role("link",name="此快照的固定链接").get_attribute("href")
    report_id=report_url.split("report=")[1]
    saved=page.request.get(BASE+"/api/research/sessions/"+sid+"/reports/"+report_id).json()
    page.request.post(BASE+"/api/research/sessions/"+sid+"/hints",data={"content":"快照创建后的新方向，不得混入旧报告"})
    expect(page.locator("#report-dialog .snapshot-notice")).to_be_visible(timeout=10000)
    with page.expect_download() as download:
        page.get_by_role("button",name="导出 Markdown",exact=True).click()
    target=Path("/tmp/cairn-research-integration-qa/immutable-report.md")
    download.value.save_as(str(target))
    assert hashlib.sha256(target.read_bytes()).hexdigest()==saved["sha256"]
    assert target.read_text()==saved["markdown"]
    assert "快照创建后的新方向" not in target.read_text()
    page.goto(report_url)
    expect(page.locator("#report-dialog")).to_be_visible()
    expect(page.locator(".report-status")).to_contain_text("已暂停")
    assert page.get_by_role("link",name="此快照的固定链接").get_attribute("href")==report_url
    page.get_by_role("button",name="生成最新快照",exact=True).click()
    expect(page.get_by_role("link",name="此快照的固定链接")).not_to_have_attribute("href",report_url)
    unchanged=page.request.get(BASE+"/api/research/sessions/"+sid+"/reports/"+report_id).json()
    assert unchanged==saved

    assert not errors,errors
    browser.close()
print(json.dumps({"checks":["persisted evidence rendered as literal text","outside/inside/Escape drawer behavior","budget change confirmation retains usage","source metadata and HTTP literal viewer","snapshot download matches saved SHA256 after later changes","fixed report link survives reload and new reports preserve old snapshots"],"errors":errors},ensure_ascii=False))
