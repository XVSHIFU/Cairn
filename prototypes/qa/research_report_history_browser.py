"""Real report browsing on Kali; only the isolated validation database is written."""
from pathlib import Path
import hashlib
import json
from cairn.server import db, research_services as s
from cairn.server.research_models import CreateResearch
from playwright.sync_api import sync_playwright, expect

BASE="http://192.168.61.129:8012"
OUT=Path("/tmp/cairn-research-integration-qa")
OUT.mkdir(exist_ok=True)
db.configure(Path("/tmp/cairn-research-validation.sqlite3"))
with db.get_conn() as conn:
    session=s.create_session(conn,CreateResearch(title="报告历史验收夹具",objective="仅检查报告版本，不执行目标测试。",url="http://example.test",authorization_confirmed=True))
    other=s.create_session(conn,CreateResearch(title="报告隔离验收夹具 "+session["id"],objective="项目隔离检查。",url="http://example.test",authorization_confirmed=True))
sid=session["id"]
base=BASE+"/api/research/sessions/"+sid+"/reports"
checks=[]
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    page=browser.new_page(viewport={"width":1440,"height":1000})
    errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
    writes=[]
    page.on("request",lambda r:writes.append(r.url) if r.method=="POST" and "/reports" in r.url else None)
    page.goto(BASE+"/research#/"+sid)
    page.get_by_test_id("report").click()
    expect(page.get_by_text("尚未生成报告。",exact=False)).to_be_visible()
    assert not writes
    assert page.request.get(base).json()["items"]==[]
    page.get_by_test_id("generate-report").click()
    expect(page.locator(".report-status")).to_contain_text("已保存快照")
    first_link=page.get_by_role("link",name="此快照的固定链接").get_attribute("href")
    first_id=first_link.split("report=")[1]
    first=page.request.get(base+"/"+first_id).json()
    page.get_by_role("button",name="关闭研究报告").click()
    page.get_by_test_id("report").click()
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",first_link)
    assert len(writes)==1
    checks.append("opening is read-only, explicit creation, reopening retrieves saved version")
    page.get_by_role("button",name="关闭研究报告").click()
    saved=[first]
    with db.get_conn() as conn:
        for i in range(24):
            s.add_hint(conn,sid,"报告历史夹具方向 "+str(i))
            saved.append(s.create_report(conn,sid))
    page.get_by_test_id("report").click()
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",BASE+"/research#/"+sid+"?report="+saved[-1]["id"])
    page.get_by_role("button",name="历史报告",exact=True).click()
    expect(page.locator(".report-history-item")).to_have_count(20)
    # A report saved by another browser does not shift the older-page boundary.
    new=page.request.post(base,data={}).json()
    page.get_by_role("button",name="加载更早报告").click()
    expect(page.locator(".report-history-item")).to_have_count(25)
    assert page.locator(".report-history-item").evaluate_all("(els)=>els.map(e=>e.dataset.reportId)")==[r["id"] for r in reversed(saved)]
    page.locator('[data-report-id="'+first_id+'"]').click()
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",first_link)
    with page.expect_download() as download:
        page.get_by_role("button",name="导出 Markdown",exact=True).click()
    path=OUT/"history-original-report.md";download.value.save_as(str(path))
    assert path.read_bytes()==first["markdown"].encode("utf-8")
    assert hashlib.sha256(path.read_bytes()).hexdigest()==first["sha256"]
    assert len(writes)==1
    checks.append("cursor pagination survives concurrent insertion; old selection and download are immutable")
    # Failing list requests must not replace the selected report or create a new one.
    page.route(base+"?*",lambda r:r.fulfill(status=503,json={"detail":"验收历史读取失败"}))
    page.get_by_role("button",name="刷新历史报告",exact=True).click()
    expect(page.get_by_text("历史报告读取失败：验收历史读取失败",exact=True)).to_be_visible()
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",first_link)
    expect(page.locator(".report-history-item")).to_have_count(25)
    assert len(writes)==1
    page.unroute(base+"?*")
    page.get_by_role("button",name="刷新历史报告",exact=True).click()
    expect(page.locator(".report-history-item")).to_have_count(20)
    expect(page.locator(".report-history-item").first).to_have_attribute("data-report-id",new["id"])
    checks.append("history failure preserves current report; refreshing includes newly saved versions")
    # Hold one read, choose another version, then release the old response.
    pending=[]
    slow=saved[-2]
    page.route(base+"/"+slow["id"],lambda r:pending.append(r))
    page.locator('[data-report-id="'+slow["id"]+'"]').click()
    for _ in range(100):
        if pending:break
        page.wait_for_timeout(20)
    assert pending
    page.locator('[data-report-id="'+new["id"]+'"]').click()
    new_link=BASE+"/research#/"+sid+"?report="+new["id"]
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",new_link)
    pending.pop().fulfill(status=200,json=slow)
    page.unroute(base+"/"+slow["id"])
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",new_link)
    page.screenshot(path=str(OUT/"report-history-desktop.png"),full_page=True)
    checks.append("out-of-order body responses cannot replace the chosen version")
    # A closed dialog and a project change invalidate outstanding history reads.
    pending=[]
    response=page.request.get(base+"?limit=20").json()
    page.route(base+"?*",lambda r:pending.append(r))
    page.get_by_role("button",name="刷新历史报告",exact=True).click()
    for _ in range(100):
        if pending:break
        page.wait_for_timeout(20)
    assert pending
    page.keyboard.press("Escape")
    page.locator('.project-nav button').filter(has_text=other["title"]).click()
    expect(page.locator('h1[x-text="current.title"]')).to_have_text(other["title"])
    pending.pop().fulfill(status=200,json=response)
    page.unroute(base+"?*")
    expect(page.locator("#report-dialog")).not_to_be_visible()
    assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).reportHistory.length")==0
    page.get_by_test_id("report").click()
    expect(page.get_by_text("尚未生成报告。",exact=False)).to_be_visible()
    assert not page.request.get(BASE+"/api/research/sessions/"+other["id"]+"/reports").json()["items"]
    checks.append("close and project switch discard late history responses without cross-project data")
    page.goto(first_link)
    expect(page.get_by_role("link",name="此快照的固定链接")).to_have_attribute("href",first_link)
    page.set_viewport_size({"width":390,"height":844})
    page.get_by_role("button",name="历史报告",exact=True).click()
    expect(page.locator(".report-history")).to_be_visible()
    assert page.locator("#report-dialog").evaluate("(el)=>el.scrollWidth<=el.clientWidth+1")
    page.screenshot(path=str(OUT/"report-history-mobile.png"),full_page=True)
    assert len(writes)==1
    assert page.request.get(base+"/"+first_id).json()==first
    checks.append("fixed old link restores after navigation; narrow viewport fits; browsing performs no writes")
    assert not errors,errors
    browser.close()
print(json.dumps({"checks":checks,"errors":errors,"fixture":sid},ensure_ascii=False))
