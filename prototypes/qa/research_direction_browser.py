"""Delayed direction submissions must preserve newer drafts and project context."""
import json
import sys
from uuid import uuid4
from playwright.sync_api import sync_playwright, expect

BASE = "http://192.168.61.129:8012"
checks, errors = [], []
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width":1440,"height":1000})
    page.on("pageerror", lambda e: errors.append(str(e)))
    projects = []
    for label in ("A","B"):
        response = page.request.post(BASE+"/api/research/sessions", data={
            "title":"方向草稿夹具 "+label+" "+uuid4().hex[:6],
            "objective":"仅验证页面输入与请求生命周期。",
            "url":"http://example.test", "authorization_confirmed":True})
        assert response.status == 201, response.text()
        projects.append(response.json())
    a, b = projects
    pending = []
    def hold(route):
        if route.request.method == "POST":
            pending.append(route)
        else:
            route.continue_()
    page.route("**/api/research/sessions/*/hints", hold)
    def visit(project):
        page.goto(BASE+"/research#/"+project["id"])
        expect(page.locator('h1[x-text="current.title"]')).to_have_text(project["title"])
        page.wait_for_function("!Alpine.$data(document.querySelector('[x-data]')).loading")
        page.evaluate("clearInterval(Alpine.$data(document.querySelector('[x-data]')).pollTimer)")
    def send(text):
        assert not pending
        page.get_by_label("补充研究方向").fill(text)
        page.get_by_role("button",name="发送研究方向",exact=True).click()
        for _ in range(100):
            if pending:
                break
            page.wait_for_timeout(20)
        assert len(pending) == 1
        assert pending[0].request.post_data_json == {"content":text.strip()}
    def release(failure=False):
        route=pending.pop()
        if failure:
            route.fulfill(status=503,content_type="application/json",body='{"detail":"夹具提交失败"}')
        else:
            route.continue_()
        page.wait_for_function("!Alpine.$data(document.querySelector('[x-data]')).busy")
    def hint_events(project):
        response=page.request.get(BASE+"/api/research/sessions/"+project["id"])
        assert response.status==200
        return [e["description"] for e in response.json()["events"] if e["kind"]=="hint"]

    visit(a)
    send("第一条方向")
    page.get_by_label("补充研究方向").fill("正在编辑的下一条")
    release()
    actual=page.get_by_label("补充研究方向").input_value()
    if "--reproduce" in sys.argv:
        assert actual=="", "Expected original bug to clear newer draft"
        print(json.dumps({"reproduced":"late success cleared newer draft","saved":hint_events(a),"errors":errors},ensure_ascii=False))
        browser.close()
        raise SystemExit(0)
    expect(page.get_by_label("补充研究方向")).to_have_value("正在编辑的下一条")
    assert hint_events(a)==["第一条方向"]
    checks.append("same-project newer draft survives; only submitted text is saved")

    send("  普通提交  ")
    release()
    expect(page.get_by_label("补充研究方向")).to_have_value("")
    assert hint_events(a)==["第一条方向","普通提交"]
    checks.append("unchanged successful draft clears and is trimmed once")

    send("留在 A 的方向")
    page.get_by_role("navigation",name="研究项目").get_by_role("button").filter(has_text=b["title"]).click()
    expect(page.locator('h1[x-text="current.title"]')).to_have_text(b["title"])
    page.get_by_label("补充研究方向").fill("B 的未提交草稿")
    page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast=''")
    release()
    expect(page.get_by_label("补充研究方向")).to_have_value("B 的未提交草稿")
    assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast")==""
    assert hint_events(a)[-1]=="留在 A 的方向" and hint_events(b)==[]
    checks.append("cross-project success stays in original project without clearing or notifying new project")

    send("B 的失败请求")
    page.get_by_role("navigation",name="研究项目").get_by_role("button").filter(has_text=a["title"]).click()
    expect(page.locator('h1[x-text="current.title"]')).to_have_text(a["title"])
    page.get_by_label("补充研究方向").fill("A 新草稿")
    page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast=''")
    release(failure=True)
    expect(page.get_by_label("补充研究方向")).to_have_value("A 新草稿")
    assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast")==""
    checks.append("cross-project failure does not overwrite the current notification or draft")

    send("本页失败要保留")
    release(failure=True)
    expect(page.get_by_label("补充研究方向")).to_have_value("本页失败要保留")
    assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast")=="夹具提交失败"
    checks.append("current-project failure remains visible and preserves the submitted draft")

    send("跨离开再回来")
    nav=page.get_by_role("navigation",name="研究项目")
    nav.get_by_role("button").filter(has_text=b["title"]).click()
    expect(page.locator('h1[x-text="current.title"]')).to_have_text(b["title"])
    nav.get_by_role("button").filter(has_text=a["title"]).click()
    expect(page.locator('h1[x-text="current.title"]')).to_have_text(a["title"])
    page.get_by_label("补充研究方向").fill("返回 A 后的草稿")
    page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast=''")
    release()
    expect(page.get_by_label("补充研究方向")).to_have_value("返回 A 后的草稿")
    assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast")==""
    assert hint_events(a)==["第一条方向","普通提交","留在 A 的方向","跨离开再回来"]
    checks.append("returning to same project rejects the old selection epoch")
    assert not errors, errors
    browser.close()
print(json.dumps({"checks":checks,"errors":errors},ensure_ascii=False))
