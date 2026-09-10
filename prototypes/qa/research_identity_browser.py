"""Configuration-only browser checks with fabricated local identity files."""
from pathlib import Path
import json
import sqlite3
from time import time
from playwright.sync_api import sync_playwright, expect

BASE="http://192.168.61.129:8012"
ROOT=Path("/tmp/cairn-identity-browser-fixtures")
OUT=Path("/tmp/cairn-research-integration-qa")
CANARY="FAKE-IDENTITY-CANARY-NOT-A-REAL-PASSWORD"
checks=[]; errors=[]; posts=[]
def fixture(name,body):
    path=ROOT/"imports"/name
    path.write_text(json.dumps(body))
    path.chmod(0o600)
    return name
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    page=browser.new_page(viewport={"width":1440,"height":1000})
    page.on("pageerror",lambda error:errors.append(str(error)))
    page.on("request",lambda request:posts.append(request.post_data or ""))
    response=page.request.post(BASE+"/api/research/sessions",data={"title":"身份材料验收-"+str(int(time())),"objective":"只验收配置保管，不连接目标。","url":"http://example.test","repo":"/tmp","authorization_confirmed":True})
    assert response.status==201,response.text()
    sid=response.json()["id"]
    page.goto(BASE+"/research#/"+sid)
    page.get_by_role("tab",name="研究材料",exact=False).click()
    page.get_by_test_id("identities").click()
    expect(page.locator(".identity-path")).to_contain_text(str(ROOT/"imports"))
    fixture("account.json",{"type":"account","username":"fixture-user","password":CANARY})
    page.get_by_role("textbox",name="测试身份名称").fill("成员 A")
    page.get_by_role("textbox",name="身份材料文件名").fill("account.json")
    page.get_by_role("button",name="导入身份",exact=True).click()
    expect(page.locator(".identity-card")).to_contain_text("成员 A")
    expect(page.locator(".identity-card")).to_contain_text("已导入")
    expect(page.get_by_role("textbox",name="身份材料文件名")).to_have_value("")
    first=page.request.get(BASE+"/api/research/sessions/"+sid+"/identities").json()["items"][0]
    iid=first["id"]
    assert first["kind"]=="account" and first["version"]==1
    assert set(first)=={"id","label","kind","origin","version","status","created_at","updated_at"}
    assert CANARY not in page.content() and CANARY not in json.dumps(posts)
    assert CANARY not in page.request.get(BASE+"/api/research/sessions/"+sid).text()
    checks.append("file import stores identity metadata without browser credential transfer")
    page.get_by_role("button",name="关闭测试身份").click()
    page.reload()
    page.get_by_role("tab",name="研究材料",exact=False).click()
    expect(page.locator(".identity-summary .tab-count")).to_have_text("1")
    page.get_by_test_id("identities").click()
    expect(page.locator(".identity-card")).to_contain_text("成员 A")
    checks.append("identity summary persists across page reload")
    fixture("cookies.json",{"type":"cookies","cookies":{"session":CANARY+"-ROTATED"}})
    page.locator(".identity-card").get_by_role("button",name="更换材料",exact=True).click()
    page.get_by_role("textbox",name="身份材料文件名").fill("cookies.json")
    page.get_by_role("button",name="保存更换",exact=True).click()
    expect(page.locator(".identity-card")).to_contain_text("版本 2")
    expect(page.locator(".identity-card")).to_contain_text("Cookie")
    assert page.request.get(BASE+"/api/research/sessions/"+sid+"/identities").json()["items"][0]["id"]==iid
    checks.append("replacement retains identity reference and advances version")
    fixture("invalid.json",{"password":CANARY,"wrong":True})
    page.get_by_role("textbox",name="测试身份名称").fill("不应保存")
    page.get_by_role("textbox",name="身份材料文件名").fill("invalid.json")
    page.get_by_role("button",name="导入身份",exact=True).click()
    expect(page.locator("#identity-dialog .form-error")).to_contain_text("格式无效")
    assert CANARY not in page.content()
    assert len(page.request.get(BASE+"/api/research/sessions/"+sid+"/identities").json()["items"])==1
    checks.append("invalid import errors do not echo file contents or add rows")
    page.get_by_role("button",name="关闭测试身份").click()
    changed=page.request.patch(BASE+"/api/research/sessions/"+sid+"/materials",data={"url":"http://other.example.test","authorization_confirmed":True})
    assert changed.status==200,changed.text()
    page.reload()
    page.get_by_role("tab",name="研究材料",exact=False).click()
    page.get_by_test_id("identities").click()
    expect(page.locator(".identity-card")).to_contain_text("环境已变更")
    page.locator(".identity-card").get_by_role("button",name="更换材料",exact=True).click()
    page.get_by_role("textbox",name="身份材料文件名").fill("account.json")
    page.get_by_role("button",name="保存更换",exact=True).click()
    expect(page.locator(".identity-card")).to_contain_text("版本 3")
    expect(page.locator(".identity-card")).to_contain_text("http://other.example.test")
    expect(page.locator(".identity-card .verdict")).to_have_text("已导入")
    checks.append("origin changes mark stale until explicit material replacement")
    page.get_by_role("button",name="关闭测试身份").click()
    assert page.request.patch(BASE+"/api/research/sessions/"+sid+"/materials",data={"url":None}).status==200
    page.reload()
    page.get_by_role("tab",name="研究材料",exact=False).click()
    page.get_by_test_id("identities").click()
    expect(page.get_by_role("button",name="导入身份",exact=True)).to_be_disabled()
    page.locator(".identity-card").get_by_role("button",name="撤销",exact=True).click()
    expect(page.locator(".identity-card")).to_contain_text("已撤销")
    with sqlite3.connect("/tmp/cairn-research-validation.sqlite3") as conn:
        row=conn.execute("SELECT status,ciphertext,nonce FROM research_identities WHERE id=?",(iid,)).fetchone()
        assert row==("revoked",None,None)
    report=page.request.post(BASE+"/api/research/sessions/"+sid+"/reports",data={}).json()
    assert CANARY not in json.dumps(report)
    checks.append("revocation after removing URL clears stored ciphertext; reports omit secrets")
    page.set_viewport_size({"width":390,"height":844})
    assert not page.evaluate("document.documentElement.scrollWidth>innerWidth")
    expect(page.get_by_role("button",name="关闭测试身份")).to_be_visible()
    page.screenshot(path=str(OUT/"identity-mobile.png"),full_page=True)
    page.get_by_role("button",name="关闭测试身份").click()
    page.set_viewport_size({"width":1440,"height":1000})
    page.get_by_test_id("identities").click()
    page.screenshot(path=str(OUT/"identity-desktop.png"),full_page=True)
    checks.append("narrow and desktop identity dialog remains usable")
    assert not errors,errors
    assert CANARY not in json.dumps(posts)
    result={"checks":checks,"errors":errors,"session_id":sid}
    (OUT/"identity-results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2))
    browser.close()
print(json.dumps(result,ensure_ascii=False))
