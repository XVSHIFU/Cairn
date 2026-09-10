"""Project-scoped edit dialogs retain their own lifecycle during delayed writes."""
import json,sys
from uuid import uuid4
from playwright.sync_api import sync_playwright,expect
BASE="http://192.168.61.129:8012"
checks=[];errors=[]
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True)
 page=browser.new_page(viewport={"width":1440,"height":1000})
 page.on("pageerror",lambda e:errors.append(str(e)))
 items=[]
 for label in ["A","B"]:
  r=page.request.post(BASE+"/api/research/sessions",data={"title":"授权弹窗夹具 "+label+" "+uuid4().hex[:6],"objective":"验证编辑界面，不运行研究。","url":"http://"+label.lower()+".example.test","authorization_confirmed":True})
  assert r.status==201
  items.append(r.json())
 a,b=items
 dialog=page.locator("#scope-dialog")
 def state(project):
  return page.request.get(BASE+"/api/research/sessions/"+project["id"]).json()
 def goto(project,initial=False):
  if initial:page.goto(BASE+"/research#/"+project["id"])
  else:page.evaluate("(id)=>{location.hash='#/'+id}",project["id"])
  expect(page.locator('h1[x-text="current.title"]')).to_have_text(project["title"])
  page.wait_for_function("!Alpine.$data(document.querySelector('[x-data]')).loading")
  page.evaluate("clearInterval(Alpine.$data(document.querySelector('[x-data]')).pollTimer)")
 def open_scope():
  page.locator(".profile-button").click()
  expect(dialog).to_be_visible()
 def expand(index):
  el=dialog.locator("details").nth(index)
  if el.get_attribute("open") is None:el.locator("summary").click()
 def material(value):
  expand(0)
  page.get_by_label("更新运行环境").fill(value)
  dialog.locator('input[x-model="scopeDraft.authorized"]').check()
 def budget(value):
  expand(1)
  page.get_by_label("总请求上限",exact=True).fill(str(value))
  dialog.locator('input[x-model="budgetDraft.authorized"]').check()
 def clean_toast():
  page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast=''")
 def toast():return page.evaluate("Alpine.$data(document.querySelector('[x-data]')).toast")
 pending=[]
 def hold(route):
  if route.request.method=="PATCH":pending.append(route)
  else:route.continue_()
 page.route("**/api/research/sessions/*/materials",hold)
 page.route("**/api/research/sessions/*/budget",hold)
 def submit(kind):
  page.get_by_role("button",name="保存材料变更" if kind=="materials" else "保存预算",exact=True).click()
  for _ in range(100):
   if pending:break
   page.wait_for_timeout(20)
  assert len(pending)==1
  return pending[0].request.post_data_json
 def release(failure=False):
  route=pending.pop()
  if failure:route.fulfill(status=503,content_type="application/json",body='{"detail":"夹具保存失败"}')
  else:route.continue_()
  page.wait_for_function("!Alpine.$data(document.querySelector('[x-data]')).busy")

 goto(a,True);open_scope();material("http://a-edit.example.test")
 goto(b)
 if "--reproduce" in sys.argv:
  assert dialog.is_visible()
  assert page.get_by_label("更新运行环境").input_value()=="http://a-edit.example.test"
  print(json.dumps({"reproduced":"A draft remained editable while selected project was B","production_writes":False,"errors":errors},ensure_ascii=False))
  browser.close();raise SystemExit(0)
 expect(dialog).not_to_be_visible()
 open_scope();expand(0)
 expect(page.get_by_label("更新运行环境")).to_have_value(b["url"])
 assert not dialog.locator('input[x-model="scopeDraft.authorized"]').is_checked()
 checks.append("hash navigation closes previous project draft and clears its consent")

 material("http://b-saved.example.test");submit("materials")
 page.keyboard.press("Escape");expect(dialog).not_to_be_visible()
 open_scope();material("http://b-next.example.test");clean_toast()
 release()
 expect(dialog).to_be_visible()
 expect(page.get_by_label("更新运行环境")).to_have_value("http://b-next.example.test")
 assert toast()==""
 assert state(b)["url"]=="http://b-saved.example.test/"
 checks.append("Escape and reopen keep new dialog intact when old material save succeeds")

 page.get_by_role("button",name="关闭授权摘要").click()
 open_scope();budget(350);submit("budget")
 page.get_by_role("button",name="关闭授权摘要").click()
 open_scope();budget(360);clean_toast();release(True)
 expect(dialog).to_be_visible()
 expect(page.get_by_label("总请求上限",exact=True)).to_have_value("360")
 assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).formError")==""
 assert toast()=="" and state(b)["budget"]["requests"]==300
 checks.append("closed budget request failure does not pollute reopened form")

 page.get_by_role("button",name="关闭授权摘要").click()
 open_scope();material("http://b-final.example.test");submit("materials")
 goto(a);expect(dialog).not_to_be_visible();open_scope();material("http://a-new-draft.example.test");clean_toast()
 release()
 expect(dialog).to_be_visible()
 expect(page.get_by_label("更新运行环境")).to_have_value("http://a-new-draft.example.test")
 assert toast()=="" and state(a)["url"]==a["url"]
 assert state(b)["url"]=="http://b-final.example.test/"
 checks.append("pending save persists only original project and leaves new project's form open")

 page.get_by_role("button",name="关闭授权摘要").click()
 open_scope();budget(350);submit("budget")
 budget(360);material("http://a-next-draft.example.test")
 release()
 expect(dialog).to_be_visible()
 expect(page.get_by_label("总请求上限",exact=True)).to_have_value("360")
 expect(page.get_by_label("更新运行环境")).to_have_value("http://a-next-draft.example.test")
 assert state(a)["budget"]["requests"]==350 and state(a)["url"]==a["url"]
 checks.append("editing either form while saving preserves both new drafts")

 submit("materials");release()
 expect(dialog).not_to_be_visible()
 assert state(a)["url"]=="http://a-next-draft.example.test/"
 checks.append("unchanged current material save closes normally")
 open_scope();budget(360);submit("budget");release()
 expect(dialog).not_to_be_visible()
 assert state(a)["budget"]["requests"]==360
 checks.append("unchanged current budget save closes normally and persists requested total")

 open_scope();budget(370);submit("budget");release(True)
 expect(dialog).to_be_visible()
 expect(page.get_by_label("总请求上限",exact=True)).to_have_value("370")
 assert page.evaluate("Alpine.$data(document.querySelector('[x-data]')).formError")=="夹具保存失败"
 assert state(a)["budget"]["requests"]==360
 checks.append("current form failure keeps its draft and error")
 for project in items:
  assert state(project)["usage"]==project["usage"]
 assert not errors,errors
 browser.close()
print(json.dumps({"checks":checks,"errors":errors},ensure_ascii=False))
