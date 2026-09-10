"""Runtime availability UI checks, using an isolated project and stubbed health replies."""
import json
from playwright.sync_api import sync_playwright,expect
BASE="http://192.168.61.129:8012"
checks=[];errors=[]
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True)
 page=browser.new_page(viewport={"width":1440,"height":1000})
 page.on("pageerror",lambda e:errors.append(str(e)))
 response=page.request.post(BASE+"/api/research/sessions",data={"title":"执行器状态显示夹具","objective":"仅检查界面，不执行研究。","url":"http://example.test","authorization_confirmed":True})
 assert response.status==201,response.text()
 sid=response.json()["id"]
 endpoint=BASE+"/api/research/sessions/"+sid
 original=page.request.get(endpoint).json()
 pending=[]
 page.route("**/api/research/runtime",lambda route:pending.append(route))
 page.goto(BASE+"/research#/"+sid)
 expect(page.locator(".run-banner strong")).to_have_text("项目已保存，执行状态待确认")
 for _ in range(100):
  if pending:break
  page.wait_for_timeout(20)
 assert pending,"Runtime request did not reach the held route"
 for route in pending:route.fulfill(status=200,content_type="application/json",body=json.dumps({"available":False,"message":"夹具：执行器尚未接入"}))
 page.unroute("**/api/research/runtime")
 expect(page.locator(".run-banner strong")).to_have_text("项目已保存，执行器尚未就绪")
 checks.append("initial unknown and explicit unavailable are distinct")
 def visit(health,status="queued",error=None):
  page.unroute("**/api/research/runtime")
  page.unroute(endpoint)
  if health=="error":page.route("**/api/research/runtime",lambda route:route.fulfill(status=503,content_type="application/json",body='{"detail":"夹具：健康接口暂不可用"}'))
  else:page.route("**/api/research/runtime",lambda route:route.fulfill(status=200,content_type="application/json",body=json.dumps({"available":health,"message":"夹具状态"})))
  data={**original,"status":status,"latest_error":error}
  page.route(endpoint,lambda route:route.fulfill(status=200,content_type="application/json",body=json.dumps(data)))
  page.reload()
 visit(True)
 expect(page.locator(".run-banner strong")).to_have_text("研究已排队")
 checks.append("ready queued keeps normal queue state")
 visit("error")
 expect(page.locator(".run-banner strong")).to_have_text("项目已保存，执行状态待确认")
 expect(page.locator(".run-banner p")).to_contain_text("暂时无法确认")
 checks.append("failed health lookup is unknown rather than unavailable")
 for status,title in [("running","Agent 正在研究"),("paused","研究已暂停"),("failed","研究执行受阻")]:
  visit("error",status)
  expect(page.locator(".run-banner strong")).to_have_text(title)
  expect(page.locator(".local-connection")).to_contain_text("暂时无法确认")
 checks.append("health errors do not rewrite running, paused or failed project status")
 visit(False,error="夹具：项目自己的错误")
 expect(page.locator(".run-banner p")).to_have_text("夹具：项目自己的错误")
 checks.append("project error retains description priority")
 assert page.request.get(endpoint).json()==original
 assert not errors,errors
 browser.close()
print(json.dumps({"checks":checks,"errors":errors},ensure_ascii=False))
