
const ICONS={
plus:'<path d="M12 5v14M5 12h14"/>',
layers:'<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/>',
code:'<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18"/>',
globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>',
compass:'<circle cx="12" cy="12" r="9"/><path d="m16 8-2.5 5.5L8 16l2.5-5.5L16 8Z"/>',
settings:'<path d="m9 3-.7 2.1-2.2 1.3-2.1-.4-2 3.4 1.5 1.7v2.6L2 15.4l2 3.4 2.1-.4 2.2 1.3L9 22h4l.7-2.3 2.2-1.3 2.1.4 2-3.4-1.5-1.7v-2.6L20 9.4 18 6l-2.1.4-2.2-1.3L13 3Z"/><circle cx="11" cy="12.5" r="3"/>',
shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
play:'<path d="m7 4 14 8-14 8Z"/>',
pause:'<path d="M8 5v14M16 5v14" stroke-width="3"/>',
document:'<path d="M14 3H5v18h14V8l-5-5Z"/><path d="M14 3v6h5M8 13h8M8 17h5"/>',
route:'<circle cx="5" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 5h9a4 4 0 0 1 0 8H8a3 3 0 0 0 0 6h9"/>',
activity:'<path d="M3 12h4l3-7 4 14 3-7h4"/>',
check:'<path d="m5 12 4 4L19 6"/>',
arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
arrowUp:'<path d="M12 20V4m-6 6 6-6 6 6"/>',
warning:'<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v.1"/>',
info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
message:'<path d="M21 4H3v13h5v4l5-4h8V4Z"/><path d="M7 8h10M7 12h7"/>',
link:'<path d="m10 13 4-4m-6 7-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 1 1-1a4 4 0 1 1 6 6l-4 4a4 4 0 0 1-6 0" transform="translate(1 0)"/>',
search:'<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>',
panel:'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M10 3v18m4-13h3m-3 4h3m-3 4h3"/>',
spark:'<path d="m12 3 2.2 6.8L21 12l-6.8 2.2L12 21l-2.2-6.8L3 12l6.8-2.2L12 3Z"/>',
close:'<path d="m6 6 12 12M6 18 18 6"/>',
chevron:'<path d="m9 5 7 7-7 7"/>',
exchange:'<path d="M3 7h17m-4-4 4 4-4 4M21 17H4m4-4-4 4 4 4"/>',
refresh:'<path d="M20 8a8 8 0 1 0 0 8M20 3v5h-5"/>',
download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
menu:'<path d="M4 6h16M4 12h16M4 18h16"/>'
};
const clone=x=>JSON.parse(JSON.stringify(x));
const noteFinding={
id:'F-001',state:'confirmed',severity:'高影响',title:'普通成员可读取他人的私有笔记',
summary:'查询只绑定笔记编号，未检查资源归属。代码线索与两个测试身份的请求结果相互印证。',
basis:'源码检查 + 动态对照 · 虚构样例',
impact:'测试身份 A 能读取测试身份 B 的私有笔记正文。该证据仅证明读取边界失效，不推断修改、删除或其他对象同样受影响。',
gap:'附件下载和分享链接尚未检查；本次演示仅覆盖笔记读取接口。',
file:'src/api/routes/notes.py',commit:'a7c3e91',
code:[
{n:46,text:'@router.get("/api/notes/{note_id}")'},
{n:47,text:'async def read_note(note_id: int,'},
{n:48,text:'    user = Depends(current_user)):'},
{n:49,text:'    # Load note by resource id'},
{n:50,text:'    note = await notes.get(note_id)',highlight:true},
{n:51,text:'    if note is None:'},
{n:52,text:'        raise HTTPException(404)'},
{n:53,text:'    return NoteView.from_orm(note)',highlight:true}],
codeNote:'接口完成了身份认证，但当前查询和返回路径没有将 note.owner_id 与当前用户关联。需结合对照请求判断是否存在其他访问控制。',
request:{baseline:'GET /api/notes/41 HTTP/1.1\nHost: atlas.local.test\nX-Test-Identity: member-a\n\nHTTP/1.1 200 OK\n{"id":41,"owner":"member-a",\n "title":"A 的演示笔记"}',variant:'GET /api/notes/42 HTTP/1.1\nHost: atlas.local.test\nX-Test-Identity: member-a\n\nHTTP/1.1 200 OK\n{"id":42,"owner":"member-b",\n "title":"B 的私有演示笔记"}'},
evidence:[
{id:'E-003',label:'代码入口',title:'按编号读取，未关联当前用户',text:'notes.py:50–53 · 固定代码快照',tab:'code'},
{id:'E-005',label:'基线请求',title:'身份 A 读取自己的笔记',text:'GET /api/notes/41 → 200 · 预期行为',tab:'http'},
{id:'E-007',label:'对照请求',title:'相同身份读到 B 的私有笔记',text:'GET /api/notes/42 → 200 · 归属不匹配',tab:'http'}]
};
const uploadFinding={
id:'F-002',state:'pending',severity:'待评估',title:'附件下载的权限边界仍待验证',
summary:'附件路由与笔记使用独立的读取逻辑，目前只有接口线索，尚未获得有效的跨身份对照。',
basis:'静态线索 · 尚未动态验证',
impact:'目前不能确定能否访问其他成员的附件，需要补充测试对象并完成身份对照。',
gap:'尚缺属于不同测试成员的附件样本，不应把线索计为已证实漏洞。',
file:'src/api/routes/attachments.py',commit:'a7c3e91',
code:[{n:21,text:'@router.get("/api/attachments/{key}")'},{n:22,text:'async def download(key: str,'},{n:23,text:'    user = Depends(current_user)):'},{n:24,text:'    return await storage.resolve(key)',highlight:true}],
codeNote:'需要继续检查 storage.resolve 内部是否实施归属约束；当前入口片段不足以证明存在问题。',
evidence:[{id:'E-008',label:'代码线索',title:'独立的附件读取入口',text:'attachments.py:21–24 · 内层检查未覆盖',tab:'code'}]
};
const rejectedFinding={
id:'F-003',state:'rejected',severity:'',title:'搜索接口未复现查询注入',
summary:'已检查的查询使用参数绑定，当前证据不支持查询结构被输入改变。保留本次证伪依据。',
basis:'代码检查 · 仅当前查询路径',
impact:'本次检查不形成漏洞。结论仅适用于已检查的查询路径与代码版本。',
gap:'未覆盖其他报表或动态排序查询，不能据此声明整个应用不存在注入问题。',
file:'src/services/search.py',commit:'a7c3e91',
code:[{n:18,text:'async def search_notes(query, user):'},{n:19,text:'    stmt = select(Note).where('},{n:20,text:'        Note.owner_id == user.id,'},{n:21,text:'        Note.title.contains(query)'},{n:22,text:'    )',highlight:true},{n:23,text:'    return await db.execute(stmt)'}],
codeNote:'该路径使用表达式构造与绑定参数，且限定当前成员。用户输入作为值传入，不直接拼接为查询结构。',
evidence:[{id:'E-006',label:'证伪依据',title:'查询使用绑定参数与用户条件',text:'search.py:18–23 · 当前代码版本',tab:'code'}]
};
function fixtures(){
const atlas={id:'atlas',title:'Atlas Notes',mode:'combined',url:'http://atlas.local.test:8080',repo:'/home/kali/labs/atlas-notes',objective:'检查成员之间的数据隔离，重点关注私有笔记与附件的访问权限。',stack:'Python · FastAPI',status:'running',stage:2,minutes:45,requests:300,next:'沿着相同的对象访问路径，继续检查附件下载和分享链接。',findings:clone([noteFinding,uploadFinding,rejectedFinding]),events:[
{id:'e1',kind:'complete',time:'14:32:01',title:'识别应用与研究入口',description:'已关联本地实例与代码快照，识别出笔记、附件和分享三个相关入口。',meta:'阅读 4 个文件',trace:'读取 pyproject.toml 与路由定义\n识别 Python / FastAPI\n固定演示代码快照 a7c3e91\n关联网站与本地源码目录'},
{id:'e2',kind:'complete',time:'14:33:18',title:'发现一处缺少归属检查的查询',description:'笔记接口验证了登录身份，但读取路径只使用 note_id。将它列为需要动态确认的假设。',finding:'F-001',linkLabel:'notes.py:50–53',meta:'检索 3 次 · 追踪 1 条调用路径',trace:'GET /api/notes/{note_id}\n入口 → current_user → notes.get(note_id)\n尚需验证：中间件或数据层是否另有归属约束'},
{id:'e3',kind:'complete',time:'14:35:42',title:'用对照请求确认访问边界',description:'保持测试身份 A 不变，切换为 B 的笔记编号，返回了对应私有正文。形成一条有证据的发现。',finding:'F-001',linkLabel:'查看基线与对照 · E-005 / E-007'},
{id:'e4',kind:'warning',time:'14:36:07',title:'保留尚未验证的方向',description:'附件路径独立处理权限。目前缺少对照对象，先继续源码检查；不把它标记成漏洞。',finding:'F-002',linkLabel:'查看附件线索 · E-008'}
],assets:[
{name:'atlas.local.test:8080',detail:'用户提供的运行环境 · 演示种子',type:'web',label:'网站'},
{name:'src/api/routes/notes.py',detail:'笔记读取入口 · 代码快照 a7c3e91',type:'code',label:'源码',finding:'F-001',tab:'code'},
{name:'GET /api/notes/{note_id}',detail:'2 份身份对照证据 · E-005 / E-007',type:'request',label:'接口',finding:'F-001',tab:'http'},
{name:'src/api/routes/attachments.py',detail:'附件下载入口 · 尚待动态验证',type:'code',label:'源码',finding:'F-002',tab:'code'},
{name:'src/services/search.py',detail:'已检查的参数绑定查询',type:'code',label:'源码',finding:'F-003',tab:'code'}]};
const black=clone(noteFinding);black.id='F-101';black.title='测试成员能读取另一成员的草稿';black.summary='基线与对照请求返回了不同所有者的草稿。当前仅有黑盒响应证据，没有源码。';black.basis='黑盒请求对照 · 虚构样例';delete black.code;delete black.file;delete black.commit;delete black.codeNote;black.evidence=black.evidence.filter(e=>e.tab==='http');black.request.baseline=black.request.baseline.replaceAll('atlas.local.test','harbor.local.test');black.request.variant=black.request.variant.replaceAll('atlas.local.test','harbor.local.test');
const harbor={id:'harbor',title:'Harbor Web',mode:'web',url:'http://harbor.local.test:8090',repo:'',objective:'从网站入口检查登录后的对象访问边界，不提供源码。',stack:'',status:'paused',stage:2,next:'继续验证草稿分享链接的访问条件，尚未覆盖删除与修改操作。',minutes:30,requests:200,findings:[black],events:[{id:'h1',kind:'complete',time:'10:11:02',title:'建立网站与接口线索',description:'从演示页面记录草稿列表与读取接口；未提供源码，不推断服务端实现。'},{id:'h2',kind:'complete',time:'10:14:26',title:'得到对象读取对照证据',description:'以两个测试对象建立基线，仅切换对象编号比较返回归属。',finding:'F-101',linkLabel:'查看请求对照'},{id:'h3',kind:'hint',time:'10:15:03',title:'已在检查点暂停',description:'保留现有证据。继续时使用同一项目授权与剩余预算。'}],assets:[{name:'harbor.local.test:8090',detail:'用户提供的网站入口',type:'web',label:'网站'},{name:'GET /api/notes/{note_id}',detail:'演示基线和对照',type:'request',label:'接口',finding:'F-101',tab:'http'}]};
const code=clone(uploadFinding);code.id='F-201';code.title='导出服务的租户约束需要进一步确认';code.summary='调用路径在入口接收租户标识，当前代码片段不足以证明下游始终限定当前租户。没有运行环境，未做动态验证。';code.basis='白盒源码审计 · 未动态验证';code.file='src/main/java/app/ExportService.java';code.commit='c82b1d4';code.code=[{n:37,text:'public Export export(String tenantId) {'},{n:38,text:'    var query = queries.forTenant(tenantId);',highlight:true},{n:39,text:'    return renderer.render(query);'},{n:40,text:'}'}];code.codeNote='需追踪调用方身份来源及 queries.forTenant 的实现，不能仅凭方法参数判定越权。';code.evidence=[{id:'E-021',label:'调用路径',title:'租户标识进入导出查询',text:'ExportService.java:37–40 · 版本 c82b1d4',tab:'code'}];code.impact='尚未确定是否缺少租户隔离；应追踪上游身份绑定与下游查询条件。';code.gap='没有运行环境；动态对照与实际影响尚未验证。';
const ledger={id:'ledger',title:'Ledger Service',mode:'code',url:'',repo:'/home/kali/labs/ledger-service',objective:'审计导出流程的租户隔离与数据访问，优先追踪身份到查询的调用链。',stack:'Java · Spring',status:'done',stage:3,next:'等待提供已搭建的实例和测试租户，再验证导出结果。当前只完成了示例源码检查。',findings:[code],events:[{id:'l1',kind:'complete',time:'昨天 16:10',title:'自动识别工程与入口',description:'从 pom.xml 和控制器目录识别 Java / Spring；无需手工选择语言。'},{id:'l2',kind:'complete',time:'昨天 16:16',title:'追踪导出调用路径',description:'关联导出入口、服务和数据查询，保留一条需要继续确认的租户边界线索。',finding:'F-201',linkLabel:'查看 Java 源码依据'},{id:'l3',kind:'warning',time:'昨天 16:20',title:'收束静态结果，保留验证条件',description:'未提供运行环境，不生成请求证据，也不把当前线索标记为动态已证实。'}],assets:[{name:'src/main/java/app/ExportService.java',detail:'租户数据导出路径',type:'code',label:'源码',finding:'F-201',tab:'code'},{name:'pom.xml',detail:'Java / Spring · 演示识别结果',type:'code',label:'工程'}]};
return [atlas,harbor,ledger];
}

document.addEventListener('alpine:init',()=>{
Alpine.data('workbench',()=>({
projects:fixtures(),selectedId:'atlas',view:'research',selectedFindingId:'F-001',evidenceTab:'overview',evidenceOpen:false,menuOpen:false,
findingFilter:'全部',assetSearch:'',hint:'',toast:'',toastTimer:null,retesting:false,epoch:0,formError:'',
draft:{title:'',objective:'',url:'',repo:'',authorized:false,minutes:45,requests:300},
get current(){return this.projects.find(p=>p.id===this.selectedId)||this.projects[0]},
get selectedFinding(){return this.current.findings.find(f=>f.id===this.selectedFindingId)||null},
get filteredFindings(){return this.current.findings.filter(f=>this.findingFilter==='全部'||this.verdictLabel(f.state)===this.findingFilter)},
get filteredAssets(){const q=this.assetSearch.trim().toLowerCase();return this.current.assets.filter(a=>(a.name+' '+a.detail).toLowerCase().includes(q))},
get statusTitle(){return ({paused:'研究已暂停',pausing:'正在保存检查点',done:'本轮研究已收束'})[this.current.status]||(this.current.stage===2?'正在沿着证据深入验证':this.current.stage===1?'正在建立值得验证的线索':'已建立研究，准备理解目标')},
get statusDescription(){if(this.current.status==='paused')return '现有证据保留，继续研究无需再次授权。';if(this.current.status==='pausing')return '演示状态切换：等待当前步骤结束。';if(this.current.status==='done')return '已知结论与尚未覆盖的方向分别保留。';return this.current.id.startsWith('new-')?'仅演示前端状态，尚未连接真实研究执行器。':'围绕对象归属核对代码与行为，不重复已经证伪的方向。'},
icon(name){return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(ICONS[name]||ICONS.info)+'</svg>'},
modeLabel(mode){return ({combined:'黑白盒联动',code:'代码审计',web:'黑盒研究'})[mode]},
verdictLabel(state){return ({confirmed:'已证实',pending:'待验证',rejected:'已排除'})[state]||'暂无法判断'},
statusLabel(status){return ({running:'研究中',paused:'已暂停',pausing:'正在暂停',done:'已结束'})[status]||'待开始'},
notify(message){this.toast=message;clearTimeout(this.toastTimer);this.toastTimer=setTimeout(()=>this.toast='',3600)},
now(){return new Date().toLocaleTimeString('zh-CN',{hour12:false})},
addEvent(project,event){project.events.push({id:'evt-'+Date.now()+'-'+Math.random().toString(36).slice(2),time:this.now(),...event})},
selectProject(id){this.selectedId=id;this.view='research';this.selectedFindingId=this.current.findings[0]?.id||null;this.evidenceTab='overview';this.evidenceOpen=false;this.menuOpen=false;this.findingFilter='全部';this.assetSearch='';this.hint=''},
selectFinding(id,tab='overview'){const finding=this.current.findings.find(f=>f.id===id);if(!finding)return;this.selectedFindingId=id;this.evidenceTab=(tab==='code'&&!finding.code||tab==='http'&&!finding.request)?'overview':tab;this.evidenceOpen=window.matchMedia('(max-width:1020px)').matches},
openAsset(asset){if(asset.finding)this.selectFinding(asset.finding,asset.tab||'overview');else {this.openScope();}},
openCreate(){this.formError='';this.draft={title:'',objective:'',url:'',repo:'',authorized:false,minutes:45,requests:300};this.menuOpen=false;document.getElementById('create-dialog').showModal()},
openScope(){document.getElementById('scope-dialog').showModal()},
openReport(){document.getElementById('report-dialog').showModal()},
closeDialog(id){document.getElementById(id).close()},
closeLayers(){this.menuOpen=false;this.evidenceOpen=false;document.querySelectorAll('dialog[open]').forEach(d=>d.close())},
createProject(){
 const d=this.draft;const title=d.title.trim(),objective=d.objective.trim(),url=d.url.trim(),repo=d.repo.trim();
 if(!title||!objective||(!url&&!repo)||!d.authorized){this.formError='请填写研究名称、目标、至少一项材料，并确认授权。';return;}
 if(url){try{const u=new URL(url.includes('://')?url:'http://'+url);if(!['http:','https:'].includes(u.protocol)||!u.hostname||u.username||u.password)throw Error();}catch{this.formError='请填写有效的网站地址，不要在地址中包含账号或密码。';return;}}
 if(!Number.isFinite(d.minutes)||d.minutes<5||d.minutes>240||!Number.isFinite(d.requests)||d.requests<10||d.requests>10000){this.formError='请填写有效的运行边界。';return;}
 const id='new-'+Date.now(),mode=url&&repo?'combined':repo?'code':'web';
 this.projects.push({id,title,objective,url,repo,mode,stack:'',status:'running',stage:0,minutes:d.minutes,requests:d.requests,findings:[],events:[],assets:[...(url?[{name:url,detail:'用户提供 · 演示输入，未访问',type:'web',label:'网站'}]:[]),...(repo?[{name:repo,detail:'用户提供 · 尚未识别语言或框架',type:'code',label:'源码'}]:[])],next:'正式接入后，先识别目标与材料，再生成有依据的研究计划。'});
 this.selectProject(id);this.addEvent(this.current,{kind:'complete',title:'项目授权与研究材料已记录',description:'演示已接收目标与边界。没有访问网站、读取代码、调用模型或创建后端任务。'});
 this.closeDialog('create-dialog');this.notify('研究已创建 · 当前为交互演示');
},
togglePause(){
 const p=this.current,epoch=this.epoch;
 if(p.status==='running'){p.status='pausing';setTimeout(()=>{if(epoch!==this.epoch||p.status!=='pausing')return;p.status='paused';this.addEvent(p,{kind:'hint',title:'已暂停研究（演示）',description:'检查点与授权保留。恢复时继续使用同一范围和预算。'});},500)}
 else if(p.status==='paused'||p.status==='done'){p.status='running';if(p.stage===3)p.stage=2;this.addEvent(p,{kind:'active',title:'继续研究（演示）',description:'沿用现有授权，从已保存的研究方向继续。'});this.notify('已继续，无需再次授权');}
},
sendHint(){const text=this.hint.trim();if(!text)return;const p=this.current;this.addEvent(p,{kind:'hint',title:'你补充了研究方向',description:text});p.next=text;this.hint='';this.notify(p.status==='running'?'方向已加入，下一步处理（演示）':'方向已保存，继续研究后处理（演示）');},
advanceDemo(){
 const p=this.current;if(p.status!=='running'||p.stage===3)return;
 if(p.id.startsWith('new-')){p.stage=Math.min(3,p.stage+1);this.addEvent(p,{kind:'active',title:'演示路线已推进',description:'此处将展示真实执行器返回的行动与证据。原型不生成或推断该目标的真实发现。'});if(p.stage===3)p.status='done';return;}
 p.stage=3;p.status='done';this.addEvent(p,{kind:'complete',title:'整理已证实、待验证与已排除的结果',description:'保留每条结论的证据和限制。没有用执行完成率代表目标安全。',finding:p.findings[0]?.id,linkLabel:'回看主要依据'});this.notify('演示已收束，可以查看研究报告');
},
finishDemo(){const p=this.current;p.status='done';p.stage=3;this.addEvent(p,{kind:'complete',title:'本轮研究结束（演示）',description:'保留当前结论与未覆盖方向；报告可导出。'});this.notify('本轮演示研究已结束');},
retest(){
 if(this.retesting||!this.selectedFinding)return;const p=this.current,f=this.selectedFinding,epoch=this.epoch;this.retesting=true;
 this.notify('正在播放复测过程，没有发送实际请求');
 setTimeout(()=>{this.retesting=false;if(epoch!==this.epoch)return;this.addEvent(p,{kind:f.state==='confirmed'?'complete':'warning',title:'复测演示已记录',description:f.state==='confirmed'?'固定演示样本保持相同结果。正式版本会保存新的运行与对照证据。':'当前证据不足以完成动态复测，结论保持不变。',finding:f.id,linkLabel:'查看原始依据'});this.notify('演示复测结束，已加入研究记录');},850);
},
exportReport(single=false){
 const p=this.current,findings=single&&this.selectedFinding?[this.selectedFinding]:p.findings;
 let md='# '+p.title+(single?' · 发现':' · 研究报告')+'\n\n> 交互原型：所有运行、源码与请求证据均为虚构演示；不代表真实测试结果。\n\n## 研究目标\n\n'+p.objective+'\n\n## 研究材料\n\n'+[p.url,p.repo].filter(Boolean).map(x=>'- '+x).join('\n')+'\n\n';
 for(const f of findings){md+='## '+f.id+' '+f.title+'\n\n状态：'+this.verdictLabel(f.state)+' / '+f.basis+'\n\n'+f.summary+'\n\n### 证据\n\n'+f.evidence.map(e=>'- '+e.id+' '+e.title+' — '+e.text).join('\n')+'\n\n';if(f.code)md+='源码：'+f.file+' @ '+f.commit+'\n\n~~~\n'+f.code.map(l=>l.n+' '+l.text).join('\n')+'\n~~~\n\n';if(f.request)md+='### 请求对照（虚构）\n\n~~~http\n'+f.request.baseline+'\n~~~\n\n~~~http\n'+f.request.variant+'\n~~~\n\n';md+='### 影响与限制\n\n'+f.impact+'\n\n'+f.gap+'\n\n';}
 if(!findings.length)md+='尚未形成发现。\n\n';md+='## 尚未覆盖与下一步\n\n'+p.next+'\n';
 const blob=new Blob([md],{type:'text/markdown;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='cairn-'+p.title.replace(/[^\p{L}\p{N}_-]/gu,'_')+(single?'-finding':'-report')+'.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);this.notify('已导出演示 Markdown，包含证据与限制说明');
},
resetDemo(){this.epoch++;this.retesting=false;this.projects=fixtures();this.selectProject('atlas');this.closeLayers();this.notify('已恢复演示项目；临时输入已清空');}
}));
});
