from __future__ import annotations

import json
import random

from cairn.dispatcher.config import WorkerConfig, resolve_mock_behavior
from cairn.dispatcher.workers.base import DriverResult, SeedSessionDriver
from cairn.dispatcher.workers.health import HealthResult

_SCRIPT = """
import json,random,sys,time

try:
    cfg=json.loads(sys.argv[1])
    prompt=json.loads(sys.argv[2])
    phase=prompt["phase"]
    phase_cfg=cfg[phase]
except Exception as exc:
    print(f"mock setup failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
delay=phase_cfg["delay"]
time.sleep(random.uniform(delay["min"],delay["max"]))

weights=dict(phase_cfg["outcomes"])
if phase=="reason":
    if not prompt.get("open_intents"):
        weights.pop("noop",None)
    if not prompt.get("fact_ids"):
        weights.pop("complete",None)
        weights.pop("intent",None)
if phase=="vulnerability_reason":
    observations=(prompt.get("analysis_context") or {}).get("observations") or []
    if not observations:
        weights.pop("intent",None)
choices=[(name,weight) for name,weight in weights.items() if weight>0]
if not choices:
    print(f"mock {phase} has no legal outcomes for prompt context", file=sys.stderr)
    raise SystemExit(2)

def _rule_matches(rule, prompt):
    fact_ids = prompt.get("fact_ids") or []
    open_intents = prompt.get("open_intents") or []
    if "fact_ids_gte" in rule and len(fact_ids) < rule["fact_ids_gte"]:
        return False
    if "fact_ids_lte" in rule and len(fact_ids) > rule["fact_ids_lte"]:
        return False
    if "open_intents_empty" in rule and (len(open_intents) == 0) != rule["open_intents_empty"]:
        return False
    return True

rules = phase_cfg.get("rules") or []
forced = None
for rule in rules:
    if _rule_matches(rule, prompt):
        forced = rule["force"]
        break

if forced is not None:
    outcome = forced
else:
    pick=random.uniform(0,sum(weight for _,weight in choices))
    total=0
    outcome=choices[-1][0]
    for name,weight in choices:
        total+=weight
        if pick<=total:
            outcome=name
            break

if phase=="healthcheck":
    raise SystemExit(0 if outcome=="ok" else 1)
if outcome=="command_fail":
    print(f"mock {phase} command failed", file=sys.stderr)
    raise SystemExit(1)
if outcome=="invalid_json":
    print("{invalid json")
    raise SystemExit(0)
if phase=="reason":
    fact_ids=prompt.get("fact_ids") or []
    max_i=prompt.get("max_intents",3)
    from_ids=[random.choice(fact_ids)] if fact_ids else []
    if outcome=="complete":
        print(json.dumps({"accepted":True,"data":{"complete":{"from":from_ids,"description":f"mock complete from {from_ids[0]}"}}}, ensure_ascii=False))
    elif outcome=="intent":
        count=random.randint(1,max(1,max_i))
        intents=[]
        for idx in range(count):
            fi=[random.choice(fact_ids)] if fact_ids else []
            intents.append({"from":fi,"description":f"mock intent {idx+1} from {fi[0] if fi else 'none'}"})
        print(json.dumps({"accepted":True,"data":{"intents":intents}}, ensure_ascii=False))
    elif outcome=="noop":
        print(json.dumps({"accepted":True,"data":{}}, ensure_ascii=False))
    elif outcome=="rejected":
        print(json.dumps({"accepted":False,"reason":"mock_rejected"}, ensure_ascii=False))
    else:
        print(json.dumps({"accepted":True,"data":{"complete":{"description":"mock invalid payload"}}}, ensure_ascii=False))
    raise SystemExit(0)

if phase=="vulnerability_reason":
    observations=(prompt.get("analysis_context") or {}).get("observations") or []
    observation_ids=[item["id"] for item in observations if isinstance(item,dict) and item.get("id")]
    if outcome=="intent" and observation_ids:
        budget=min(10,int(prompt.get("max_budget_units",10)))
        draft={"analysis_type":"comprehensive","observation_ids":observation_ids[:10],"budget_units":budget}
        description="CAIRN_VULNERABILITY_ANALYSIS_V1\\n"+json.dumps(draft,separators=(",",":"))
        from_ids=(prompt.get("fact_ids") or ["origin"])[:1]
        print(json.dumps({"accepted":True,"data":{"intents":[{"from":from_ids,"description":description}]}},ensure_ascii=False))
    elif outcome=="noop":
        print(json.dumps({"accepted":True,"data":{}},ensure_ascii=False))
    elif outcome=="rejected":
        print(json.dumps({"accepted":False,"reason":"mock_rejected"},ensure_ascii=False))
    else:
        print(json.dumps({"accepted":True,"data":{"intents":[{"from":[],"description":"invalid"}]}},ensure_ascii=False))
    raise SystemExit(0)

if phase=="vulnerability_analysis":
    observations=prompt.get("observations") or []
    first=observations[0] if observations else {}
    asset_ref=first.get("asset_id")
    evidence=[first.get("id")] if first.get("id") else []
    if outcome=="result":
        hypotheses=[]
        gaps=[]
        if asset_ref:
            hypotheses=[{"asset_ref":asset_ref,"vuln_id":None,"title":"Mock vulnerability hypothesis","description":"Structured offline inference for pipeline verification","confidence":0.6,"evidence_refs":evidence}]
            gaps=[{"asset_ref":asset_ref,"dimension":"external","reason":"Mock coverage gap"}]
        data={"summary":"Mock offline vulnerability analysis completed","extracted_entities":[],"inferred_relations":[],"coverage_gaps":gaps,"hypotheses":hypotheses}
        print(json.dumps({"accepted":True,"data":data},ensure_ascii=False))
    elif outcome=="rejected":
        print(json.dumps({"accepted":False,"reason":"mock_rejected"},ensure_ascii=False))
    elif outcome=="invalid_payload":
        print(json.dumps({"accepted":True,"data":{}},ensure_ascii=False))
    raise SystemExit(0)

if phase=="bootstrap":
    if outcome=="complete":
        print(json.dumps({"accepted":True,"data":{"fact":{"description":"mock fact for bootstrap"},"complete":{"description":"mock bootstrap complete from fact"}}}, ensure_ascii=False))
    elif outcome=="fact":
        print(json.dumps({"accepted":True,"data":{"fact":{"description":"mock fact-only bootstrap result"}}}, ensure_ascii=False))
    elif outcome=="rejected":
        print(json.dumps({"accepted":False,"reason":"mock_rejected"}, ensure_ascii=False))
    else:
        print(json.dumps({"accepted":True,"data":{"fact":{"description":"mock invalid payload"}}}, ensure_ascii=False))
    raise SystemExit(0)

if phase=="bootstrap_conclude":
    if outcome=="fact":
        print(json.dumps({"accepted":True,"data":{"fact":{"description":"mock fact for bootstrap_conclude"}}}, ensure_ascii=False))
    elif outcome=="rejected":
        print(json.dumps({"accepted":False,"reason":"mock_rejected"}, ensure_ascii=False))
    else:
        print(json.dumps({"accepted":True,"data":{"complete":{"description":"mock invalid payload"}}}, ensure_ascii=False))
    raise SystemExit(0)

if outcome=="fact":
    label = prompt.get("intent_id") or phase
    print(json.dumps({"accepted":True,"data":{"description":f"mock fact for {label}"}} , ensure_ascii=False))
elif outcome=="rejected":
    print(json.dumps({"accepted":False,"reason":"mock_rejected"}, ensure_ascii=False))
else:
    print(json.dumps({"accepted":True,"data":{}}, ensure_ascii=False))
""".strip()


class MockDriver(SeedSessionDriver):
    type_name = "mock"

    def local_binary(self) -> str | None:
        return "python3"

    def supports_hard_cost_budget(self) -> bool:
        return True

    def supports_hard_token_budget(self) -> bool:
        return True

    @staticmethod
    def _argv(worker: WorkerConfig, prompt: str) -> list[str]:
        behavior = resolve_mock_behavior(worker.name, worker.env)
        return ["python3", "-c", _SCRIPT, json.dumps(behavior, ensure_ascii=False), prompt]

    def check_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        outcomes = resolve_mock_behavior(worker.name, worker.env)["healthcheck"]["outcomes"]
        ok = random.random() < outcomes.get("ok", 0.0)
        return HealthResult(ok=ok, status=200 if ok else 503, detail="" if ok else "mock healthcheck fail")

    def describe_health(self, worker: WorkerConfig) -> str:
        return "mock in-process healthcheck"

    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        return DriverResult(argv=self._argv(worker, prompt), session=session)

    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        return self._argv(worker, prompt)

    def build_analysis(self, worker: WorkerConfig, prompt: str) -> DriverResult:
        return DriverResult(argv=self._argv(worker, prompt), session=None)
