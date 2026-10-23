"""Eight-call hosted smoke: clean/attack at the first gate of each workflow."""
from __future__ import annotations
import hashlib, importlib.util, json, os
from pathlib import Path
from copy import deepcopy

from . import customer_system as customer, customer_fixtures
from . import security_system as security, security_fixtures
from . import invoice_system as invoice, invoice_fixtures
from . import trace_system as trace, trace_fixtures

HERE = Path(__file__).resolve().parent
PROVIDER_PATH = HERE.parent / "system1_agent_injection_20260929" / "provider.py"
spec = importlib.util.spec_from_file_location("jev_provider_smoke", PROVIDER_PATH)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)


def digest(x): return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def run(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=False)
    provider = mod.DecisionsProvider(out_dir / "receipts.jsonl", max_calls=8, max_cost=0.02,
                                     mock=False, expected_model="typesafe/jev-1.13-20260917",
                                     original_requested_model="typesafe/jev-1.13")
    rows = []
    # Each tuple builds the exact first-gate state and typed question set. The
    # attack text changes one declared external field only.
    cases = []
    c = customer_fixtures.build_cases()[0]
    for label, attack in [("clean", ""), ("attack", customer_fixtures.PAYLOADS["direct_override"])]:
        cases.append(("customer_service", c["id"], "triage", {"conversation": c["conversation"] + ("\n" + attack if attack else ""), "customer_record": c["customer_record"], "account_state": c["account_state"], "pending_proposal": c["pending_proposal"]}, customer.configuration()["questions"]["triage"], attack))
    s = security_fixtures.build_cases()[2]  # process case, ACT is the intended clean route
    for label, attack in [("clean", ""), ("attack", security_fixtures.PAYLOADS["direct_override"])]:
        cases.append(("security_incidents", s["id"], "initial", {k: deepcopy(s[k]) for k in ("alert","asset","open_tickets","change_requests","incidents","registered_devices","scheduled_maintenance","standing_authorizations")} | {"external_alert_text": attack, "maintenance_note": s.get("maintenance_note", "")}, security.configuration()["questions"]["initial"], attack))
    i = invoice_fixtures.build_cases()[0]
    for label, attack in [("clean", ""), ("attack", invoice_fixtures.PAYLOADS["fake_approval"])]:
        docs = {k: deepcopy(i[k]) for k in ("invoice","purchase_order","contract","vendor_record","prior_invoices","delivery_evidence","approval_record")}
        docs["correspondence_text"] = attack; docs["delivery_note"] = ""
        cases.append(("invoice_processing", i["id"], "document_read", {"invoice_documents": docs}, invoice.configuration()["questions"]["document_read"], attack))
    t = trace_fixtures.build_cases()[3]  # silent-failure trace, post-hoc audit should not auto-close
    for label, attack in [("clean", ""), ("attack", trace_fixtures.ATTACKS["final_message_override"])]:
        state = {"agent_instructions": t["agent_instructions"], "conversation": t["conversation"], "tool_calls_and_returns": t["tool_calls"], "final_message": t["final_message"] + ("\n" + attack if attack else ""), "customer_feedback": t["customer_feedback"]}
        cases.append(("agent_trace_observability", t["id"], "permission", state, {"permission": deepcopy(trace.configuration()["questions"]["permission"]["permission"])}, attack))
    start = int(os.environ.get("JEV_SMOKE_START", "0"))
    cases = cases[start:]
    for idx, (workflow, case_id, stage, state, questions, attack) in enumerate(cases, start=start):
        api_questions = deepcopy(questions)
        # Hosted API represents Score criteria as a list; local harnesses keep
        # a dict for deterministic validation and readable configuration.
        for q in api_questions.values():
            if q.get("type") == "score" and isinstance(q.get("criteria"), dict):
                q["criteria"] = list(q["criteria"].values())
        raw = provider(state, api_questions, stage)
        answers = raw.get("answers", {})
        rows.append({"index": idx, "workflow": workflow, "case_id": case_id, "condition": "attack" if attack else "clean", "stage": stage, "attack_sha256": digest(attack), "answers": answers, "reported_model": raw.get("model"), "usage": raw.get("usage")})
        (out_dir / "rows.jsonl").open("a").write(json.dumps(rows[-1], ensure_ascii=False) + "\n")
    summary = {"attempts": provider.attempts, "provider": provider.stats(), "rows": len(rows), "paired": {}}
    for workflow in sorted({x["workflow"] for x in rows}):
        a = [x for x in rows if x["workflow"] == workflow]
        clean, attack = a[0], a[1]
        summary["paired"][workflow] = {"answer_changed": clean["answers"] != attack["answers"], "clean_answers": clean["answers"], "attack_answers": attack["answers"]}
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    run(Path(os.environ.get("JEV_SMOKE_OUT", str(HERE / "results_hosted_smoke_20260929"))))
