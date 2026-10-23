#!/usr/bin/env python3
"""Continue only unfinished test trials, preserving frozen sources and successful rows."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from agent import run_agent
from fixtures import build_cases, build_payloads
from provider import DecisionsProvider, ProviderError
from run import identity, save, summarize, write_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-base", required=True, type=Path)
    parser.add_argument("--out-base", required=True, type=Path)
    parser.add_argument("--max-calls", type=int, default=95)
    parser.add_argument("--max-cost", type=float, default=0.1992)
    args = parser.parse_args()
    if not 1 <= args.max_calls <= 95 or not 0 < args.max_cost <= 0.1992:
        parser.error("Recovery cap: at most 95 calls and 0.1992 USD known cost")
    parent = args.source_base / "test"
    output = args.out_base / "test"
    if args.out_base.exists() and any(args.out_base.iterdir()):
        parser.error("Output base must be empty; existing evidence cannot be overwritten")
    selection_bytes = (args.source_base / "selection.json").read_bytes()
    selection = json.loads(selection_bytes)
    manifest = json.loads((parent / "manifest.json").read_text())
    frozen = identity()
    if selection["identity"] != frozen or manifest["identity"] != frozen or selection["mock"] or manifest["mock"]:
        parser.error("Frozen source identity or live mode mismatch")
    payloads = build_payloads()
    chosen = selection["chosen_payload_name"]
    if payloads[chosen] != selection["text"] or hashlib.sha256(payloads[chosen].encode()).hexdigest() != selection["sha256"]:
        parser.error("Frozen payload mismatch")
    planned = manifest["planned"]
    planned_keys = [(r["case_id"], r["payload_name"]) for r in planned]
    if len(planned_keys) != len(set(planned_keys)):
        parser.error("Duplicate planned trials")
    cases = {case["id"]: case for case in build_cases()}
    prior_bytes = (parent / "rows.jsonl").read_bytes()
    parent_rows = [json.loads(line) for line in prior_bytes.splitlines()]
    reused = {}
    for row in parent_rows:
        key = (row["case_id"], row["payload_name"])
        if key not in planned_keys:
            parser.error("Parent trial outside frozen plan")
        if row["trace"]["status"] == "ok":
            if key in reused:
                parser.error("Repeated successful parent trial")
            if row["payload_sha256"] != hashlib.sha256(payloads[key[1]].encode()).hexdigest():
                parser.error("Parent payload mismatch")
            if row["trace"]["configuration_hash"] != frozen["config_hash"]:
                parser.error("Parent configuration mismatch")
            for stage in row["trace"]["stages"]:
                if stage["response"].get("model") != selection["reported_model"]:
                    parser.error("Parent reported model mismatch")
            reused[key] = row
    output.mkdir(parents=True)
    (args.out_base / "selection.json").write_bytes(selection_bytes)
    recovery = dict(manifest)
    recovery.update(recovery_runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        recovery_parent=str(parent.resolve()), parent_rows_sha256=hashlib.sha256(prior_bytes).hexdigest(),
        reused_successes=len(reused), parent_failures=[r for r in parent_rows if r["trace"]["status"] != "ok"],
        max_calls=args.max_calls, max_cost_usd=args.max_cost,
        transport_retry_policy="At most two extra provider invocations for URLError/TimeoutError only; sleeps 1 and 2 seconds; provider attempt cap applies")
    save(output / "manifest.json", recovery)
    rows = [reused[key] for key in planned_keys if key in reused]
    with (output / "rows.jsonl").open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    provider = None
    try:
        provider = DecisionsProvider(output / "receipts.jsonl", max_calls=args.max_calls,
            max_cost=args.max_cost, expected_model=selection["reported_model"],
            original_requested_model=selection["original_requested_model"])

        def decide(state, questions, stage):
            for retry in range(3):
                try:
                    return provider(state, questions, stage)
                except ProviderError as error:
                    # Exception text from the bounded provider is a sanitized type/status only.
                    if str(error) not in ("URLError", "TimeoutError") or retry == 2:
                        raise
                    with (output / "retry_events.jsonl").open("a") as handle:
                        handle.write(json.dumps({"stage": stage, "error": str(error),
                            "extra_attempt": retry + 1, "sleep_seconds": retry + 1}) + "\n")
                    time.sleep(retry + 1)

        for key in planned_keys:
            if key in reused:
                continue
            case_id, name = key
            case = cases[case_id]
            trace = run_agent(case, payloads[name], decide)
            row = dict(case_id=case_id, split=case["split"], family=case["family"],
                gold_action=case["gold_action"], accepted_actions=case.get("accepted_actions", [case["gold_action"]]),
                target_action=case["target_action"], oracle_rationale=case["oracle_rationale"],
                payload_name=name, payload_sha256=hashlib.sha256(payloads[name].encode()).hexdigest(), trace=trace)
            rows.append(row)
            with (output / "rows.jsonl").open("a") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            save(output / "provider_stats.json", provider.stats())
            if trace["status"] != "ok":
                save(output / "stopped.json", {"reason": "RecoveryTrialError", "case_id": case_id, "payload_name": name})
                raise ProviderError("RecoveryTrialErrorSeeReceipts")
    except ProviderError as error:
        save(output / "blocked.json", {"reason": str(error), "reused_successes": len(reused)})
        raise
    finally:
        summary = summarize(rows, False, planned)
        summary["recovery"] = {"reused_successes": len(reused), "new_trials": len(rows) - len(reused),
            "parent_failed_trials": len(recovery["parent_failures"]), "parent": str(parent.resolve())}
        write_report(output, summary)
        if provider is not None:
            save(output / "provider_stats.json", provider.stats())
    print(json.dumps({"out": str(output), "reused_successes": len(reused),
        "new_trials": len(rows) - len(reused), "provider": provider.stats()}))


if __name__ == "__main__":
    try:
        main()
    except ProviderError as error:
        raise SystemExit(str(error)) from None
