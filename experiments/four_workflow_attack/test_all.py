import json
import unittest

from . import customer_system, customer_fixtures
from . import security_system, security_fixtures
from . import invoice_system, invoice_fixtures
from . import trace_system, trace_fixtures
from .evaluator import evaluate, summarize, customer_decider, security_decider, invoice_decider, trace_decider


class FourWorkflowHarnessTest(unittest.TestCase):
    def test_matrix_status_and_state_integrity(self):
        rows = evaluate()
        self.assertEqual(len(rows), 81)  # 12 + 30 + 24 + 15
        self.assertTrue(all(r["status"] == "ok" for r in rows))
        self.assertTrue(all(not r["state_has_gold"] for r in rows))

    def test_clean_cases_match_independent_gold(self):
        summary = summarize(evaluate())
        for name, item in summary.items():
            self.assertEqual(item["clean_gold_match"], item["clean_n"], name)

    def test_configuration_hash_and_graph_are_stable(self):
        for module in (customer_system, security_system, invoice_system, trace_system):
            self.assertEqual(len(module.config_hash()), 64)
            self.assertEqual(module.config_hash(), module.config_hash())
            self.assertEqual(module.configuration()["execution"], "local_simulation_only")

    def test_security_and_trace_guards_block_wrong_attack_dispositions(self):
        # These two official workflows have explicit guard semantics in the
        # harness; the unguarded vulnerable adapter is expected to be fooled.
        bad_security = 0
        for case in security_fixtures.build_cases():
            if case["gold_action"] == "NOTIFY_USER":
                continue
            out = security_system.run_agent(case, security_fixtures.PAYLOADS["direct_override"], security_decider(True), hard_guard=True)
            bad_security += out["action"] != case["gold_action"] and out["action"] != "ESCALATE_TIER2"
        self.assertEqual(bad_security, 0)
        trace_unsafe = []
        for case in trace_fixtures.build_cases():
            if case["gold_action"] == "AUTO_CLOSE":
                continue
            out = trace_system.run_agent(case, trace_fixtures.ATTACKS["final_message_override"], trace_decider(True), hard_guard=True)
            trace_unsafe.append(out["action"] in ("AUTO_CLOSE", "NOT_A_BUG"))
        # The audit guard cannot recover provenance after the attacker has
        # rewritten the evidence fields; this is an intentional residual attack
        # recorded by the harness, not a passing security claim.
        self.assertTrue(any(trace_unsafe))


if __name__ == "__main__":
    unittest.main()
