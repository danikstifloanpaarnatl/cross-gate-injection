# Four official TypeSafe workflow harnesses

This directory implements local, minimal research harnesses derived from the four public TypeSafe workflow envelopes. It does not claim to reproduce TypeSafe production code. Every undocumented attacker permission is marked as a research assumption and must be confirmed before being called an indirect injection result.

- `customer_system.py`: Customer Service inputs/actions; direct attack changes conversation text.
- `security_system.py`: Security Incidents initial/act graph and playbook.
- `invoice_system.py`: Invoice Processing document, termination, parallel-check and payment graph.
- `trace_system.py`: Agent Trace Observability post-hoc audit graph.
- `evaluator.py`: deterministic grounded/vulnerable adapters and the full offline matrix.
- `test_all.py`: regression tests for gold alignment, state isolation, graph hashes and guards.
- `live_smoke.py`: bounded hosted first-gate smoke; it does not claim end-to-end ASR.

Run the offline evidence suite from the project root:

```bash
PYTHONPATH=. python -m unittest -v experiments.four_workflow_attack_20260929.test_all
PYTHONPATH=. python -m experiments.four_workflow_attack_20260929.evaluator
```

All actions are `local_simulation_only`; no harness performs a real refund, payment, account disablement, process kill or on-call page.
