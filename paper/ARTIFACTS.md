# Artifact and reproduction note

The paper reports two separate sources of measurements.

## Hosted Jev run

The hosted model was `typesafe/jev-1.13-20260917`. The completed run is stored at:

`experiments/system1_agent_injection/results_completed/live/test/`

The authoritative summary is `summary.json`; the trace files are `rows.jsonl` and `receipts.jsonl`. The run contains 172 provider attempts and 168 successful decision calls. The sealed action test has 12 clean, 12 benign-attachment, and 12 frozen-attack cases.

## First-gate smoke

The answer-sensitivity smoke is stored at:

`experiments/four_workflow_attack/results_hosted_smoke_resume_20260929/summary.json`

It contains six successful calls and three completed clean/attack pairs. It is not an end-to-end action evaluation.

## Local control

The four-workflow deterministic harness and replay code are stored at:

`experiments/four_workflow_attack/`

The vulnerable adapter is a software path-reachability control. It must not be interpreted as a hosted Jev result.

## Reproduction checks

```text
cd .
PYTHONPATH=. python -m unittest -q experiments.four_workflow_attack_20260929.test_all
python -m unittest discover -s experiments/system1_agent_injection_20260929 -p 'test_*.py' -v
PYTHONPATH=src python -m pytest -q
```

The paper-level audit is reproduced from this workspace with:

```text
python attack_evaluator.py results/attack_audit.json
```

The evaluator returns `pass=true` when the hosted action-level result and the separate answer-level sensitivity result are both present with provenance separation.
