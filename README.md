# Cross-Gate Injection in Typed Decision Agents

Research artifact for *From Answer Changes to Action Hijacks: Cross-Gate Injection and the Hijack Ladder in Typed Decision Agents*.

The paper is in [`paper/paper.pdf`](paper/paper.pdf). Source is [`paper/paper.tex`](paper/paper.tex).

## What is included

- `experiments/system1_agent_injection`: the multi-gate customer-service agent, the injection protocol, the offline tests, and the completed hosted Jev run.
- `experiments/four_workflow_attack`: local harnesses for customer service, security incidents, invoice processing, and agent-trace observability, plus the first-gate hosted smoke.
- `paper/`: the manuscript, bibliography, artifact note, and the paper-level audit file.

Hosted calls use `OPENROUTER_API_KEY` from the environment. The repository does not contain credentials.

## Reproduce the offline checks

```bash
cd experiments/system1_agent_injection
python -m unittest discover -s . -p 'test_*.py' -v
```

```bash
cd experiments/four_workflow_attack
python -m unittest -v test_all
```

All terminal actions are local simulation records. The harnesses do not issue refunds, payments, account changes, or external messages.
