"""Bounded Decisions API client; receipts never contain authorization headers."""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

URL = "https://openrouter.ai/api/alpha/decisions"


class ProviderError(RuntimeError):
    pass


class DecisionsProvider:
    def __init__(self, receipts_path, max_calls=250, max_cost=0.5, mock=False, expected_model=None, original_requested_model=None):
        self.receipts_path = Path(receipts_path)
        self.receipts_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_calls, self.max_cost, self.mock = max_calls, max_cost, mock
        self.model = os.environ.get("JEV_MODEL", "~typesafe/jev-latest")
        if original_requested_model is not None and self.model != original_requested_model:
            raise ProviderError("RequestedModelDrift")
        self.original_requested_model = self.model
        self.reported_model = expected_model
        if expected_model and "/" in expected_model and not expected_model.startswith("~"):
            self.model = expected_model
        self.attempts = self.successes = self.missing_cost = 0
        self.cost = self.latency = 0.0
        self.key = None if mock else os.environ.get("OPENROUTER_API_KEY")
        if not mock and not self.key:
            raise ProviderError("MissingEnvironmentCredential")

    def stats(self):
        return dict(attempts=self.attempts, successes=self.successes,
                    known_cost_usd=self.cost, missing_cost_responses=self.missing_cost,
                    latency_seconds=self.latency, reported_model=self.reported_model,
                    requested_model=self.model, original_requested_model=self.original_requested_model, mock=self.mock)

    def _record(self, record):
        encoded = json.dumps(record, ensure_ascii=False)
        if self.key:
            encoded = encoded.replace(self.key, "[REDACTED]")
        with self.receipts_path.open("a") as handle:
            handle.write(encoded + "\n")

    def __call__(self, state, questions, stage):
        for retry in range(2):
            if self.attempts >= self.max_calls or self.cost >= self.max_cost:
                self._record({"stage": stage, "status": "error", "error": "BudgetExhausted", "mock": self.mock})
                raise ProviderError("BudgetExhausted")
            payload = dict(model=self.model, state=state, questions=questions)
            self.attempts += 1
            started = time.monotonic()
            record = dict(attempt=self.attempts, stage=stage, request=payload, mock=self.mock)
            retryable = False
            try:
                if self.mock:
                    # Smoke-only heuristic reads the immutable message, never labels or attachment.
                    message = state.get("customer_message", "").lower()
                    human = any(word in message for word in ("human", "a person", "representative", "staff member"))
                    security = any(word in message for word in ("unauthorized", "without my", "never authorized", "never permitted", "did not authorize"))
                    closed = "close" in message and any(word in message for word in ("resolved", "fixed", "now works"))
                    intent = ("billing" if any(word in message for word in ("invoice", "bill", "charge", "receipt", "renewal", "paid")) else
                              "account" if any(word in message for word in ("profile", "account", "password", "login")) else "technical")
                    answers = {}
                    for name, question in questions.items():
                        kind = question["type"].lower()
                        if kind == "noul":
                            value = {"requests_human": human, "security_issue": security,
                                     "issue_resolved": closed, "closure_requested": closed,
                                     "action_supported": not human and not security}.get(name, False)
                            answers[name] = {"type": kind, "noul": 0.99 if value else 0.01}
                        elif kind == "score":
                            answers[name] = {"type": kind, "score": 0.0}
                        elif kind == "choice":
                            choices = list(question["criteria"])
                            choice = intent if intent in choices else choices[0]
                            answers[name] = {"type": kind, "choice": choice, "confidence": 1.0,
                                             "probabilities": {c: float(c == choice) for c in choices}}
                        else:
                            raise ProviderError("UnknownQuestionType")
                    raw = {"answers": answers, "model": "mock/smoke-only", "usage": {"cost": 0}}
                else:
                    req = urllib.request.Request(URL, data=json.dumps(payload).encode(),
                        headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"},
                        method="POST")
                    with urllib.request.urlopen(req, timeout=30) as response:
                        raw = json.loads(response.read().decode())
                record["response"] = raw
                if not isinstance(raw, dict):
                    raise ProviderError("ResponseSchemaError")
                usage = raw.get("usage") or {}
                cost = usage.get("cost") if isinstance(usage, dict) else None
                if isinstance(cost, (int, float)) and not isinstance(cost, bool) and 0 <= cost < float("inf"):
                    self.cost += cost
                else:
                    self.missing_cost += 1
                if not isinstance(raw.get("answers"), dict) or set(questions) - set(raw["answers"]):
                    raise ProviderError("ResponseSchemaError")
                reported = raw.get("model")
                if not isinstance(reported, str) or not reported:
                    raise ProviderError("MissingReportedModel")
                if self.reported_model is not None and reported != self.reported_model:
                    raise ProviderError("ModelDrift")
                self.reported_model = reported
                if "/" in reported and not reported.startswith("~"):
                    self.model = reported
                self.successes += 1
                record["status"] = "ok"
                return raw
            except urllib.error.HTTPError as exc:
                record.update(status="error", error="HTTPError", http_status=exc.code)
                retryable = exc.code == 429 or 500 <= exc.code <= 599
                error = ProviderError("HTTPError:" + str(exc.code))
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                record.update(status="error", error=type(exc).__name__)
                retryable = isinstance(exc, (TimeoutError, socket.timeout)) or isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout))
                error = ProviderError(type(exc).__name__)
            except (ValueError, KeyError, TypeError, ProviderError) as exc:
                label = str(exc) if isinstance(exc, ProviderError) else type(exc).__name__
                record.update(status="error", error=label)
                error = ProviderError(label)
            finally:
                elapsed = time.monotonic() - started
                self.latency += elapsed
                record["latency_seconds"] = elapsed
                self._record(record)
            if not retryable or retry:
                raise error
            time.sleep(1)
