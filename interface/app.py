#!/usr/bin/env python3
"""COE444 Security Lab — Flask interface.

Run from the REPOSITORY ROOT, after sourcing scripts/activate.sh:

    source scripts/activate.sh
    python interface/app.py

Both of those matter. config.py calls a bare load_dotenv(), so .env is found
relative to the working directory; and .env points COE444_DATA_ROOT at an
external disk image that is usually not mounted, which activate.sh overrides
with the local .data path. Without it the first retrieval raises
"No FAISS index" even though a perfectly good index exists.

Scoring note: this UI does NOT reimplement the 2x2. When the run corresponds to
a corpus item it goes through evaluation.runner.Runner, exactly as
`python cli.py demo` does, and the A/B/C/D verdicts come from conditions.score().
A free-text run has no mechanical success predicate, so it reports the trace
(chunks, detector scores, gate decisions) and says the conditions are not
scoreable rather than inventing a verdict. See CLAUDE.md invariants 2 and 5.
"""

import logging
import os
import sys
import time
import traceback
from collections import deque
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder=str(Path(__file__).parent / "ui"))
app.config["JSON_SORT_KEYS"] = False

_log = logging.getLogger(__name__)

# ── Free-tier guard ──────────────────────────────────────────────────────────
# Every /api/run and /api/assistant spends real model quota, and a teammate
# clicking through the demo can burn a day's free-tier allowance in a few
# minutes without noticing. This counts model-calling requests handled by THIS
# process and tells the UI when to ease off.
#
# Advisory only — it never refuses a run. A demo that dies mid-presentation is
# worse than a spent quota, and a hard limit here would be trivially bypassed
# by restarting the server anyway. Shared keys are not aggregated: each
# teammate's server counts only its own calls.
_RUNS: deque[tuple[float, int]] = deque(maxlen=1000)
USAGE_WARN_RUNS = int(os.getenv("USAGE_WARN_RUNS", "8"))
USAGE_WINDOW_S = int(os.getenv("USAGE_WINDOW_S", "300"))


def _record_run(tokens: int) -> None:
    _RUNS.append((time.monotonic(), int(tokens or 0)))


def _usage() -> dict:
    now = time.monotonic()
    recent = [(t, n) for t, n in _RUNS if now - t <= USAGE_WINDOW_S]
    runs = len(recent)
    mins = max(1, USAGE_WINDOW_S // 60)
    warn = runs >= USAGE_WARN_RUNS
    if warn:
        msg = (
            f"{runs} model runs in the last {mins} minutes "
            f"({sum(n for _, n in recent):,} tokens). Every run spends shared "
            f"free-tier quota — pause between runs, or use the Details tab and "
            f"the saved logs instead of re-running."
        )
    else:
        msg = ""
    return {
        "runs_in_window": runs,
        "tokens_in_window": sum(n for _, n in recent),
        "runs_session": len(_RUNS),
        "tokens_session": sum(n for _, n in _RUNS),
        "window_minutes": mins,
        "warn_at": USAGE_WARN_RUNS,
        "warn": warn,
        "message": msg,
    }


def _with_usage(result: dict) -> dict:
    """Stamp a finished run with its cost and the running total."""
    _record_run(result.get("tokens") or 0)
    result["usage"] = _usage()
    return result


@app.route("/api/usage")
def api_usage():
    return jsonify(_usage())


# ── Lazy-load components (so the app starts even if a module is broken) ──────

_cache = {}


def get(name):
    return _cache.get(name)


def load_all():
    """Try to import every component. Returns dict of {name: error_string}.

    Each component is loaded independently so a missing ANTHROPIC_API_KEY —
    which only the agent and the detector need — still leaves the retriever and
    the gate reporting healthy.
    """
    errors = {}

    if "retriever" not in _cache:
        try:
            from rag.retriever import Retriever

            _cache["retriever"] = Retriever()
        except Exception as e:
            errors["retriever"] = str(e)

    if "agent" not in _cache:
        try:
            # Agent takes (provider, retriever, mail) — all three required.
            # Built the same way cli.py:36 and runner.py:61 build it.
            from agent.agent import Agent
            from agent.llm import get_provider
            from config import AGENT_MODEL, AGENT_PROVIDER
            from mailsink import MailSink

            retriever = _cache.get("retriever")
            if retriever is None:
                raise RuntimeError("retriever failed to load; agent needs it")
            mail = MailSink()
            _cache["mail"] = mail
            _cache["agent"] = Agent(get_provider(AGENT_PROVIDER, AGENT_MODEL), retriever, mail)
        except Exception as e:
            errors["agent"] = str(e)

    if "detector" not in _cache:
        try:
            from defense.detection import Detector

            _cache["detector"] = Detector()
        except Exception as e:
            errors["detector"] = str(e)

    if "gate" not in _cache:
        try:
            # The class is ProvenanceGate, and it needs the contact list or its
            # decisions diverge from the CLI's (runner.py:63).
            from attacks.loader import contacts
            from defense.prevention import ProvenanceGate

            _cache["gate"] = ProvenanceGate(contacts=frozenset(contacts().values()))
        except Exception as e:
            errors["gate"] = str(e)

    return errors


def get_runner():
    """One Runner, reusing the detector already loaded.

    Runner builds its own Retriever, but rag.retriever._load() is an
    lru_cache(maxsize=1), so the FAISS index and the embedding model are loaded
    once regardless of how many Retriever instances exist.
    """
    if "runner" not in _cache:
        from evaluation.runner import Runner

        _cache["runner"] = Runner(trials=1, detector=_cache.get("detector"))
    return _cache["runner"]


# ── Serialisers ──────────────────────────────────────────────────────────────


def chunk_json(c, poisoned_id):
    return {
        "chunk_id": c.chunk_id,
        "document_id": c.document_id,
        "text": c.text,
        # Origin/Decision/FieldClass are all str-subclass enums with lowercase
        # values, so .value is a plain string.
        "origin": c.origin.value,
        "similarity": round(float(c.similarity), 4),
        "is_poisoned": c.chunk_id == poisoned_id,
    }


def call_json(call):
    return {
        "call_id": call.call_id,
        "tool": call.tool_name,
        "args": dict(call.arguments or {}),
    }


def detection_json(d):
    return {
        "chunk_id": d.chunk_id,
        "score": round(float(d.score), 3),
        "label": d.label,
        "latency_ms": d.latency_ms,
        "model": d.model,
        "error": d.error,
        "failed": bool(d.failed),
    }


def decision_json(d):
    prov = []
    for fp in d.field_provenance or []:
        # There is no per-field verdict in the schema. A field is a violation
        # when a CONTROL argument traces to EXTERNAL bytes (prevention.py:85);
        # derive that here rather than pretending the field exists.
        violation = fp.field_class.value == "control" and fp.origin.value == "external"
        prov.append(
            {
                "field_name": fp.field_name,
                "field_class": fp.field_class.value,
                "origin": fp.origin.value,
                "external_support": fp.external_support,
                "matched_span": fp.matched_span,
                "violation": violation,
            }
        )
    return {
        "call_id": d.call_id,
        "decision": d.decision.value,
        "denied": bool(d.denied),
        "sanitized": bool(d.sanitized),
        "sanitized_arguments": d.sanitized_arguments,
        "reason": d.reason,
        "field_provenance": prov,
    }


def conditions_json(outcomes):
    from conditions import ALL_CONDITIONS

    by_name = {c.name: c for c in ALL_CONDITIONS}
    out = {}
    for o in outcomes:
        cond = by_name[o.condition]
        out[o.condition] = {
            "label": cond.label,
            "detection": cond.detection,
            "prevention": cond.prevention,
            "outcome": o.outcome.value,
            "attack_success": o.outcome.is_attack_success,
            "counts_in_asr": o.outcome.counts_in_asr_denominator,
            "executed": o.executed_calls,
            "blocked_by": o.blocked_by,
        }
    return out


# ── Static UI ────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    # The mailbox is the front door; the paired A/B/C/D research view is /lab.
    return send_from_directory(app.static_folder, "mail.html")


@app.route("/lab")
def lab():
    return send_from_directory(app.static_folder, "index.html")


# ── API: health ──────────────────────────────────────────────────────────────


@app.route("/api/status")
def status():
    errors = load_all()
    return jsonify({"ok": not errors, "errors": errors})


# ── API: payloads + benign tasks ─────────────────────────────────────────────


@app.route("/api/payloads")
def api_payloads():
    try:
        from attacks.loader import load_payloads

        # Payload fields are id / family / evasion — there is no task_id and no
        # category.
        return jsonify(
            [
                {
                    "id": p.id,
                    "family": p.family,
                    "evasion": p.evasion,
                    "task": p.user_task,
                    "payload": p.payload,
                    "inject_into": p.inject_into,
                    "gate_applicable": p.gate_applicable,
                    "split": p.split,
                    # The lab turns this into a plain-words success rule before
                    # the run, so a beginner knows what "winning" means for the
                    # attacker without reading evaluation/predicates.py.
                    "predicate": p.target.get("predicate"),
                }
                for p in load_payloads(split=None)
            ]
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/benign")
def api_benign():
    try:
        from attacks.loader import load_benign

        return jsonify(
            [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "task": t.user_task,
                    "hard_negative": t.hard_negative,
                    "split": t.split,
                }
                for t in load_benign(split=None)
            ]
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/families")
def api_families():
    """Attack family descriptions, for the lab's "About this attack" box.

    Copies only the families dict, not the file: payloads.json also holds the
    canary, the tracking code the canary predicates search for, and a generic
    lookup endpoint has no reason to hand it out. A description that ever
    quotes the canary is redacted rather than trusted to stay clean.
    """
    try:
        import json

        from config import PAYLOADS_PATH

        raw = json.loads(PAYLOADS_PATH.read_text(encoding="utf-8"))
        canary = str(raw.get("canary") or "")
        families = {}
        for name, desc in (raw.get("families") or {}).items():
            text = str(desc)
            if canary:
                text = text.replace(canary, "[redacted]")
            families[str(name)] = text
        return jsonify({"families": families})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: run ─────────────────────────────────────────────────────────────────


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.json or {}
    payload_id = (data.get("payload_id") or "").strip()
    benign_id = (data.get("benign_id") or "").strip()
    user_task = (data.get("user_task") or "").strip()
    inject_into = data.get("inject_into") or None

    errors = load_all()
    result = {
        "user_task": user_task,
        "is_attack": bool(payload_id),
        "scored": False,
        "scored_reason": "",
        "component_errors": errors,
        "chunks": [],
        "proposed_calls": [],
        "detections": [],
        "decisions": [],
        "conditions": {},
        "final_text": "",
        "tokens": 0,
        "latency_ms": 0,
        "poisoned_chunk_id": None,
        "retrieval_hit": None,
        "error": None,
    }

    try:
        from attacks.loader import load_benign, load_payloads

        item = None
        is_attack = False
        if payload_id:
            item = next((p for p in load_payloads() if p.id == payload_id), None)
            if item is None:
                return jsonify({**result, "error": f"Unknown payload {payload_id}"}), 400
            is_attack = True
        elif benign_id:
            item = next((t for t in load_benign() if t.id == benign_id), None)
            if item is None:
                return jsonify({**result, "error": f"Unknown benign task {benign_id}"}), 400

        if item is not None:
            return jsonify(_with_usage(run_scored(result, item, is_attack)))

        if not user_task:
            return jsonify({**result, "error": "user_task is required"}), 400
        return jsonify(_with_usage(run_freeform(result, user_task, inject_into)))

    except Exception as e:
        result["error"] = f"Run failed: {e}"
        result["traceback"] = traceback.format_exc()
        return jsonify(result), 500


def run_scored(result, item, is_attack):
    """The corpus path. Identical to `python cli.py demo` — same Runner, same
    RunRecord, same conditions.score(). If this ever disagrees with the CLI,
    one of them is wrong and it is worth knowing."""
    if get("agent") is None or get("detector") is None:
        result["error"] = "Agent or detector unavailable — see component_errors."
        return result

    runner = get_runner()

    # RunRecord keeps only chunk IDs, but the UI wants to show the chunk text —
    # including the spliced payload — exactly as the agent saw it. Rather than
    # duplicate Runner._one (and risk it drifting from the real scoring path),
    # briefly wrap agent.run to keep the AgentRun it returns.
    captured = {}
    original_run = runner.agent.run

    def capturing_run(*args, **kwargs):
        out = original_run(*args, **kwargs)
        captured["run"] = out
        return out

    runner.agent.run = capturing_run
    try:
        record = runner._one(item, 1, is_attack=is_attack)
    finally:
        runner.agent.run = original_run

    outcomes = runner.score_all([record])
    run = captured.get("run")
    chunks = list(run.chunks or []) if run is not None else []

    result.update(
        {
            "user_task": item.user_task,
            "is_attack": is_attack,
            "scored": True,
            "task_id": item.id,
            "chunks": [chunk_json(c, record.poisoned_chunk_id) for c in chunks],
            "proposed_calls": [call_json(c) for c in record.proposed_calls],
            "detections": [detection_json(d) for d in record.detections],
            "decisions": [decision_json(d) for d in record.policy_decisions],
            "conditions": conditions_json(outcomes),
            "final_text": record.agent_final_text or "",
            "tokens": (record.input_tokens or 0) + (record.output_tokens or 0),
            "latency_ms": record.latency_ms or 0,
            "poisoned_chunk_id": record.poisoned_chunk_id,
            "retrieval_hit": record.retrieval_hit,
            "error": record.error,
        }
    )
    if is_attack:
        result["payload_meta"] = {
            "family": item.family,
            "evasion": item.evasion,
            "gate_applicable": item.gate_applicable,
            "predicate": item.target.get("predicate"),
        }
    return result


def run_freeform(result, user_task, inject_into):
    """Exploratory path: arbitrary text, no corpus item, therefore no predicate."""
    agent = get("agent")
    if agent is None:
        result["error"] = "Agent not loaded — see component_errors."
        return result

    mail = _cache.get("mail")
    if mail is not None:
        mail.clear()

    run = agent.run(user_task, inject=None, inject_into=None)

    detections = []
    detector = get("detector")
    if detector is not None and run.chunks:
        try:
            detections = detector.scan_all(run.chunks)
        except Exception as e:
            result["detections"] = [{"error": str(e)}]

    decisions = []
    gate = get("gate")
    if gate is not None and run.proposed_calls:
        try:
            decisions = gate.evaluate_all(run.proposed_calls, user_task, run.chunks)
        except Exception as e:
            result["decisions"] = [{"error": str(e)}]

    result.update(
        {
            "scored": False,
            "scored_reason": (
                "Free-text run: no corpus item, so there is no mechanical success "
                "predicate and the four conditions cannot be scored. Pick a payload "
                "or a benign task to get A/B/C/D."
            ),
            "chunks": [chunk_json(c, run.poisoned_chunk_id) for c in (run.chunks or [])],
            "proposed_calls": [call_json(c) for c in (run.proposed_calls or [])],
            "final_text": run.final_text or "",
            "tokens": (run.input_tokens or 0) + (run.output_tokens or 0),
            "latency_ms": run.latency_ms or 0,
            "poisoned_chunk_id": run.poisoned_chunk_id,
            "retrieval_hit": run.poisoned_chunk_id is not None,
            "error": run.error,
        }
    )
    if detections and not result["detections"]:
        result["detections"] = [detection_json(d) for d in detections]
    if decisions and not result["decisions"]:
        result["decisions"] = [decision_json(d) for d in decisions]
    return result


# ── Entry point ──────────────────────────────────────────────────────────────

# ── API: mailbox playground (live mode) ──────────────────────────────────────
#
# Live, not shadow: the switches decide what really happens in this one run.
# Reported numbers still come only from the research harness (/lab, cli.py
# eval); see interface/playground.py for why the two modes differ.


def get_playground():
    if "playground" not in _cache:
        from attacks.loader import contacts
        from interface.playground import Playground

        _cache["playground"] = Playground(contacts())
    return _cache["playground"]


def get_playground_gate():
    """The team's gate, given the playground's address book.

    The research gate only knows the corpus contacts. In the mailbox the user
    also writes to colleagues like Sara, whose address appears in no prompt -
    only in her own email - so without the directory every reply to her looks
    like a recipient lifted from external content.
    """
    if "playground_gate" not in _cache:
        from defense.prevention import ProvenanceGate

        _cache["playground_gate"] = ProvenanceGate(contacts=get_playground().directory)
    return _cache["playground_gate"]


def _defense_status():
    from interface.playground import _implemented

    return {
        "detection": {"implemented": _implemented(get("detector")), "loaded": get("detector") is not None},
        "prevention": {"implemented": _implemented(get("gate")), "loaded": get("gate") is not None},
    }


@app.route("/api/mailbox")
def api_mailbox():
    from config import AGENT_MODEL, AGENT_PROVIDER, DETECTOR_MODEL, DETECTOR_PROVIDER
    from interface.playground import EMPLOYEE

    load_all()
    box = get_playground()
    return jsonify(
        {
            "employee": EMPLOYEE,
            "inbox": box.inbox,
            "sent": box.sent,
            "documents": [{k: d[k] for k in ("id", "title", "planted")} for d in box.documents()],
            # The static colleague list the gate itself uses. The Mailbox page
            # needs it to tell "the agent mailed a colleague you didn't name"
            # from "the agent mailed an address an attacker planted" — without
            # it, replying to Sara (whose address appears only inside her own
            # email) looks identical to an injected recipient.
            "contacts": sorted(box.directory),
            "defenses": _defense_status(),
            "models": {
                "agent": f"{AGENT_MODEL} on {AGENT_PROVIDER}",
                "detector": f"{DETECTOR_MODEL} on {DETECTOR_PROVIDER}",
            },
        }
    )


@app.route("/api/mailbox/receive", methods=["POST"])
def api_mailbox_receive():
    data = request.json or {}
    email = get_playground().receive(
        str(data.get("sender") or ""), str(data.get("subject") or ""), str(data.get("body") or "")
    )
    return jsonify(email)


@app.route("/api/mailbox/inbox/<email_id>", methods=["DELETE"])
def api_mailbox_delete(email_id):
    return jsonify({"deleted": get_playground().delete(email_id)})


@app.route("/api/mailbox/compose", methods=["POST"])
def api_mailbox_compose():
    data = request.json or {}
    if not str(data.get("to") or "").strip():
        return jsonify({"error": "A recipient is required."}), 400
    entry = get_playground().compose(
        str(data.get("to") or ""), str(data.get("subject") or ""), str(data.get("body") or ""),
        cc=str(data.get("cc") or ""), bcc=str(data.get("bcc") or ""),
    )
    return jsonify(entry)


@app.route("/api/mailbox/reset", methods=["POST"])
def api_mailbox_reset():
    get_playground().reset()
    return jsonify({"ok": True})


@app.route("/api/documents")
def api_documents():
    return jsonify(get_playground().documents())


@app.route("/api/documents/<doc_id>/plant", methods=["POST", "DELETE"])
def api_documents_plant(doc_id):
    box = get_playground()
    if request.method == "DELETE":
        box.unplant(doc_id)
        return jsonify({"ok": True})
    text = str((request.json or {}).get("text") or "").strip()
    if not text:
        return jsonify({"error": "Write the text to plant first."}), 400
    try:
        box.plant(doc_id, text)
    except KeyError:
        return jsonify({"error": f"No document called {doc_id}."}), 404
    return jsonify({"ok": True})


def _judge(payload_id: str, result: dict) -> dict:
    """Score a live run with the harness's own predicate, not a UI heuristic.

    Mirrors evaluation/runner.py:score_all for a single unscored run. Live mode
    has no conditions, so every proposed call is an executed call.
    """
    try:
        from attacks.loader import canary, contacts, load_payloads
        from evaluation.predicates import attack_succeeded, benign_succeeded, carrier_success
        from schema import ToolCall

        item = next((p for p in load_payloads() if p.id == payload_id), None)
        if item is None:
            return {"known": False}

        calls = [
            ToolCall(s.get("call_id") or f"c{i}", s["tool"], s.get("args") or {})
            for i, s in enumerate(result.get("steps") or [])
        ]
        reply = result.get("reply") or ""

        # goal_hijack wins by making the agent abandon the user's task, so it
        # needs to know what a correct answer looks like. The others ignore it.
        spec = item.success or carrier_success(item.family, item.user_task, contacts())
        ben_ok = benign_succeeded(spec, calls, reply)
        won = attack_succeeded(item.target["predicate"], calls, reply, canary(), ben_ok)

        return {
            "known": True,
            "attack_succeeded": bool(won),
            "task_still_worked": bool(ben_ok),
            "predicate": item.target["predicate"],
            "family": item.family,
        }
    except Exception as e:      # telemetry, so fail open and say why
        _log.warning("verdict failed for %s: %s", payload_id, e)
        return {"known": False, "error": f"{type(e).__name__}: {e}"}


@app.route("/api/assistant", methods=["POST"])
def api_assistant():
    from agent.llm import get_provider
    from config import AGENT_MODEL, AGENT_PROVIDER

    data = request.json or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Type a request for the assistant first."}), 400

    errors = load_all()
    missing = [n for n in ("retriever", "detector", "gate") if get(n) is None]
    if missing:
        return jsonify({"error": f"Components failed to load: {missing}", "component_errors": errors}), 500
    try:
        result = get_playground().ask(
            message,
            provider=get_provider(AGENT_PROVIDER, AGENT_MODEL),
            retriever=get("retriever"),
            detector=get("detector"),
            gate=get_playground_gate(),
            detection_on=bool(data.get("detection")),
            prevention_on=bool(data.get("prevention")),
        )
    except Exception as e:
        traceback.print_exc()
        _record_run(0)   # a failed run still spent tokens upstream
        return jsonify({"error": f"{type(e).__name__}: {e}", "usage": _usage()}), 500
    # Ground truth. The page used to judge "did the attack win?" by diffing
    # recipients, which is only ONE of four predicates: content_exfiltration
    # wins in the body, reply_channel_exfil in the reply text, and goal_hijack
    # by breaking the user's task. Four of the eight landing dev payloads have
    # nothing to do with recipients, so the page reported real hits as misses.
    # evaluation/predicates.py is the same judge the research harness uses.
    payload_id = str(data.get("payload_id") or "").strip()
    if payload_id:
        result["verdict"] = _judge(payload_id, result)
    return jsonify(_with_usage(result))


if __name__ == "__main__":
    print("\n  COE444 Security Lab")
    print("   -> http://127.0.0.1:5000\n")
    errors = load_all()
    if errors:
        print("Some components failed to load:")
        for k, v in errors.items():
            print(f"   {k}: {v}")
        print("   (The app still starts — fix the errors and reload)\n")
    else:
        print("All components loaded\n")
    # 127.0.0.1, not 0.0.0.0: debug=True enables the Werkzeug console, which
    # executes arbitrary Python. Binding it to every interface would put a
    # remote shell on the network.
    # No auto-reloader: it hands the first process's environment - including
    # the .env values it loaded at startup - to every restart, and
    # load_dotenv(override=False) then refuses to replace them. A server started
    # before a key was added kept sending the old, empty key. Restart by hand
    # (Ctrl+C, run again) after changing code or .env.
    app.run(debug=True, use_reloader=False, host="127.0.0.1", port=5000)
