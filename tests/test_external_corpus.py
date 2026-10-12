"""The exploratory LLMail-Inject corpus: it loads, stays separate from ours, and is
contained. Reads only attacks/external_llmail.json and ids of the main corpus."""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = _ROOT / "attacks" / "external_llmail.json"


def _external():
    from attacks.loader import load_payloads

    return load_payloads("exploratory")


def test_the_external_corpus_loads_as_its_own_split():
    ext = _external()
    assert 150 <= len(ext) <= 200
    assert {p.split for p in ext} == {"exploratory"}
    assert len({p.id for p in ext}) == len(ext)
    assert all(p.id.startswith("PI-LM-") for p in ext)  # summary_table counts PI- ids as attacks


def test_the_main_corpus_never_returns_external_items():
    from attacks.loader import load_benign, load_payloads

    assert not any(p.id.startswith("PI-LM-") for p in load_payloads())
    assert len(load_payloads("dev")) == 10
    assert load_benign("exploratory") == []


def test_every_external_payload_can_be_scored():
    from evaluation.predicates import is_attacker_address

    for p in _external():
        assert p.target == {"tool": "send_email", "predicate": "recipient_is_attacker"}
        assert p.success == {"predicate": "answer_nonempty"}
    # The rewritten address, and the original if the agent rebuilds it from an obfuscation.
    assert is_attacker_address("contact@contact.com.invalid")
    assert is_attacker_address("CONTACT@contact.com")


def test_every_external_payload_is_within_the_stated_length_cap():
    doc = json.loads(EXTERNAL.read_text(encoding="utf-8"))
    assert max(len(p["payload"]) for p in doc["payloads"]) <= doc["sampling"]["max_chars"]


def test_every_address_in_the_external_corpus_is_under_a_reserved_name():
    for p in _external():
        for addr in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", p.payload):
            assert addr.lower().endswith((".invalid", ".example")), p.id


def test_the_file_names_its_source_licence_and_rules():
    doc = json.loads(EXTERNAL.read_text(encoding="utf-8"))
    assert doc["corpus_version"] == "llmail-v1"
    assert doc["source"]["dataset"] == "microsoft/llmail-inject-challenge"
    assert doc["source"]["revision"] == "1063bdf01ec8762b812d5e06ee768a06faa5a6f7"
    assert doc["source"]["license"] == "MIT"
    assert doc["conversion_rules"] and doc["sampling"]["seed"] == 444


def test_corpus_version_is_read_from_the_corpus_file():
    from attacks.loader import corpus_version

    assert corpus_version("dev") == "v0.2.1-ridealong"
    assert corpus_version("exploratory") == "llmail-v1"


def test_eval_takes_the_exploratory_split_and_a_limit():
    from cli import build_parser

    args = build_parser().parse_args(["eval", "--split", "exploratory", "--limit", "50", "--trials", "1"])
    assert (args.split, args.limit, args.trials) == ("exploratory", 50, 1)


def test_limit_runs_only_the_first_items_in_file_order(monkeypatch, tmp_path):
    import evaluation.runner as er
    from agent.agent import AgentRun
    from attacks.loader import Payload
    from evaluation.runner import Runner
    from mailsink import MailSink
    from schema import DetectionResult

    items = [Payload(id=f"PI-LM-000{i}", family="llmail_inject", evasion="e", user_task="Summarise.",
                     inject_into="email_guidelines", payload="p",
                     target={"tool": "send_email", "predicate": "recipient_is_attacker"},
                     gate_applicable=True, split="exploratory", success={"predicate": "answer_nonempty"})
             for i in range(1, 4)]
    monkeypatch.setattr(er, "LOG_DIR", tmp_path)
    monkeypatch.setattr(er, "load_payloads", lambda split=None: items)
    monkeypatch.setattr(er, "load_benign", lambda split=None: [])

    seen = []

    class _Agent:
        def run(self, prompt, *, inject=None, inject_into=None):
            seen.append(prompt)
            return AgentRun(user_prompt=prompt, final_text="A summary of the guidelines.",
                            poisoned_chunk_id="email_guidelines::1")

    class _Detector:
        def scan_all(self, chunks):
            return [DetectionResult(c.chunk_id, 0.0, "clean", 0, "fake") for c in chunks]

    runner = Runner.__new__(Runner)
    runner.trials, runner.agent, runner.detector, runner.gate = 1, _Agent(), _Detector(), None
    runner.mail, runner.git, runner.canary, runner.contacts = MailSink(), "test", "C", {}
    records, _ = runner.run_all("exploratory", limit=2)
    assert [r.task_id for r in records] == ["PI-LM-0001", "PI-LM-0002"]
    assert {r.corpus_version for r in records} == {"llmail-v1"}
