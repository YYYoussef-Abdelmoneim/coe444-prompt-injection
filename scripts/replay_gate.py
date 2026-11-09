"""Offline replay: re-run the current gate on every logged send_email call in the given live logs
and compare with the decision recorded by gate-v3 at run time. No API."""
import json, sys
sys.path.insert(0, ".")
from defense.prevention import ProvenanceGate, POLICY_VERSION
from schema import ToolCall, TaggedChunk, Origin
from directory import Directory

d = Directory.load() if hasattr(Directory, "load") else None
internal = d.internal_domains if d else frozenset({"northwind.example"})
gate = ProvenanceGate(internal_domains=internal)

def chunks_of(rec):
    out = []
    for c in rec.get("chunks") or []:
        out.append(TaggedChunk(c["chunk_id"], c.get("document_id", ""), c["text"], Origin(c["origin"]), c.get("similarity", 0.0)))
    return out

total = same = 0; diffs = []
for path in ["logs/live-20261108T211359Z.jsonl", "logs/live-20261108T213725Z.jsonl"]:
    for line in open(path):
        rec = json.loads(line)
        logged = {d["call_id"]: d for d in rec["policy_decisions"]}
        chunks = chunks_of(rec)
        for call in rec["proposed_calls"]:
            if call["tool_name"] != "send_email" or call["call_id"] not in logged:
                continue
            total += 1
            new = gate.evaluate(ToolCall(call["call_id"], "send_email", call["arguments"]), rec["user_prompt"], chunks)
            old = logged[call["call_id"]]
            if new.decision.value == old["decision"] and (new.sanitized_arguments or None) == (old.get("sanitized_arguments") or None):
                same += 1
            else:
                diffs.append((rec["task_id"], rec["live_condition"], call["call_id"], old["decision"], new.decision.value))
print(f"{POLICY_VERSION} replay over logged gate-v3 decisions: {same}/{total} identical")
for x in diffs[:10]: print("  DIFF", x)
