"""Read run logs back into RunRecords.

Invariant 5 says every metric comes from logs/*.jsonl, and before this module
nothing could read one back. RunRecord.to_json uses dataclasses.asdict, so nested
objects come back as plain dicts and enums as their values; this rebuilds them.

A key the current schema does not know is dropped with a warning rather than
failing the load, so a log written by newer code still loads here. A key the log
lacks takes its dataclass default, which is how logs written before a field
existed stay readable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from pathlib import Path
from typing import Any

from schema import (
    Decision,
    DetectionResult,
    FieldClass,
    FieldProvenance,
    Origin,
    PolicyDecision,
    RunRecord,
    TaggedChunk,
    ToolCall,
)

_log = logging.getLogger(__name__)


def load_records(path: Path | str) -> list[RunRecord]:
    """Every RunRecord in a run log, in file order."""
    path = Path(path)
    records: list[RunRecord] = []
    with path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                records.append(record_from_dict(json.loads(line), where=f"{path.name}:{n}"))
    return records


def record_from_dict(data: dict[str, Any], *, where: str = "record") -> RunRecord:
    d = _known(RunRecord, data, where)
    d["detections"] = [DetectionResult(**_known(DetectionResult, x, where)) for x in d.get("detections", [])]
    d["proposed_calls"] = [ToolCall(**_known(ToolCall, x, where)) for x in d.get("proposed_calls", [])]
    d["policy_decisions"] = [_decision(x, where) for x in d.get("policy_decisions", [])]
    d["chunks"] = [_chunk(x, where) for x in d.get("chunks", [])]
    return RunRecord(**d)


def _decision(x: dict[str, Any], where: str) -> PolicyDecision:
    d = _known(PolicyDecision, x, where)
    d["decision"] = Decision(d["decision"])
    d["field_provenance"] = [_provenance(p, where) for p in d.get("field_provenance", [])]
    return PolicyDecision(**d)


def _provenance(x: dict[str, Any], where: str) -> FieldProvenance:
    d = _known(FieldProvenance, x, where)
    d["field_class"] = FieldClass(d["field_class"])
    d["origin"] = Origin(d["origin"])
    return FieldProvenance(**d)


def _chunk(x: dict[str, Any], where: str) -> TaggedChunk:
    d = _known(TaggedChunk, x, where)
    d["origin"] = Origin(d["origin"])
    return TaggedChunk(**d)


def _known(cls: type, data: dict[str, Any], where: str) -> dict[str, Any]:
    names = {f.name for f in fields(cls)}
    extra = sorted(set(data) - names)
    if extra:
        _log.warning("%s: ignoring %s fields this schema does not know: %s", where, cls.__name__, extra)
    return {k: v for k, v in data.items() if k in names}
