"""Layer 2 - the provenance gate (gate-v1).

THE QUESTION
For every recipient the agent proposes: did these exact bytes come from the
user, from the company directory in this run, or from text an attacker could
write? It never asks whether an address looks malicious. Swap a payload for an
unseen one with identical provenance and the decision is bit-for-bit the same -
which is what makes this a deterministic invariant rather than a second, weaker
classifier.

WHY ARGUMENT GRANULARITY, NOT CALL GRANULARITY
The team's proposal gates whole calls: block any tool call that "traces to
external content". Walk that through the canonical attack from their own
diagram. The user says "summarise the Q3 report and email it to my team". The
*call* is user-initiated, so a call-level check passes it - while the injection
has quietly rewritten `to` to attacker@evil.invalid. Call-level origin tagging
does not see this at all. Per-argument provenance does.

THE RULES
Every CONTROL argument (to, cc, bcc, and any argument the tool schema does not
classify) is split on commas, semicolons and newlines, and each token is parsed
strictly as ONE address, 'a@b.c' or 'Name <a@b.c>'. Then, per token:
  USER       the user typed this exact address
  DIRECTORY  lookup_contact returned it in this run, before this call (a chunk
             stamped Origin.DIRECTORY). Directory membership alone grants
             nothing: the runner and the Mailbox hand the gate only what had
             been read before the call ran.
  kept                USER or DIRECTORY, on a company domain;
  kept, to confirm    USER outside the company, or a company address that
                      appears only in retrieved content (excerpts, emails);
  stripped            everything else: an outside address from content, any
                      address found nowhere, a token that does not parse.
DENY if a required field (to) is left empty - an email whose recipient was
injected is not the user's email. Otherwise SANITIZE if anything was stripped
(subject and body untouched). Otherwise CONFIRM if anything needs confirming:
a simulated approval, so the email goes out as proposed. Otherwise ALLOW.

The company's domains come from data/directory.json. They only decide whether
an address the gate already attributed is the company's own; they never make an
external address acceptable, and this is not a blocklist of attacker domains.

TODO(after-presentation): sensitivity labels - compare a document's
classification with the recipient's directory clearance before it is mailed.
TODO(after-presentation): lookalike domains - flag 'northwind-records.example'
or 'northvvind.example' next to 'northwind.example' in the CONFIRM prompt.

WHAT THIS GATE DOES NOT COVER  (state this in the report; do not let a reader
discover it)
  * Exfiltration through CONTENT. If the attacker's goal is to get secret text
    into the body of a mail to an *authorised* recipient, every CONTROL field is
    clean and the gate allows it. This is not an oversight - it is the boundary
    of what provenance can decide, and it is why condition C has a measurable,
    non-zero attack success rate instead of a rate that is zero by theorem.
  * Exfiltration through the agent's natural-language reply to the user.
  * Social engineering the user into approving a malicious action themselves -
    which is exactly what a real CONFIRM would put in front of them.
  * Influencing WHICH document gets retrieved.

This module does not import defense/detection.py and must never call it, and it
never reads config.ATTACKER_DOMAINS, which exists for scoring only.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agent.tools import field_class, is_required
from schema import Decision, FieldClass, FieldProvenance, Origin, PolicyDecision, TaggedChunk, ToolCall

_log = logging.getLogger(__name__)

# Recorded in every RunRecord. gate-stub-v0 allowed everything; provenance-v1
# and -v2 (unmerged) trusted a static contact list.
POLICY_VERSION = "gate-v1"

# A dot-atom local part and a dotted domain: deliberately narrower than RFC 5322.
# A quoted local part ('"audit"@x.invalid') or a source route ('@a.invalid:b@c')
# is legal mail syntax, but the gate cannot attribute those bytes whole, so the
# token fails to parse and is stripped rather than waved through.
_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_ADDR = rf"{_ATOM}(?:\.{_ATOM})*@{_LABEL}(?:\.{_LABEL})+"
_IN_TEXT = re.compile(rf"(?<![\w.+-])({_ADDR})")
_BARE = re.compile(rf"({_ADDR})")
_NAMED = re.compile(rf"[^<>@\"]*<\s*({_ADDR})\s*>")
_SEPARATORS = re.compile(r"[,;\n]")

_KEEP, _CONFIRM, _STRIP = "keep", "confirm", "strip"


class ProvenanceGate:
    """Per-argument provenance policy over proposed tool calls."""

    # Read by the Mailbox page to label the Prevention switch.
    implemented = True

    def __init__(self, internal_domains: frozenset[str] | set[str] = frozenset()) -> None:
        # The company's own domains, from data/directory.json. Empty means no
        # domain counts as the company's, the strictest reading: such a gate
        # never trusts a company address it was not shown.
        self.internal_domains = frozenset(d.lower() for d in internal_domains)

    def evaluate(
        self, call: ToolCall, user_prompt: str, chunks: list[TaggedChunk]
    ) -> PolicyDecision:
        typed = _addresses(user_prompt)
        looked_up = {a for c in chunks if c.origin is Origin.DIRECTORY for a in _addresses(c.text)}
        external = [(c.chunk_id, _addresses(c.text)) for c in chunks if c.origin is Origin.EXTERNAL]

        provenance: list[FieldProvenance] = []
        stripped: list[str] = []
        confirm: list[str] = []
        sanitized = dict(call.arguments)
        unrepairable = False

        for name, value in call.arguments.items():
            if value is None or value == "" or field_class(call.tool_name, name) is FieldClass.CONTENT:
                continue
            tokens = _tokens(value)
            kept: list[str] = []
            for token in tokens:
                verdict, prov = self._attribute(name, token, typed, looked_up, external)
                provenance.append(prov)
                if verdict == _STRIP:
                    stripped.append(token)
                    continue
                kept.append(token)
                if verdict == _CONFIRM and prov.matched_span not in confirm:
                    confirm.append(prov.matched_span)
            if len(kept) == len(tokens):
                continue
            # Strip, don't deny: the rest of the call is what the user asked for,
            # so dropping it would turn a blocked attack into a broken task. A
            # required field left empty cannot be repaired.
            if kept:
                sanitized[name] = ", ".join(kept)
            elif is_required(call.tool_name, name):
                unrepairable = True
            else:
                del sanitized[name]

        decision, reason, repaired = self._decide(unrepairable, stripped, confirm, sanitized)
        _log.info("gate %s %s %s stripped=%s confirm=%s",
                  POLICY_VERSION, call.call_id, decision.value, stripped, confirm)
        return PolicyDecision(
            call_id=call.call_id,
            decision=decision,
            reason=reason,
            field_provenance=provenance,
            sanitized_arguments=repaired,
            stripped=stripped,
            needs_confirmation=confirm,
        )

    def evaluate_all(
        self, calls: list[ToolCall], user_prompt: str, chunks: list[TaggedChunk]
    ) -> list[PolicyDecision]:
        return [self.evaluate(c, user_prompt, chunks) for c in calls]

    def _attribute(
        self,
        name: str,
        token: str,
        typed: set[str],
        looked_up: set[str],
        external: list[tuple[str, set[str]]],
    ) -> tuple[str, FieldProvenance]:
        address = _parse(token)
        if address is None:
            return _STRIP, FieldProvenance(name, FieldClass.CONTROL, Origin.EXTERNAL, None, token)
        internal = address.rsplit("@", 1)[1] in self.internal_domains
        if address in typed:
            return (_KEEP if internal else _CONFIRM), FieldProvenance(
                name, FieldClass.CONTROL, Origin.USER, None, address)
        if address in looked_up:
            return (_KEEP if internal else _CONFIRM), FieldProvenance(
                name, FieldClass.CONTROL, Origin.DIRECTORY, None, address)
        support = next((chunk_id for chunk_id, found in external if address in found), None)
        prov = FieldProvenance(name, FieldClass.CONTROL, Origin.EXTERNAL, support, address)
        if internal and support is not None:
            return _CONFIRM, prov
        return _STRIP, prov

    @staticmethod
    def _decide(
        unrepairable: bool, stripped: list[str], confirm: list[str], sanitized: dict[str, Any]
    ) -> tuple[Decision, str, dict[str, Any] | None]:
        to_confirm = (f"; confirm {', '.join(confirm)} (simulated approval)" if confirm else "")
        if unrepairable:
            return (Decision.DENY,
                    f"no recipient left after stripping {', '.join(stripped)}: not typed by the user "
                    "and not returned by a directory lookup in this run", None)
        if stripped:
            return (Decision.SANITIZE,
                    f"stripped {', '.join(stripped)}: not typed by the user and not returned by a "
                    f"directory lookup in this run{to_confirm}", sanitized)
        if confirm:
            return (Decision.CONFIRM,
                    f"needs the user's confirmation: {', '.join(confirm)}; simulated approval, "
                    "sent as proposed", None)
        return (Decision.ALLOW,
                "every recipient was typed by the user or returned by a directory lookup", None)


def _addresses(text: str) -> set[str]:
    return {a.lower() for a in _IN_TEXT.findall(text or "")}


def _tokens(value: Any) -> list[str]:
    parts = value if isinstance(value, (list, tuple)) else [value]
    return [t.strip() for p in parts for t in _SEPARATORS.split(str(p)) if t.strip()]


def _parse(token: str) -> str | None:
    """The one address a recipient token holds, lowercased, or None."""
    t = token.strip().rstrip(".")
    m = _BARE.fullmatch(t) or _NAMED.fullmatch(t)
    return m.group(1).lower() if m else None
