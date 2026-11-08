"""Lookalike-domain warning for the human review step (review-v2).

The lookalike family (attacks/THREAT_MODEL.md) targets the person who approves
a protected send, not the agent: 'hr@northvvind.example' or
'records@northwind-records.example' next to 'northwind.example' reads as
internal at a glance. The gate already strips such an address when nobody typed
it and no lookup returned it. This module covers the remaining path: the user
themselves typed or confirmed it, so it survives to review, and the reviewer
needs to see that it is NOT the company domain.

Pure string comparison against the company's own domains from the directory.
No model, no blocklist of attacker domains, no judgement about intent; it only
answers "how close is this domain to ours without being ours?". It changes no
decision: review-v2 shows a warning, the person still decides.
"""

from __future__ import annotations

from dataclasses import dataclass

# Characters that are commonly swapped to fool a reader. Used only to score
# similarity, never to decide anything on its own.
_CONFUSABLE = {
    "vv": "w", "rn": "m", "cl": "d", "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b",
}


@dataclass(frozen=True)
class LookalikeWarning:
    address: str
    domain: str
    resembles: str
    reason: str


def _registrable(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _fold(s: str) -> str:
    out = s.lower()
    for a, b in _CONFUSABLE.items():
        out = out.replace(a, b)
    return out


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(address: str, internal_domains: frozenset[str] | set[str]) -> LookalikeWarning | None:
    """A warning if the address's domain resembles one of ours but is not one of ours."""
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].lower().strip(">").strip()
    if not domain:
        return None
    ours = {d.lower() for d in internal_domains}
    if domain in ours or _registrable(domain) in ours:
        return None
    reg = _registrable(domain)
    base = reg.split(".", 1)[0]
    for mine in ours:
        mine_base = mine.split(".", 1)[0]
        # 1. confusable-character spelling of our name (northvvind, n0rthwind)
        if _fold(base) == _fold(mine_base) or _levenshtein(base, mine_base) <= 1:
            return LookalikeWarning(address, domain, mine,
                                    f"'{domain}' is spelled almost like '{mine}' but is a different domain")
        # 2. our name embedded with a hyphen/extra label (northwind-records.example, nw-helpdesk)
        if mine_base in base and base != mine_base:
            return LookalikeWarning(address, domain, mine,
                                    f"'{domain}' contains '{mine_base}' but is not '{mine}'")
        # 3. our domain used as a subdomain of someone else's (northwind.example.attacker.invalid)
        if domain != mine and mine in domain and not domain.endswith("." + mine):
            return LookalikeWarning(address, domain, mine,
                                    f"'{domain}' contains our domain inside another domain")
    return None


def warnings_for(addresses: list[str], internal_domains: frozenset[str] | set[str]) -> list[LookalikeWarning]:
    out: list[LookalikeWarning] = []
    for raw in addresses:
        for token in str(raw).replace(";", ",").split(","):
            token = token.strip()
            if "<" in token and token.endswith(">"):
                token = token[token.index("<") + 1:-1].strip()
            w = lookalike(token, internal_domains)
            if w is not None:
                out.append(w)
    return out
