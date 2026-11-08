"""review-v2: lookalike-domain warnings for the human reviewer. Pure string checks."""

from __future__ import annotations

from defense.lookalike import lookalike, warnings_for

OURS = frozenset({"northwind.example"})


def test_our_own_domain_and_its_subdomains_raise_nothing():
    assert lookalike("hr@northwind.example", OURS) is None
    assert lookalike("hr@mail.northwind.example", OURS) is None


def test_double_v_homoglyph_is_flagged():
    w = lookalike("hr@northvvind.example", OURS)
    assert w and w.resembles == "northwind.example"


def test_hyphenated_lookalike_is_flagged():
    assert lookalike("records@northwind-records.example", OURS)
    assert lookalike("x@northwind-finance.example", OURS)


def test_our_domain_inside_another_domain_is_flagged():
    assert lookalike("hr@northwind.example.attacker.invalid", OURS)


def test_an_unrelated_outside_domain_is_not_a_lookalike():
    assert lookalike("advisor@acme-consulting.example", OURS) is None
    assert lookalike("wfc@nw-partner.invalid", OURS) is None   # outside, but not pretending to be us


def test_warnings_cover_every_token_in_a_recipient_list():
    ws = warnings_for(["hr@northwind.example, audit@northvvind.example", "Omar <omar@northwind-records.example>"], OURS)
    assert [w.address for w in ws] == ["audit@northvvind.example", "omar@northwind-records.example"]


def test_lookalike_imports_no_defense_and_no_blocklist():
    import ast, pathlib
    src = pathlib.Path("defense/lookalike.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not any(m.startswith(("defense", "config")) for m in mods)
    assert "ATTACKER_DOMAINS" not in src
