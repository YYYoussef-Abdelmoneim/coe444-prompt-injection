"""The company directory behind lookup_contact. No live API calls."""

from __future__ import annotations

import pytest

from schema import Origin


def _directory():
    from directory import Directory

    return Directory.load()


def test_the_directory_holds_every_corpus_contact_and_knows_the_company_domain():
    """The scoring ground truth (benign_tasks.json contacts) must be reachable by lookup,
    or the tasks that name a recipient indirectly could never succeed."""
    from attacks.loader import contacts

    d = _directory()
    assert set(contacts().values()) <= d.addresses()
    assert d.internal_domains == frozenset({"northwind.example"})


def test_every_entry_has_a_name_role_domain_and_clearance():
    for e in _directory().entries:
        assert e.name and e.role
        assert e.email.endswith("@" + e.domain)
        assert e.clearance in {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}


@pytest.mark.parametrize(
    "query, address",
    [("my manager", "manager@northwind.example"), ("finance", "finance@northwind.example"),
     ("HR", "hr@northwind.example"), ("Sara", "sara.khan@northwind.example"),
     ("Omar Farouk", "manager@northwind.example"), ("the finance team", "finance@northwind.example")],
)
def test_names_roles_and_aliases_resolve(query, address):
    assert address in [e.email for e in _directory().lookup(query)]


def test_a_lookup_returns_directory_bytes_stamped_directory():
    """Origin is set where the text enters, like the retriever's EXTERNAL stamp."""
    [chunk] = _directory().search("my manager")
    assert chunk.origin is Origin.DIRECTORY
    assert chunk.document_id == "directory"
    assert chunk.chunk_id == "directory::manager@northwind.example"
    assert "manager@northwind.example" in chunk.text


def test_a_miss_returns_nothing_rather_than_echoing_the_query():
    """An echoed query would come back stamped DIRECTORY: a way to launder an
    injected address into trusted text."""
    assert _directory().search("attacker@evil.invalid") == []
    assert _directory().search("") == []
