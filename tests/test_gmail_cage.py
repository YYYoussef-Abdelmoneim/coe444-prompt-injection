"""The Gmail demo backend's cage: no recipient off the allow-list, ever."""
import pytest

from gmail_backend import check_allowed, RecipientNotAllowed, allowed_recipients


@pytest.fixture
def allow(monkeypatch):
    monkeypatch.setenv("GMAIL_ALLOWED_RECIPIENTS", "444testmail@gmail.com, Attacker.Demo@gmail.com")


def test_an_empty_allow_list_refuses_everything(monkeypatch):
    monkeypatch.setenv("GMAIL_ALLOWED_RECIPIENTS", "")
    with pytest.raises(RecipientNotAllowed):
        check_allowed("444testmail@gmail.com")


def test_allowed_recipients_pass(allow):
    check_allowed("444testmail@gmail.com", cc="attacker.demo@gmail.com")   # no raise


def test_a_single_off_list_bcc_refuses_the_whole_send(allow):
    with pytest.raises(RecipientNotAllowed) as e:
        check_allowed("444testmail@gmail.com", bcc="records@nw-partner.invalid")
    assert "records@nw-partner.invalid" in str(e.value)


def test_a_display_name_with_an_embedded_address_is_still_checked(allow):
    with pytest.raises(RecipientNotAllowed):
        check_allowed('"444testmail@gmail.com" <evil@example.com>')


def test_the_corpus_attacker_domains_can_never_be_allowed_by_accident(allow):
    assert not any(a.endswith(".invalid") for a in allowed_recipients())


def test_the_evaluation_harness_never_imports_the_gmail_backend():
    import pathlib
    for f in ("evaluation/live.py", "evaluation/runner.py", "cli.py", "agent/agent.py", "mailsink.py", "conditions.py"):
        assert "gmail_backend" not in pathlib.Path(f).read_text(encoding="utf-8"), f


def test_the_default_backend_is_still_the_simulated_sink(monkeypatch):
    """With no MAIL_BACKEND anywhere (env or .env), config falls back to the sink."""
    monkeypatch.delenv("MAIL_BACKEND", raising=False)
    import importlib, dotenv, config, mailsink
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)   # ignore the developer's .env
    importlib.reload(config)
    try:
        assert config.MAIL_BACKEND == "simulated"
        importlib.reload(mailsink)
        assert type(mailsink.get_mail_backend()).__name__ == "MailSink"
    finally:
        monkeypatch.undo(); importlib.reload(config); importlib.reload(mailsink)
