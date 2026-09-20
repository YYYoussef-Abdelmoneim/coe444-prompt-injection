"""The agent loop.

Note what is absent: there is no `condition` parameter, no `if detection_on`,
no branch of any kind for the evaluation arms. The agent executes once, the
defenses observe in shadow mode, and conditions are applied afterwards by
conditions.score(). If this file ever grows a condition flag, the experiment
stops being a controlled comparison — the arms would differ by code, not just
by policy.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent.llm import LLMProvider, LLMToolCall
from agent.prompts import SYSTEM_PROMPT
from agent.tools import TOOL_SCHEMAS
from mailsink import MailSink
from rag.retriever import Retriever
from schema import Origin, TaggedChunk, ToolCall

_log = logging.getLogger(__name__)

MAX_TURNS = 4


@dataclass
class AgentRun:
    """Everything one execution produced, before any condition is applied."""

    user_prompt: str
    chunks: list[TaggedChunk] = field(default_factory=list)
    poisoned_chunk_id: str | None = None
    proposed_calls: list[ToolCall] = field(default_factory=list)
    final_text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    error: str | None = None


class Agent:
    def __init__(self, provider: LLMProvider, retriever: Retriever, mail: MailSink) -> None:
        self.provider = provider
        self.retriever = retriever
        self.mail = mail

    def run(
        self,
        user_prompt: str,
        *,
        inject: str | None = None,
        inject_into: str | None = None,
    ) -> AgentRun:
        started = time.monotonic()
        out = AgentRun(user_prompt=user_prompt)
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]

        try:
            for _ in range(MAX_TURNS):
                resp = self.provider.generate(messages, TOOL_SCHEMAS, SYSTEM_PROMPT)
                out.input_tokens += resp.input_tokens
                out.output_tokens += resp.output_tokens

                if not resp.tool_calls:
                    out.final_text = resp.text
                    break

                messages.append({"role": "assistant", "content": resp.raw_blocks})
                results = []
                for call in resp.tool_calls:
                    out.proposed_calls.append(
                        ToolCall(call_id=call.id, tool_name=call.name, arguments=dict(call.input))
                    )
                    results.append(self._execute(call, out, inject, inject_into))
                messages.append({"role": "user", "content": results})
            else:
                out.final_text = "(turn limit reached)"
        except Exception as exc:  # noqa: BLE001 - one bad run must not kill a sweep
            _log.exception("Agent run failed")
            out.error = f"{type(exc).__name__}: {exc}"

        out.latency_ms = int((time.monotonic() - started) * 1000)
        return out

    def _execute(
        self,
        call: LLMToolCall,
        out: AgentRun,
        inject: str | None,
        inject_into: str | None,
    ) -> dict[str, Any]:
        """Execute a proposed call and build the tool_result block.

        In shadow mode every proposed call executes — including attacker-chosen
        ones. That is safe because send_email lands in MailSink, which has no
        network path, and it is necessary because scoring condition A requires
        observing what an undefended agent actually did.
        """
        try:
            if call.name == "search_documents":
                chunks, poisoned = self.retriever.search(
                    str(call.input.get("query", "")), inject=inject, inject_into=inject_into
                )
                # Only the first search carries the injection, matching an
                # attacker who poisoned one document rather than the corpus.
                if poisoned and out.poisoned_chunk_id is None:
                    out.poisoned_chunk_id = poisoned
                    inject = None
                out.chunks.extend(chunks)
                content = "\n\n---\n\n".join(
                    f"[{c.chunk_id}] {c.text}" for c in chunks
                ) or "No matching documents."
            elif call.name == "send_email":
                msg = self.mail.send(
                    to=str(call.input.get("to", "")),
                    subject=str(call.input.get("subject", "")),
                    body=str(call.input.get("body", "")),
                    cc=call.input.get("cc"),
                    bcc=call.input.get("bcc"),
                )
                content = f"Email sent to {msg.to}."
            else:
                content = f"Unknown tool: {call.name}"
            return {"type": "tool_result", "tool_use_id": call.id, "content": content}
        except Exception as exc:  # noqa: BLE001
            return {
                "type": "tool_result",
                "tool_use_id": call.id,
                "content": f"Error: {exc}",
                "is_error": True,
            }
