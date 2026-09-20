"""The agent's tool surface.

Each tool declares, per argument, whether that argument is CONTROL or CONTENT.
That table is the input to the prevention gate and it is the reason the gate can
be deterministic: it never asks whether a value looks malicious, only whether a
CONTROL value traces back to bytes the user wrote.

`to`, `cc` and `bcc` steer where a message lands, so they are CONTROL. `subject`
and `body` are what the message carries, so they are CONTENT — summarising a
retrieved policy document into an email body is the normal, legitimate case and
must not be blocked.
"""

from __future__ import annotations

import logging
from typing import Any

from schema import FieldClass

_log = logging.getLogger(__name__)

# tool name -> {argument name -> field class}
FIELD_CLASSES: dict[str, dict[str, FieldClass]] = {
    "send_email": {
        "to": FieldClass.CONTROL,
        "cc": FieldClass.CONTROL,
        "bcc": FieldClass.CONTROL,
        "subject": FieldClass.CONTENT,
        "body": FieldClass.CONTENT,
    },
    "search_documents": {
        "query": FieldClass.CONTENT,
    },
}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "search_documents",
        "description": (
            "Search the company's internal policy documents and return the most "
            "relevant excerpts. Use this whenever the user asks about company "
            "policy, benefits, procedures, or guidelines."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to search for."}
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "send_email",
        "description": (
            "Send an email on the user's behalf. Use this when the user asks you "
            "to email, send, forward, or share something with someone."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address."},
                "subject": {"type": "string", "description": "Subject line."},
                "body": {"type": "string", "description": "Body of the message."},
                "cc": {"type": "string", "description": "Optional CC address."},
                "bcc": {"type": "string", "description": "Optional BCC address."},
            },
            "required": ["to", "subject", "body"],
            "additionalProperties": False,
        },
    },
]


def field_class(tool_name: str, argument: str) -> FieldClass:
    """CONTROL for anything we have not explicitly classified.

    Failing closed here means a tool argument someone forgets to classify gets
    the strict treatment rather than silently becoming an ungated channel.
    """
    return FIELD_CLASSES.get(tool_name, {}).get(argument, FieldClass.CONTROL)
