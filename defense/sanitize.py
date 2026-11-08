"""Layer 0 - the input normaliser (sanitize-v1).

THE JOB
Attackers hide instructions where a human reviewer will not see them but a
model will read them: zero-width characters between letters, Unicode "tag"
characters (U+E0000-E007F, invisible but decoded by many tokenisers - the
"ASCII smuggling" attack), HTML comments, bidi overrides, white-on-white text
markers. Detection is a model reading the excerpt; if the model can read the
hidden text, the detector can too - but a detector that sees ``i n s t r u c t``
with zero-width joiners between the letters is being asked a harder question
than it needs to be. This module makes the hidden visible, or removes it,
deterministically, before any model reads the excerpt.

WHAT IT DOES, in order
1. NFKC normalisation: fullwidth and compatibility forms fold to ASCII, so
   "ｉｇｎｏｒｅ" becomes "ignore".
2. Unicode tag characters (U+E0000-E007F) are decoded to the ASCII they encode
   and marked, so smuggled text becomes visible: "[hidden: ...]".
3. Zero-width and bidi-control characters are removed (U+200B-200F, U+2028-202E,
   U+2060-2064, U+FEFF, U+061C, U+180E).
4. HTML comments and <script>/<style> blocks are replaced by a visible marker.
5. Other C0/C1 control characters (except tab and newline) are removed.

The result keeps every visible character the author wrote. The report shows
how many excerpts were changed and how (sanitize_actions), so a run can say
whether this layer did anything.

INDEPENDENCE
This module imports neither defense/detection.py nor defense/prevention.py,
and neither imports it. It is pure text processing with no model call and no
notion of "malicious"; it only removes what cannot be seen. It is therefore a
pre-processing step, not a classifier, and condition A is still undefended by
it: the shadow runner applies it to the chunks handed to the detector and the
live runner applies it to what the agent reads under B and D.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, replace

from schema import TaggedChunk

SANITIZE_VERSION = "sanitize-v1"

_TAG_BASE = 0xE0000
_TAG_LO, _TAG_HI = 0xE0020, 0xE007F        # tag characters that map to ASCII 0x20-0x7F
_TAG_CANCEL = 0xE007F
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff\u061c\u180e]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_HIDDEN_BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class SanitizeResult:
    text: str
    actions: tuple[str, ...]   # e.g. ("nfkc", "tag_chars", "zero_width", "html_comment")

    @property
    def changed(self) -> bool:
        return bool(self.actions)


def sanitize_text(text: str) -> SanitizeResult:
    actions: list[str] = []
    out = text

    normalised = unicodedata.normalize("NFKC", out)
    if normalised != out:
        actions.append("nfkc")
        out = normalised

    decoded = _decode_tag_characters(out)
    if decoded != out:
        actions.append("tag_chars")
        out = decoded

    stripped = _ZERO_WIDTH.sub("", out)
    if stripped != out:
        actions.append("zero_width")
        out = stripped

    uncommented = _HTML_COMMENT.sub("[hidden html comment removed]", out)
    uncommented = _HTML_HIDDEN_BLOCK.sub("[hidden html block removed]", uncommented)
    if uncommented != out:
        actions.append("html_hidden")
        out = uncommented

    cleaned = _CONTROL.sub("", out)
    if cleaned != out:
        actions.append("control_chars")
        out = cleaned

    return SanitizeResult(out, tuple(actions))


def sanitize_chunk(chunk: TaggedChunk) -> tuple[TaggedChunk, tuple[str, ...]]:
    """The chunk with hidden text made visible or removed. The id, origin and
    poison flag are untouched: where the text came from has not changed."""
    r = sanitize_text(chunk.text)
    if not r.changed:
        return chunk, ()
    return replace(chunk, text=r.text), r.actions


def _decode_tag_characters(text: str) -> str:
    """Unicode tag characters carry an ASCII payload in their low byte. They
    render as nothing. Decode runs of them into visible, marked text."""
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append(f"[hidden: {''.join(run)}]")
            run.clear()

    for ch in text:
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            if cp != _TAG_CANCEL:
                run.append(chr(cp - _TAG_BASE))
            continue
        if cp == _TAG_BASE or _TAG_BASE < cp < _TAG_LO:
            continue  # tag space with no printable mapping: drop
        flush()
        out.append(ch)
    flush()
    return "".join(out)
