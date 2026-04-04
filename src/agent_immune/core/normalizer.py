"""
Input normalization and deobfuscation before pattern-based threat detection.

Applies Unicode homoglyph folding, zero-width stripping, encoding-aware transforms,
and light HTML/Markdown stripping so regex and downstream scoring see a canonical view.
"""

from __future__ import annotations

import base64
import codecs
import html
import logging
import re
from typing import List, Set

from agent_immune.core.models import NormalizationResult

logger = logging.getLogger("agent_immune.core.normalizer")

# Common Cyrillic / Greek letters that visually resemble Latin (subset; extend as needed)
_HOMOGLYPH_MAP: dict[int, str] = {
    ord("а"): "a",
    ord("е"): "e",
    ord("о"): "o",
    ord("р"): "p",
    ord("с"): "c",
    ord("у"): "y",
    ord("х"): "x",
    ord("і"): "i",
    ord("ј"): "j",
    ord("ѕ"): "s",
    ord("ԛ"): "q",
    ord("ɑ"): "a",
    ord("ο"): "o",
}

_ZERO_WIDTH: Set[str] = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u00ad",
}

_THREAT_KEYWORDS_AFTER_DECODE = re.compile(
    r"\b(ignore|bypass|override|reveal|exfil|leak|dump|password|secret|token|admin|sudo)\b",
    re.I,
)

_BASE64_CHUNK = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")


def _strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in _ZERO_WIDTH)


def _fullwidth_to_ascii(text: str) -> str:
    out: List[str] = []
    for ch in text:
        o = ord(ch)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)


def _homoglyph_fold(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ord(ch), ch) for ch in text)


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def _collapse_spaced_letters(text: str) -> str:
    """Collapse patterns like 'i g n o r e' -> 'ignore' for common imperatives."""

    def repl(m: re.Match[str]) -> str:
        letters = m.group(1).split()
        if len(letters) >= 5:
            return "".join(letters)
        return m.group(0)

    return re.sub(
        r"\b((?:[a-zA-Z]\s+){4,}[a-zA-Z])\b",
        repl,
        text,
    )


def _strip_html_tags(text: str) -> str:
    """Remove HTML-like tags only; preserve ChatML tokens such as <|im_start|>."""
    no_tags = re.sub(r"</?[a-zA-Z][a-zA-Z0-9:-]*(\s[^>]*)?>", " ", text)
    return html.unescape(no_tags)


def _strip_markdown_fences(text: str) -> str:
    text = re.sub(r"```[\s\S]*?```", " ", text)
    text = re.sub(r"`[^`]+`", " ", text)
    return text


_LEET_MAP = str.maketrans({"@": "a", "$": "s", "3": "e", "0": "o", "1": "i", "7": "t", "5": "s"})
_LEET_DIGIT_CHARS = frozenset("30175")
_LETTER_RE = re.compile(r"[a-zA-Z]")


def _leetspeak_normalize(text: str) -> str:
    """Map common leet substitutions when embedded in letter context, preserving pure numeric tokens."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _LEET_DIGIT_CHARS:
            left_is_letter = i > 0 and bool(_LETTER_RE.match(text[i - 1]))
            right_is_letter = i + 1 < n and bool(_LETTER_RE.match(text[i + 1]))
            right_is_digit = i + 1 < n and text[i + 1].isdigit()
            left_is_digit = i > 0 and text[i - 1].isdigit()
            at_word_boundary = i + 1 >= n or not text[i + 1].isalnum()
            if left_is_digit or right_is_digit:
                out.append(ch)
            elif left_is_letter and (right_is_letter or at_word_boundary):
                out.append(ch.translate(_LEET_MAP))
            elif right_is_letter and (i == 0 or not text[i - 1].isalnum()):
                out.append(ch.translate(_LEET_MAP))
            else:
                out.append(ch)
        elif ch in ("@", "$"):
            out.append(ch.translate(_LEET_MAP))
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _try_decode_base64_segments(text: str) -> tuple[str, bool]:
    """Replace obvious base64 segments with decoded ASCII when it looks like a threat."""
    changed = False
    raw = text.encode("utf-8", errors="ignore")

    def replace_chunk(m: re.Match[bytes]) -> bytes:
        nonlocal changed
        chunk = m.group(0)
        try:
            body = chunk.rstrip(b"=")
            pad = (-len(body)) % 4
            decoded = base64.b64decode(body + b"=" * pad, validate=False)
        except Exception:
            return chunk
        try:
            s = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                s = decoded.decode("latin-1", errors="replace")
            except Exception:
                return chunk
        if _THREAT_KEYWORDS_AFTER_DECODE.search(s):
            changed = True
            return (b" " + s.encode("utf-8", errors="replace") + b" ")
        return chunk

    new_bytes = _BASE64_CHUNK.sub(replace_chunk, raw)
    return new_bytes.decode("utf-8", errors="replace"), changed


_ROT13_TRIGGER = re.compile(r"\b(rot13|ROT13|decode\s+this)\b", re.I)


def _rot13_context(text: str) -> tuple[str, bool]:
    trigger = _ROT13_TRIGGER.search(text)
    if not trigger:
        return text, False
    changed = False
    trigger_end = trigger.end()
    window_start = max(0, trigger_end - 20)
    window_end = min(len(text), trigger_end + 500)

    prefix = text[:window_start]
    window = text[window_start:window_end]
    suffix = text[window_end:]

    def rot_block(m: re.Match[str]) -> str:
        nonlocal changed
        inner = m.group(1)
        if len(inner) < 8:
            return m.group(0)
        changed = True
        return _rot13(inner)

    transformed = re.sub(r"([A-Za-z]{8,})", rot_block, window)
    return prefix + transformed + suffix, changed


class InputNormalizer:
    """Apply a fixed pipeline of deobfuscation transforms to raw user or tool input."""

    def __init__(self) -> None:
        pass

    def normalize(self, text: str) -> NormalizationResult:
        """
        Run all normalization transforms and compute obfuscation suspicion.

        Args:
            text: Raw input string.

        Returns:
            NormalizationResult with normalized text and metadata.

        Raises:
            None.
        """
        original = text or ""
        transforms: List[str] = []
        current = original

        step = _strip_zero_width(current)
        if step != current:
            transforms.append("zero_width_strip")
            current = step

        step = _fullwidth_to_ascii(current)
        if step != current:
            transforms.append("fullwidth_to_ascii")
            current = step

        step = _homoglyph_fold(current)
        if step != current:
            transforms.append("homoglyph_fold")
            current = step

        step = _strip_html_tags(current)
        if step != current:
            transforms.append("html_strip")
            current = step

        step = _strip_markdown_fences(current)
        if step != current:
            transforms.append("markdown_fence_strip")
            current = step

        step = _leetspeak_normalize(current)
        if step != current:
            transforms.append("leetspeak_normalize")
            current = step

        step = _collapse_spaced_letters(current)
        if step != current:
            transforms.append("spaced_letter_collapse")
            current = step

        step, b64_changed = _try_decode_base64_segments(current)
        if b64_changed:
            transforms.append("base64_decode_threat")
            current = step

        step, rot_changed = _rot13_context(current)
        if rot_changed:
            transforms.append("rot13_context")
            current = step

        suspicion = 0.0
        if len(transforms) >= 3:
            suspicion = min(1.0, 0.25 + 0.15 * (len(transforms) - 3))
        elif len(transforms) >= 1:
            suspicion = 0.1 * len(transforms)
        if "base64_decode_threat" in transforms:
            suspicion = min(1.0, suspicion + 0.35)

        result = NormalizationResult(
            original=original,
            normalized=current,
            transforms_applied=transforms,
            suspicion_from_normalization=suspicion,
        )
        logger.debug("normalize transforms=%s suspicion=%s", transforms, suspicion)
        return result
