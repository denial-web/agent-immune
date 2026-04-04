"""
Input decomposition: regex-based injection, exfiltration, secret, escalation, and delimiter detection.

Operates on normalized text from InputNormalizer; pattern hit spans refer to the normalized string.
"""

from __future__ import annotations

import logging
import re
from typing import List, Tuple

from agent_immune.core.models import DecompositionResult, NormalizationResult, PatternHit

logger = logging.getLogger("agent_immune.core.decomposer")

_KHMER_RE = re.compile(r"[\u1780-\u17ff]")
_ENGLISH_IMPERATIVES = re.compile(
    r"\b(ignore|forget|override|pretend|reveal|bypass|disregard|dump|leak|exfil|transmit|forward|password|credentials|admin)\b",
    re.I,
)

_QUOTE_REGIONS = re.compile(
    r"(`{1,3}[^`]+`{1,3}|\"[^\"]{0,500}\"|'[^']{0,500}')",
    re.DOTALL,
)


def _inside_quoted(text: str, start: int, end: int) -> bool:
    for m in _QUOTE_REGIONS.finditer(text):
        if m.start() <= start < m.end() or m.start() < end <= m.end():
            return True
    return False


class InputDecomposer:
    """Scan normalized text for threat patterns and produce scores plus redacted clean text."""

    def __init__(self) -> None:
        pass
        self._injection: List[Tuple[str, re.Pattern[str], str]] = [
            (
                "injection_ignore",
                re.compile(
                    r"(ignore|forget|discard|drop|skip)\s+(?:all|the|your|my|every|any|previous|prior|above|earlier|system|preceding|foregoing)\s+.{0,30}?(instructions?|rules?|prompts?|constraints?|tasks?|directions?|assignments?|orders?|guidelines?|information)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_forget_everything",
                re.compile(
                    r"\b(forget|ignore)\s+everything\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_override",
                re.compile(
                    r"(system\s+override|admin\s+override|developer\s+mode|maintenance\s+mode|sudo\s+mode)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_new_rules",
                re.compile(r"new\s+(rules?|instructions?|persona|identity)\s*:", re.I),
                "medium",
            ),
            (
                "injection_dan",
                re.compile(
                    r"\byou\s+are\s+(now\s+)?(DAN|evil|unrestricted|unfiltered|jailbr[eo]ken)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_reveal",
                re.compile(
                    r"(reveal|show|print|output|repeat|display)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+prompt|secret\s+rules?)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_exfiltrate",
                re.compile(
                    r"\b(exfiltrate)\b.{0,20}\b(data|info|user)|"
                    r"\b(leak|dump)\b.{0,15}\b(credentials?|secrets?|keys?|tokens?|user)|"
                    r"\bleak\s+all\s+user\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_disable_safety",
                re.compile(
                    r"(disable|turn\s+off|remove|bypass|skip)\s+(safety|content\s+policy|filter|guard|moderation)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_end_user_block",
                re.compile(r"###\s*(END\s+USER|SYSTEM|ADMIN)\s*###", re.I),
                "medium",
            ),
            (
                "injection_base64_payload",
                re.compile(
                    r"(decode|base64|eval)\s*\(.*\b(ignore|override|bypass|hack|inject)\b",
                    re.I,
                ),
                "medium",
            ),
            (
                "injection_from_now",
                re.compile(
                    r"from\s+now\s+on,?\s+(you\s+(are|will|must|should|shall)|known\s+as|called)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_disregard",
                re.compile(r"disregard\s+(everything\s+)?(above|prior|previous|before)", re.I),
                "high",
            ),
            (
                "injection_pretend",
                re.compile(
                    r"(pretend|act)\s+(to\s+be|as|like|you\s+are)\s+.{0,50}(hacker|unrestricted|no\s+ethical|evil|malicious)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_task_switch",
                re.compile(
                    r"(forget|ignore)\s+(about\s+)?(all\s+)?(the\s+)?(previous|prior|above|earlier|preceding)?\s*(tasks?|assignments?|work|information|context)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_new_task",
                re.compile(
                    r"(now\s+)?(focus|concentrate|work)\s+on\s+(your\s+)?(new|next|following|this)\s+(task|assignment|instruction|objective)",
                    re.I,
                ),
                "medium",
            ),
            (
                "injection_stop_start",
                re.compile(
                    r"(stop|enough|ok(?:ay)?|well\s+done|great|excellent)[\s.,!:]+\s*(?:now\s+)?(?:please\s+)?(ignore|forget|new\s+task|new\s+instruction|help\s+me\s+with|focus\s+on|write\b)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_output_prompt",
                re.compile(
                    r"(show|output|print|display|reveal|write|repeat)\w*\s+(me\s+)?(all\s+)?(your|the|sämtlich\w*|gesamte?n?)\s+(prompt|system|initial|hidden|secret|internal)\s*(text|message|instruction|prompt)?s?",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_de_forget",
                re.compile(
                    r"\b(vergiss|vergessen\s+sie)\b.{0,30}\b(alles|alle[snr]?\b|davor|zuvor|vorher|aufgab|auftr|anweisung|instruktion|befehl|gesagt)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_de_ignore",
                re.compile(
                    r"\b(ignoriere\w*|ignorieren\s+sie)\b.{0,40}\b(anweisung|befehl|instruktion|aufgab|auftr|alles|obig|vorherig|bisherig|vorangehend)\w*",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_de_neue_aufgabe",
                re.compile(
                    r"\b(nun|jetzt)\b.{0,30}\b(neue?[nrs]?\s+(aufgab|anweisung|instruktion))\w*",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_es_forget",
                re.compile(
                    r"\bolvid[ae]\w*\b.{0,30}\b(todo|todas?\s+las?\s+instrucciones)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_fr_forget",
                re.compile(
                    r"\boubliez\b.{0,30}\b(tout|toutes?\s+les?\s+instructions?)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_hr_forget",
                re.compile(
                    r"\bzaboravi\w*\b.{0,20}\b(sve|instrukcije)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_ru_forget",
                re.compile(r"забудьте\s+все", re.I),
                "high",
            ),
            (
                "injection_act_as_system",
                re.compile(
                    r"\bact\s+as\s+(?:an?\s+)?(?:python|linux|bash|shell|sql|terminal|interpreter|compiler|command[- ]?line)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_repeat_after_me",
                re.compile(r"\brepeat\s+after\s+me\b", re.I),
                "high",
            ),
            (
                "injection_change_instructions",
                re.compile(
                    r"\b(change|modify|replace|update|override)\s+(?:your|the|my)\s+(instructions?|rules?|guidelines?|programming|behavior)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_print_above",
                re.compile(
                    r"(spell[- ]?check|print|reproduce|überprüf\w*)\s+.{0,30}\b(above|obige?n?|vorige?n?)\s*(prompt|text|eingabe|instructions?)",
                    re.I,
                ),
                "high",
            ),
            (
                "injection_abandon_thoughts",
                re.compile(
                    r"\b(abandon|discard|erase)\s+(?:all\s+)?(?:your\s+)?(thoughts?|memory|knowledge)\b",
                    re.I,
                ),
                "high",
            ),
        ]
        self._exfiltration: List[Tuple[str, re.Pattern[str], str]] = [
            (
                "exfil_send_data",
                re.compile(
                    r"\b(send|forward|transmit|relay|upload)\b.{0,40}\b(all\s+)?(user\s+)?(data|dataset|logs?|credentials?)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "exfil_external",
                re.compile(
                    r"\b(forward|relay|send)\b.{0,60}\b(external|backup|attacker|evil)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "exfil_email",
                re.compile(r"\b(email|mail)\b.{0,30}@[a-z0-9.-]+\.[a-z]{2,}", re.I),
                "medium",
            ),
        ]
        self._secret: List[Tuple[str, re.Pattern[str], str]] = [
            (
                "secret_api_key",
                re.compile(
                    r"\b(show|reveal|output|dump|display)\b.{0,20}\b(api\s*key|access\s*token|bearer\s+token)\b",
                    re.I,
                ),
                "high",
            ),
            (
                "secret_config",
                re.compile(r"\b(dump|display|output)\b.{0,20}\b(config|\.env|credentials)\b", re.I),
                "high",
            ),
            (
                "secret_password_assign",
                re.compile(r"\bpassword\s*=\s*\S+", re.I),
                "medium",
            ),
        ]
        self._escalation: List[Tuple[str, re.Pattern[str], str]] = [
            (
                "escalation_admin",
                re.compile(
                    r"\b(admin\s+mode|unrestricted\s+access|elevated\s+privileges|bypass\s+authentication)\b",
                    re.I,
                ),
                "high",
            ),
        ]
        self._delimiter: List[Tuple[str, re.Pattern[str], str]] = [
            ("delim_inst", re.compile(r"\[INST\]|\[SYS\]", re.I), "medium"),
            ("delim_chatml", re.compile(r"<\|im_start\|>|<\|system\|>|<\|redacted_im_end\|>", re.I), "high"),
            ("delim_dash", re.compile(r"---\s*system\s*---", re.I), "medium"),
        ]

        self._weight_injection = 0.35
        self._weight_exfil = 0.40
        self._weight_secret = 0.25
        self._weight_escalation = 0.20
        self._weight_delimiter = 0.15

    def decompose(self, norm: NormalizationResult) -> DecompositionResult:
        """
        Analyze normalized input and return decomposition with threat scores.

        Args:
            norm: Output of InputNormalizer.normalize.

        Returns:
            DecompositionResult with scores, hits, and redacted clean text.

        Raises:
            None.
        """
        text = norm.normalized
        original = norm.original
        injection_hits: List[PatternHit] = []
        delimiter_hits: List[PatternHit] = []
        payload_spans: List[Tuple[int, int]] = []

        def scan_group(
            group: List[Tuple[str, re.Pattern[str], str]],
            category: str,
        ) -> float:
            """Accumulate unbounded hit strength; caller scales by category weight."""
            score_acc = 0.0
            for idx, (_name, pat, sev) in enumerate(group):
                for m in pat.finditer(text):
                    start, end = m.span()
                    inside = _inside_quoted(text, start, end)
                    mult = 0.15 if inside else 1.0
                    sev_f = 1.0 if sev == "high" else 0.6
                    score_acc += sev_f * mult
                    hit = PatternHit(
                        pattern_idx=idx,
                        span=(start, end),
                        matched_text=m.group(0)[:200],
                        severity=sev,
                        category=category,
                        inside_quoted=inside,
                    )
                    if category == "delimiter":
                        delimiter_hits.append(hit)
                    else:
                        injection_hits.append(hit)
                    payload_spans.append((start, end))
            return score_acc

        inj_hits = scan_group(self._injection, "injection")
        exf_hits = scan_group(self._exfiltration, "exfiltration")
        sec_hits = scan_group(self._secret, "secret")
        esc_hits = scan_group(self._escalation, "escalation")
        _ = scan_group(self._delimiter, "delimiter")

        pattern_linear = min(
            1.0,
            min(1.0, inj_hits * 0.22) * self._weight_injection
            + min(1.0, exf_hits * 0.25) * self._weight_exfil
            + min(1.0, sec_hits * 0.3) * self._weight_secret
            + min(1.0, esc_hits * 0.35) * self._weight_escalation
            + (min(1.0, len(delimiter_hits) * 0.5) * self._weight_delimiter),
        )
        hit_boost = min(0.6, 0.18 * (len(injection_hits) + len(delimiter_hits)))

        khmer_chars = len(_KHMER_RE.findall(text))
        khmer_ratio = khmer_chars / max(1, len(text))
        language_mixing_score = 0.0
        if khmer_ratio > 0.10 and _ENGLISH_IMPERATIVES.search(text):
            language_mixing_score = min(1.0, khmer_ratio + 0.3)
            pattern_linear = min(1.0, pattern_linear + 0.2)

        injection_score = min(1.0, pattern_linear + language_mixing_score * 0.25 + hit_boost)

        merged_spans = self._merge_spans(payload_spans, len(text))
        clean_text = self._redact_spans(text, merged_spans)

        result = DecompositionResult(
            original=original,
            clean_text=clean_text,
            injection_score=injection_score,
            language_mixing_score=language_mixing_score,
            khmer_ratio=khmer_ratio,
            injection_hits=injection_hits,
            delimiter_hits=delimiter_hits,
            payload_spans=merged_spans,
        )
        logger.debug("decompose score=%s hits=%s", injection_score, len(injection_hits))
        return result

    def _merge_spans(self, spans: List[Tuple[int, int]], text_len: int) -> List[Tuple[int, int]]:
        if not spans:
            return []
        spans = sorted(spans)
        merged: List[Tuple[int, int]] = []
        cur_s, cur_e = spans[0]
        pad = 30
        for s, e in spans[1:]:
            if s <= cur_e + pad:
                cur_e = max(cur_e, e)
            else:
                merged.append((max(0, cur_s - pad), min(text_len, cur_e + pad)))
                cur_s, cur_e = s, e
        merged.append((max(0, cur_s - pad), min(text_len, cur_e + pad)))
        return merged

    def _redact_spans(self, text: str, raw_spans: List[Tuple[int, int]]) -> str:
        if not raw_spans:
            return text
        merged = sorted(self._merge_spans(raw_spans, len(text)))
        out: List[str] = []
        cursor = 0
        for s, e in merged:
            s = max(0, min(s, len(text)))
            e = max(0, min(e, len(text)))
            if s > cursor:
                out.append(text[cursor:s])
            out.append("[REDACTED]")
            cursor = max(cursor, e)
        out.append(text[cursor:])
        return "".join(out)
