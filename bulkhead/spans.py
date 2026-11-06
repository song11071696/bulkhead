"""Rebuild text from Clocked source offsets (Guard evidence, Protect entities)."""
from __future__ import annotations


def merge_spans(spans: list[dict]) -> list[dict]:
    """Sort spans and drop overlaps (the earlier/longer span wins)."""
    out: list[dict] = []
    for sp in sorted(spans, key=lambda x: (x["start"], -(x["end"] - x["start"]))):
        if out and sp["start"] < out[-1]["end"]:
            if sp["end"] > out[-1]["end"] and sp.get("kind") == out[-1].get("kind"):
                out[-1]["end"] = sp["end"]
            continue
        out.append(dict(sp))
    return out


def apply_spans(text: str, spans: list[dict]) -> str:
    """Replace each span with its ``replacement``. Offsets refer to the original text."""
    parts, pos = [], 0
    for sp in merge_spans([s for s in spans if 0 <= s["start"] < s["end"] <= len(text)]):
        parts.append(text[pos:sp["start"]])
        parts.append(sp["replacement"])
        pos = sp["end"]
    parts.append(text[pos:])
    return "".join(parts)


def guard_spans(text: str, guard: dict) -> list[dict]:
    spans = []
    for ev in guard.get("evidence") or []:
        s, e = ev.get("start"), ev.get("end")
        if s is None or e is None:
            continue
        if text[s:e] != ev.get("quote"):  # offsets must point at the quoted text; otherwise search for it
            idx = text.find(ev.get("quote") or "\0")
            if idx < 0:
                continue
            s, e = idx, idx + len(ev["quote"])
        spans.append({"start": s, "end": e, "kind": "injection",
                      "replacement": f"[BULKHEAD: {e - s} chars quarantined - suspected instruction to the agent]",
                      "label": guard.get("category") or "injection"})
    return spans


def pii_spans(text: str, pii: dict) -> list[dict]:
    spans = []
    for ent in pii.get("entities") or []:
        s, e = ent.get("start"), ent.get("end")
        if s is None or e is None or text[s:e] != ent.get("value"):
            continue
        spans.append({"start": s, "end": e, "kind": "pii", "label": ent["type"],
                      "replacement": f"<{ent['type'].upper()}>"})
    return spans


def mark(text: str, spans: list[dict], mask_pii: bool = True) -> list[dict]:
    """Segments for the audit log/UI: [{text, kind?, label?}] with highlights.

    PII and secret spans are stored as their placeholder, never the raw value, so the audit log
    itself does not become a second copy of the sensitive data Protect found."""
    segs, pos = [], 0
    for sp in merge_spans([s for s in spans if 0 <= s["start"] < s["end"] <= len(text)]):
        if sp["start"] > pos:
            segs.append({"text": text[pos:sp["start"]]})
        shown = sp["replacement"] if (mask_pii and sp.get("kind") == "pii") else text[sp["start"]:sp["end"]]
        segs.append({"text": shown, "kind": sp.get("kind"), "label": sp.get("label")})
        pos = sp["end"]
    if pos < len(text):
        segs.append({"text": text[pos:]})
    return segs
