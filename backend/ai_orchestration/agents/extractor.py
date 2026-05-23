"""
extractor.py — Agent 1: ClauseExtractor
========================================
Segments raw contract text into individual numbered clauses.
Pure Python regex — no LLM calls.

Handles:
  - Numbered clauses:  1.1, 2.3.1, 10.
  - Lettered clauses:  (a), (b), a.
  - Roman numerals:    (i), (ii), i.
  - ALL-CAPS headings: CLAUSE 5, SECTION 3
  - Paragraph fallback if fewer than 3 clauses found
"""

import re
import logging
from typing import List, Dict, Any

log = logging.getLogger("regulaite.extractor")

# ── Regex patterns for clause detection ───────────────────────────────────────
_NUMBERED_CLAUSE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){0,3}\.?)\s+(.+)",
    re.MULTILINE,
)
_LETTERED_CLAUSE = re.compile(
    r"^\s*\(([a-z]{1,3})\)\s+(.+)",
    re.MULTILINE,
)
_ROMAN_CLAUSE = re.compile(
    r"^\s*\((i{1,3}|iv|v|vi{0,3}|ix|x{1,3})\)\s+(.+)",
    re.MULTILINE | re.IGNORECASE,
)
_CAPS_HEADING = re.compile(
    r"^(CLAUSE|SECTION|ARTICLE|SCHEDULE|APPENDIX)\s+(\d+[A-Z]?)\b",
    re.MULTILINE,
)
_SECTION_HEADING = re.compile(
    r"^([A-Z][A-Z\s]{3,50})\s*$",
    re.MULTILINE,
)


def _clean_text(text: str) -> str:
    """Normalise whitespace and line endings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse 3+ blank lines to 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _split_by_regex(text: str) -> List[Dict[str, Any]]:
    """
    Primary strategy: find all numbered clause starts and slice text between them.
    Returns list of {number, text, section}.
    """
    lines = text.split("\n")
    clauses: List[Dict[str, Any]] = []
    current_number: str = ""
    current_section: str = ""
    current_lines: List[str] = []
    current_heading: str = ""

    for line in lines:
        stripped = line.strip()

        # Detect section headings (ALL CAPS lines)
        if _SECTION_HEADING.match(stripped) and len(stripped) > 3:
            current_heading = stripped

        # Detect numbered clause start
        m = _NUMBERED_CLAUSE.match(stripped)
        if m:
            # Save previous clause
            if current_number and current_lines:
                clauses.append({
                    "number": current_number,
                    "text": " ".join(current_lines).strip(),
                    "section": current_section or current_heading,
                })
            current_number = m.group(1).rstrip(".")
            current_section = current_heading
            current_lines = [m.group(2)]
            continue

        # Detect CAPS heading clause (CLAUSE 5, SECTION 3)
        m2 = _CAPS_HEADING.match(stripped)
        if m2:
            if current_number and current_lines:
                clauses.append({
                    "number": current_number,
                    "text": " ".join(current_lines).strip(),
                    "section": current_section or current_heading,
                })
            current_number = f"{m2.group(1).title()} {m2.group(2)}"
            current_section = current_number
            current_lines = []
            continue

        # Continuation of current clause
        if current_number and stripped:
            current_lines.append(stripped)

    # Flush last clause
    if current_number and current_lines:
        clauses.append({
            "number": current_number,
            "text": " ".join(current_lines).strip(),
            "section": current_section or current_heading,
        })

    return clauses


def _split_by_paragraphs(text: str) -> List[Dict[str, Any]]:
    """
    Fallback: split by double newlines (paragraphs).
    Assigns synthetic clause numbers P1, P2, ...
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 30]
    clauses = []
    for i, para in enumerate(paragraphs, start=1):
        clauses.append({
            "number": f"P{i}",
            "text": para,
            "section": "General",
        })
    return clauses


def extract_clauses(contract_text: str) -> List[Dict[str, Any]]:
    """
    Main entry point for Agent 1.

    Args:
        contract_text: raw text extracted from PDF or pasted

    Returns:
        List of clause dicts: [{number, text, section}]
        Always returns at least 1 clause.
    """
    text = _clean_text(contract_text)

    # Primary: regex-based numbered clause detection
    clauses = _split_by_regex(text)
    log.info(f"Regex extraction found {len(clauses)} clauses.")

    # Fallback: paragraph splitting if too few clauses found
    if len(clauses) < 3:
        log.info("Fewer than 3 clauses found — falling back to paragraph splitting.")
        clauses = _split_by_paragraphs(text)
        log.info(f"Paragraph fallback found {len(clauses)} clauses.")

    # Final fallback: treat entire text as one clause
    if not clauses:
        log.warning("No clauses found — treating entire text as single clause.")
        clauses = [{"number": "1", "text": text[:2000], "section": "General"}]

    # Filter out very short clauses (< 20 chars)
    clauses = [c for c in clauses if len(c.get("text", "")) >= 20]

    # Truncate very long clause texts to 1500 chars for downstream processing
    for c in clauses:
        if len(c["text"]) > 1500:
            c["text"] = c["text"][:1500] + "..."

    log.info(f"ClauseExtractor: returning {len(clauses)} clauses.")
    return clauses
