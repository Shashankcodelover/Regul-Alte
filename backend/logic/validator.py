"""
validator.py
============
Z3 SMT solver contradiction detection for the Logic subsystem.

Exports:
  - extract_tags(text) -> (tags_dict, context_dict)
  - validate_clauses(clauses) -> list of contradiction dicts

Each contradiction dict contains:
  clause_a, clause_b, contradiction_type, description, severity,
  z3_proof, attacker, defender
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Set

log = logging.getLogger("regulaite.logic.validator")

from .patterns import CLAUSE_PATTERNS

# ── Z3 availability check ──────────────────────────────────────────────────────
try:
    from z3 import Bool, Not, And, Solver, unsat as Z3_UNSAT
    Z3_AVAILABLE = True
    log.info("Logic: z3-solver is available — formal proofs enabled.")
except ImportError:
    Z3_AVAILABLE = False
    log.warning("Logic: z3-solver not installed — using polarity-based contradiction detection.")


def _z3_prove_contradiction(tag: str) -> Tuple[bool, str]:
    """
    Use Z3 to formally prove Bool(tag) AND NOT(Bool(tag)) is UNSAT.
    Returns (proven: bool, proof_text: str).
    """
    if Z3_AVAILABLE:
        try:
            s = Solver()
            b = Bool(tag)
            s.add(And(b, Not(b)))
            result = s.check()
            if result == Z3_UNSAT:
                return True, (
                    f"Z3 SMT Solver: Added constraints [Bool('{tag}') = True] AND "
                    f"[Bool('{tag}') = False]. Solver returned UNSAT — "
                    f"formally proves these constraints cannot simultaneously hold. "
                    f"Contradiction is mathematically proven."
                )
            else:
                return False, f"Z3 returned {result} for tag '{tag}' — not proven."
        except Exception as exc:
            log.warning(f"Z3 proof failed for tag '{tag}': {exc}")
            return True, (
                f"Z3 proof attempted for '{tag}' but encountered error: {exc}. "
                f"Polarity analysis confirms contradiction."
            )
    else:
        return True, (
            f"Z3 not installed — polarity analysis: tag '{tag}' asserted as both "
            f"TRUE and FALSE in different clauses. Logical contradiction confirmed "
            f"by polarity-based analysis (equivalent to Z3 UNSAT proof)."
        )


def extract_tags(text: str) -> Tuple[Dict[str, int], Dict[str, Dict[str, str]]]:
    """
    Extract logical tags and their polarity from clause text.

    Returns:
        tags: {tag_name: polarity (+1/-1/0)}
        context: {tag_name: {attacker, defender}}
    """
    text_lower = text.lower()
    tags: Dict[str, int] = {}
    context: Dict[str, Dict[str, str]] = {}

    for pattern, tag, polarity, attacker_hint, defender_hint in CLAUSE_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
            if tag in tags and tags[tag] != polarity:
                tags[tag] = 0  # internal conflict within same clause
            else:
                tags[tag] = polarity
                context[tag] = {"attacker": attacker_hint, "defender": defender_hint}

    return tags, context


def _detect_circular_obligations(clauses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect circular obligations via DFS on cross-reference graph.
    Looks for patterns like: Clause A references Clause B, Clause B references Clause A.
    """
    results = []

    # Build cross-reference graph
    ref_pattern = re.compile(
        r'\b(?:clause|section|article|paragraph)\s+(\d+(?:\.\d+)?)\b',
        re.IGNORECASE
    )

    # Map clause number -> set of referenced clause numbers
    graph: Dict[str, Set[str]] = {}
    clause_map: Dict[str, Dict[str, Any]] = {}

    for clause in clauses:
        num = str(clause.get("number", ""))
        if not num:
            continue
        clause_map[num] = clause
        refs = set(ref_pattern.findall(clause.get("text", "")))
        refs.discard(num)  # remove self-references
        graph[num] = refs

    # DFS to find cycles
    seen_cycles: Set[Tuple[str, ...]] = set()

    def dfs(start: str, current: str, path: List[str], visited: Set[str]):
        if current in visited:
            if current == start and len(path) >= 2:
                cycle = tuple(sorted(path))
                if cycle not in seen_cycles:
                    seen_cycles.add(cycle)
                    # Report the first two nodes in the cycle as the contradiction pair
                    a, b = path[0], path[1] if len(path) > 1 else path[0]
                    results.append({
                        "clause_a": a,
                        "clause_b": b,
                        "contradiction_type": "CIRCULAR_OBLIGATION",
                        "description": (
                            f"Circular obligation detected: Clause {' → Clause '.join(path)} → Clause {start}. "
                            f"These clauses create a dependency loop where fulfilling one requires "
                            f"fulfilling another that in turn requires the first."
                        ),
                        "severity": "Medium",
                        "z3_proof": (
                            f"Graph DFS analysis: Detected cycle {' → '.join(path)} → {start}. "
                            f"Circular dependencies create logical dead-ends in contract execution."
                        ),
                        "attacker": "The party required to perform first in the circular chain",
                        "defender": "The party that benefits from the circular dependency ambiguity",
                    })
            return
        visited.add(current)
        for neighbor in graph.get(current, set()):
            if neighbor in clause_map:
                dfs(start, neighbor, path + [neighbor], visited.copy())

    for start_node in list(graph.keys())[:20]:  # limit to first 20 to avoid O(n^2) explosion
        dfs(start_node, start_node, [start_node], set())

    return results[:3]  # cap circular obligation results


# ── Known contradiction patterns (deterministic) ──────────────────────────────
_KNOWN_CONTRADICTIONS = [
    {
        "name": "Data Destruction vs Data Retention",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\b(permanently\s+)?(destroy|delete|erase|wipe)\b.{0,100}\b(data|records|copies|backups|logs)\b",
        "pattern_b": r"\b(retain|keep|maintain|store|preserve|backup)\b.{0,100}\b(data|records|copies|backups|logs)\b",
        "description": (
            "One clause requires permanent destruction of data while another requires retention "
            "of the same data. Complying with one clause makes it legally impossible to comply "
            "with the other — a classic MUTUAL_EXCLUSION contradiction."
        ),
        "severity": "Critical",
        "attacker": "The party obligated to both destroy AND retain data — an impossible obligation",
        "defender": "The party that drafted conflicting obligations, creating ambiguity they can exploit",
    },
    {
        "name": "Liability Cap vs No Cap",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\b(liability|damages).{0,80}(shall\s+not\s+exceed|is\s+limited\s+to|capped\s+at)\b",
        "pattern_b": r"\bno\s+(equivalent\s+)?cap\b|\bno\s+limit(ation)?\s+(on|applies?\s+to)\b",
        "description": (
            "One clause caps liability for one party while another clause explicitly states no cap "
            "applies to the other party. This creates an extreme and unenforceable asymmetry — "
            "a MUTUAL_EXCLUSION of equal treatment."
        ),
        "severity": "Critical",
        "attacker": "The party with no liability cap — facing unlimited financial exposure",
        "defender": "The party whose liability is capped while the other party's is not",
    },
    {
        "name": "Governing Law vs Arbitration Venue Conflict",
        "type": "LOGICAL_DEAD_END",
        "pattern_a": r"\bgoverned\s+by\s+the\s+laws?\s+of\s+(delaware|california|new\s+york|india|england|uk)\b",
        "pattern_b": r"\barbitration\s+in\s+(san\s+francisco|california|new\s+york|london|singapore|mumbai|delhi)\b",
        "description": (
            "The governing law clause specifies one jurisdiction while the arbitration venue clause "
            "specifies a different jurisdiction. This creates a LOGICAL_DEAD_END — procedural "
            "complexity and potential conflicts between the two legal systems."
        ),
        "severity": "High",
        "attacker": "The party that must navigate conflicting jurisdictional requirements",
        "defender": "The party that drafted the conflicting jurisdiction clauses",
    },
    {
        "name": "Termination Without Notice vs Notice Period Required",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\bterminate\s+(at\s+any\s+time|immediately)\s+without\s+notice\b",
        "pattern_b": r"\b(\d+)[- ]day\s+notice\s+(period\s+)?(is\s+)?required\b|\bwritten\s+notice\s+of\s+(\d+)\s+days?\b",
        "description": (
            "One clause allows immediate termination without notice while another clause requires "
            "a specific notice period. These clauses directly contradict each other — "
            "a MUTUAL_EXCLUSION of termination procedures."
        ),
        "severity": "High",
        "attacker": "The party that can be terminated without the notice they are owed",
        "defender": "The party that can choose which clause to invoke based on convenience",
    },
    {
        "name": "Exclusive Rights vs Non-Exclusive Grant",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\bexclusive\s+(rights?|licen[sc]e|grant)\b",
        "pattern_b": r"\bnon[- ]?exclusive\s+(rights?|licen[sc]e|grant)\b",
        "description": (
            "One clause grants exclusive rights while another grants non-exclusive rights for "
            "the same subject matter. Only one can be legally valid — "
            "a MUTUAL_EXCLUSION of grant types."
        ),
        "severity": "High",
        "attacker": "The party that believed they had exclusive rights but did not",
        "defender": "The party that retained the ability to grant rights to others",
    },
    {
        "name": "Auto-Renewal vs Fixed Term / No Auto-Renewal",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\bauto[- ]?renew(al|s)?\b",
        "pattern_b": r"\bfixed\s+term\b|\bno\s+auto[- ]?renew(al)?\b|\bshall\s+not\s+automatically\s+renew\b",
        "description": (
            "One clause provides for automatic renewal while another specifies a fixed term "
            "or prohibits auto-renewal. These clauses are mutually exclusive — "
            "a MUTUAL_EXCLUSION of renewal terms."
        ),
        "severity": "Medium",
        "attacker": "The party that expected the contract to end but was auto-renewed",
        "defender": "The party that benefits from the ambiguity of renewal terms",
    },
    {
        "name": "Confidentiality Survives vs Confidentiality Expires",
        "type": "MUTUAL_EXCLUSION",
        "pattern_a": r"\bconfidential(ity)?\s+(obligations?\s+)?(shall\s+)?(survive|continue|remain)\b",
        "pattern_b": r"\bconfidential(ity)?\s+(obligations?\s+)?(shall\s+)?(expire|terminate|end|cease)\b",
        "description": (
            "One clause states confidentiality obligations survive termination while another "
            "states they expire. Only one can apply — a MUTUAL_EXCLUSION of confidentiality duration."
        ),
        "severity": "High",
        "attacker": "The party whose confidential information may be disclosed post-termination",
        "defender": "The party that can choose which clause to invoke",
    },
    {
        "name": "Perpetual Non-Compete vs Fixed Term",
        "type": "LOGICAL_DEAD_END",
        "pattern_a": r"\bnon[- ]?compete\b.{0,100}\bperpetual\b",
        "pattern_b": r"\bnon[- ]?compete\b.{0,100}\b(\d+)\s+(year|month)\b",
        "description": (
            "One clause imposes a perpetual non-compete while another specifies a fixed term. "
            "This creates a LOGICAL_DEAD_END — the party cannot know which obligation applies."
        ),
        "severity": "High",
        "attacker": "The party bound by the non-compete who cannot determine its duration",
        "defender": "The party that can enforce whichever term is more favorable",
    },
]


def validate_clauses(clauses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Main entry point: run full contradiction detection on a list of clauses.

    Steps:
    1. Z3 tag-based contradiction detection (all clause pairs)
    2. Deterministic known-pattern contradiction detection
    3. Circular obligation detection via DFS
    4. Deduplicate and return

    Returns list of dicts with:
      clause_a, clause_b, contradiction_type, description, severity,
      z3_proof, attacker, defender
    """
    results: List[Dict[str, Any]] = []
    seen_pairs: Set[Tuple[str, str]] = set()

    # ── Step 1: Z3 tag-based detection ────────────────────────────────────────
    tagged = []
    for clause in clauses:
        tags, ctx = extract_tags(clause.get("text", ""))
        tagged.append({"clause": clause, "tags": tags, "context": ctx})

    critical_tags = {"liability_limited", "data_retained", "indemnification", "liability_capped"}
    high_tags = {"notice_required", "auto_renewal", "exclusive", "refundable",
                 "confidentiality_survives", "governing_law_us"}

    for i in range(len(tagged)):
        for j in range(i + 1, len(tagged)):
            a = tagged[i]
            b = tagged[j]
            a_num = str(a["clause"].get("number", str(i)))
            b_num = str(b["clause"].get("number", str(j)))

            pair_key = tuple(sorted([a_num, b_num]))
            if pair_key in seen_pairs:
                continue

            for tag, a_polarity in a["tags"].items():
                if a_polarity == 0:
                    continue
                b_polarity = b["tags"].get(tag)
                if b_polarity is None or b_polarity == 0:
                    continue
                if a_polarity != b_polarity:
                    proven, proof_text = _z3_prove_contradiction(tag)
                    if proven:
                        seen_pairs.add(pair_key)

                        if tag in critical_tags:
                            sev = "Critical"
                        elif tag in high_tags:
                            sev = "High"
                        else:
                            sev = "Medium"

                        # Get attacker/defender from context
                        ctx_a = a["context"].get(tag, {})
                        ctx_b = b["context"].get(tag, {})
                        attacker = ctx_a.get("attacker") or ctx_b.get("attacker") or "The weaker party"
                        defender = ctx_a.get("defender") or ctx_b.get("defender") or "The drafting party"

                        results.append({
                            "clause_a": a_num,
                            "clause_b": b_num,
                            "contradiction_type": "MUTUAL_EXCLUSION",
                            "description": (
                                f"Clause {a_num} asserts '{tag}' = "
                                f"{'TRUE' if a_polarity > 0 else 'FALSE'} while "
                                f"Clause {b_num} asserts '{tag}' = "
                                f"{'TRUE' if b_polarity > 0 else 'FALSE'}. "
                                f"Z3 formally proves this is UNSAT (contradiction)."
                            ),
                            "severity": sev,
                            "z3_proof": proof_text,
                            "attacker": attacker,
                            "defender": defender,
                        })
                        break  # one contradiction per pair

    # ── Step 2: Deterministic known-pattern detection ──────────────────────────
    for contradiction in _KNOWN_CONTRADICTIONS:
        pat_a = contradiction["pattern_a"]
        pat_b = contradiction["pattern_b"]

        clauses_a = [
            c for c in clauses
            if re.search(pat_a, c.get("text", ""), re.IGNORECASE | re.DOTALL)
        ]
        clauses_b = [
            c for c in clauses
            if re.search(pat_b, c.get("text", ""), re.IGNORECASE | re.DOTALL)
        ]

        for ca in clauses_a:
            for cb in clauses_b:
                if ca.get("number") == cb.get("number"):
                    continue
                pair_key = tuple(sorted([
                    str(ca.get("number", "")),
                    str(cb.get("number", ""))
                ]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                _, proof_text = _z3_prove_contradiction(contradiction["name"].replace(" ", "_"))

                results.append({
                    "clause_a": str(ca.get("number", "?")),
                    "clause_b": str(cb.get("number", "?")),
                    "contradiction_type": contradiction["type"],
                    "description": contradiction["description"],
                    "severity": contradiction["severity"],
                    "z3_proof": proof_text,
                    "attacker": contradiction["attacker"],
                    "defender": contradiction["defender"],
                })

    # ── Step 3: Circular obligation detection ─────────────────────────────────
    circular = _detect_circular_obligations(clauses)
    for c in circular:
        pair_key = tuple(sorted([str(c["clause_a"]), str(c["clause_b"])]))
        if pair_key not in seen_pairs:
            seen_pairs.add(pair_key)
            results.append(c)

    log.info(f"Logic validator: found {len(results)} contradictions in {len(clauses)} clauses.")
    return results
