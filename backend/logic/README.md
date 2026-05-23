# Logic Subsystem

The Logic subsystem provides **formal contradiction detection** using the Z3 SMT solver.

## How It Works

1. **Tag Extraction** (`extract_tags`): Each clause is scanned with regex patterns from `patterns.py`. Each pattern maps to a logical tag (e.g., `data_retained`, `liability_capped`) and a polarity (`+1` = asserts TRUE, `-1` = asserts FALSE).

2. **Z3 Proof** (`validate_clauses`): For every pair of clauses, if the same tag is asserted with opposite polarities, Z3 is invoked to prove `Bool(tag) AND NOT(Bool(tag))` is UNSAT. This is a formal mathematical proof — not a heuristic.

3. **Deterministic Patterns**: Known contradiction types (data destruction vs retention, liability cap asymmetry, etc.) are also detected via direct regex matching for reliability.

4. **Circular Obligations**: A DFS graph traversal detects circular cross-references between clauses.

## Graceful Fallback

If `z3-solver` is not installed, the system falls back to polarity-based contradiction detection (equivalent logic, no formal proof). All contradictions are still reported.

## Files

- `patterns.py` — Shared pattern registry (CLAUSE_PATTERNS, PRE_SCORE_PATTERNS, LEGAL_CITATIONS)
- `validator.py` — Z3 contradiction detection engine
- `__init__.py` — Public API: `validate_clauses`, `extract_tags`

## Usage

```python
from logic.validator import validate_clauses

contradictions = validate_clauses(clauses)
for c in contradictions:
    print(c["clause_a"], "vs", c["clause_b"])
    print(c["z3_proof"])
    print(c["attacker"])
```
