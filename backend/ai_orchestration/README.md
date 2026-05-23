# AI Orchestration Pipeline

Multi-agent legal contract analysis pipeline for RegulAIte.

## Architecture

```
contract_text
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 1: ClauseExtractor (extractor.py)                │
│  • Regex-based clause segmentation                      │
│  • Handles numbered, lettered, roman numeral clauses    │
│  • Paragraph fallback if < 3 clauses found              │
│  • NO API CALL — pure Python                            │
└────────────────────────┬────────────────────────────────┘
                         │ List[{number, text, section}]
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 2: RiskScorer (risk_scorer.py)                   │
│  • Step 1: Deterministic pre-scoring (legal_patterns)   │
│  • Step 2: Parallel Claude calls for score >= 40        │
│  • Step 3: final = max(base_score, claude_score)        │
│  • Adds: risk_score, risk_level, issues, plain_english  │
└────────────────────────┬────────────────────────────────┘
                         │ Scored clauses
                    ┌────┴────┐
                    ▼         ▼
┌──────────────┐  ┌──────────────────────────────────────┐
│  Agent 3     │  │  Agent 4: ComplianceChecker          │
│  Contradiction│  │  • 25+ regex patterns (GDPR, ICA,   │
│  Detector    │  │    DPDP Act, Industrial Disputes)    │
│  • Z3 formal │  │  • Claude enrichment for penalties   │
│    proof     │  │  • Returns {law, clause, penalty}    │
│  • Claude    │  └──────────────────────────────────────┘
│    semantic  │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 5: ClauseRewriter (rewriter.py)                  │
│  • Rewrites clauses with risk_score >= 40               │
│  • Validates: longer than original, no unbalanced       │
│    "sole discretion" / "without notice"                 │
│  • risk_score < 40: rewritten = original                │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  pipeline.py: Assembly                                  │
│  • overall_risk_score (weighted average)                │
│  • jurisdiction detection (regex)                       │
│  • contract_completeness (standard sections check)      │
│  • party_bias (0=client favored, 100=vendor favored)    │
│  • missing_clauses (standard types not found)           │
│  • key_dates (regex extraction)                         │
│  • summary (Claude 2-sentence or fallback)              │
│  • Saves clauses to in-memory store                     │
└─────────────────────────────────────────────────────────┘
```

## Tools

| Tool | Purpose | API? |
|------|---------|------|
| `legal_patterns.py` | 40+ regex patterns for risk scoring + 25+ legal citation patterns | No |
| `z3_checker.py` | Z3 SMT solver for formal contradiction proof | No |
| `rag_verifier.py` | In-memory RAG with cosine similarity for claim verification | No (uses numpy) |

## No API Key Mode

All agents work without an Anthropic API key:
- Agent 1: Pure regex — always works
- Agent 2: Deterministic pre-scoring only (no Claude refinement)
- Agent 3: Z3 formal proof only (no Claude semantic detection)
- Agent 4: Regex pattern matching only (no Claude enrichment)
- Agent 5: Returns original text (no rewrites)

## Clause Storage

After each analysis, clauses are saved to an in-memory store accessible via:
```
GET /clauses
```
Returns the extracted and scored clauses from the last analysed contract.

## Adding New Patterns

To add new risk patterns, edit `tools/legal_patterns.py`:
```python
PRE_SCORE_PATTERNS.append(
    (r"\byour_pattern\b", "flag_name", score_value, "Human reason")
)
```

To add new legal citations:
```python
LEGAL_CITATIONS.append(
    (r"\byour_pattern\b", "Violation Type", severity, "Law Ref", "Description", "Penalty")
)
```
