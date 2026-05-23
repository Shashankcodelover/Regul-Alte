# Memory Subsystem

The Memory subsystem provides **RAG-based citation verification** and **hallucination detection** for the RegulAIte pipeline.

## Components

### InMemoryRAG (`rag.py`)
Indexes all contract clauses using vector embeddings and verifies agent claims against them via cosine similarity.

- **Primary**: sentence-transformers `all-MiniLM-L6-v2` (384-dim embeddings)
- **Fallback**: TF-IDF cosine similarity (numpy only, no external dependencies)
- **Threshold**: `SIMILARITY_THRESHOLD = 0.55` — claims above this are considered verified

### CitationGraph (`citation_graph.py`)
Tracks which agent claims cite which clauses using a directed graph.

- **Primary**: NetworkX DiGraph
- **Fallback**: Python dict-based storage
- Computes hallucination rate = unverified claims / total claims

### MemoryBridge (`bridge.py`)
Connects the RAG and CitationGraph to the agent pipeline.

- `__init__(clauses)`: indexes clauses in RAG
- `verify_claim(agent_name, claim)`: verifies a single claim
- `verify_batch(agent_name, claims)`: verifies multiple claims
- `get_summary()`: returns hallucination stats

## Usage

```python
from memory.bridge import MemoryBridge

bridge = MemoryBridge(clauses)
result = bridge.verify_claim("risk_scorer", "This clause limits vendor liability")
print(result["verified"])          # True/False
print(result["confidence_score"])  # 0.0-1.0
print(result["source_clause_id"]) # e.g. "clause_7.1"

summary = bridge.get_summary()
print(summary["hallucination_rate"])  # e.g. 0.25 = 25% unverified
```

## Graceful Fallback

- If `sentence-transformers` is not installed → uses TF-IDF
- If `networkx` is not installed → uses dict-based citation tracking
- All functionality works without any optional dependencies
