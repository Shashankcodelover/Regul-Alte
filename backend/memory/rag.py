"""
rag.py
======
In-memory RAG (Retrieval-Augmented Generation) verifier using numpy
cosine similarity. No external vector database needed.

Uses sentence-transformers all-MiniLM-L6-v2 for embeddings.
Falls back to TF-IDF cosine similarity if sentence-transformers
is not installed or HF hub is offline.
"""

import os
import logging
import numpy as np
from typing import List, Dict, Any, Optional

log = logging.getLogger("regulaite.memory.rag")

# Force offline mode before any HF imports
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

SIMILARITY_THRESHOLD = 0.55


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class TFIDFVectorizer:
    """
    Minimal TF-IDF vectorizer as fallback when sentence-transformers
    is not available. Uses numpy only.
    """

    def __init__(self):
        self.vocab: Dict[str, int] = {}
        self.idf: Optional[np.ndarray] = None
        self._fitted = False

    def _tokenize(self, text: str) -> List[str]:
        import re
        return re.findall(r"\b[a-z]{2,}\b", text.lower())

    def fit(self, texts: List[str]):
        """Fit TF-IDF on a corpus of texts."""
        all_tokens: set = set()
        for t in texts:
            all_tokens.update(self._tokenize(t))
        self.vocab = {tok: i for i, tok in enumerate(sorted(all_tokens))}

        n = len(texts)
        df = np.zeros(len(self.vocab))
        for t in texts:
            tokens = set(self._tokenize(t))
            for tok in tokens:
                if tok in self.vocab:
                    df[self.vocab[tok]] += 1
        self.idf = np.log((n + 1) / (df + 1)) + 1
        self._fitted = True

    def transform(self, text: str) -> np.ndarray:
        """Transform a single text to a TF-IDF vector."""
        if not self._fitted or not self.vocab:
            return np.zeros(1)
        tokens = self._tokenize(text)
        vec = np.zeros(len(self.vocab))
        for tok in tokens:
            if tok in self.vocab:
                vec[self.vocab[tok]] += 1
        if self.idf is not None:
            vec = vec * self.idf
        return vec


class InMemoryRAG:
    """
    In-memory RAG store for clause verification.

    Usage:
        rag = InMemoryRAG()
        rag.index(clauses)          # list of {number, text, id, ...} dicts
        result = rag.verify(claim)  # CitationResult-compatible dict
        results = rag.search(query, top_k=3)
    """

    SIMILARITY_THRESHOLD = SIMILARITY_THRESHOLD

    def __init__(self):
        self._model = None
        self._use_st = False
        self._tfidf: Optional[TFIDFVectorizer] = None
        self._store: List[Dict[str, Any]] = []
        self._indexed = False

    def _load_model(self):
        """Try to load sentence-transformers; fall back to TF-IDF."""
        if self._model is not None or self._tfidf is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._use_st = True
            log.info("Memory RAG: using sentence-transformers all-MiniLM-L6-v2")
        except Exception as exc:
            log.warning(f"Memory RAG: sentence-transformers unavailable ({exc}), using TF-IDF fallback.")
            self._use_st = False

    def _encode(self, text: str) -> np.ndarray:
        """Encode text to a vector."""
        if self._use_st and self._model is not None:
            return self._model.encode(text, convert_to_numpy=True)
        elif self._tfidf is not None and self._tfidf._fitted:
            return self._tfidf.transform(text)
        else:
            return np.zeros(1)

    def index(self, clauses: List[Dict[str, Any]]) -> int:
        """
        Encode all clause texts and store vectors.
        Returns number of clauses indexed.
        """
        self._load_model()
        self._store = []

        texts = [c.get("text", "") for c in clauses]

        if not self._use_st:
            self._tfidf = TFIDFVectorizer()
            self._tfidf.fit(texts)

        for clause, text in zip(clauses, texts):
            vec = self._encode(text)
            self._store.append({"clause": clause, "vector": vec})

        self._indexed = True
        log.info(f"Memory RAG: indexed {len(self._store)} clauses.")
        return len(self._store)

    def verify(self, claim: str) -> Dict[str, Any]:
        """
        Find the most similar clause to the claim.

        Returns CitationResult-compatible dict:
        {verified, confidence_score, source_clause_id, source_text_excerpt, claim}
        """
        if not self._indexed or not self._store:
            return {
                "verified": False,
                "confidence_score": 0.0,
                "source_clause_id": "?",
                "source_text_excerpt": "",
                "claim": claim,
            }

        claim_vec = self._encode(claim)
        best_sim = -1.0
        best_clause = None

        for item in self._store:
            sim = _cosine_similarity(claim_vec, item["vector"])
            if sim > best_sim:
                best_sim = sim
                best_clause = item["clause"]

        verified = best_sim >= self.SIMILARITY_THRESHOLD
        clause_id = (
            best_clause.get("id") or
            f"clause_{best_clause.get('number', '?')}"
            if best_clause else "?"
        )
        excerpt = best_clause.get("text", "")[:200] if best_clause else ""

        return {
            "verified": verified,
            "confidence_score": round(float(best_sim), 4),
            "source_clause_id": clause_id,
            "source_text_excerpt": excerpt,
            "claim": claim,
        }

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Return top_k most similar clauses to the query."""
        if not self._indexed or not self._store:
            return []

        query_vec = self._encode(query)
        scored = []
        for item in self._store:
            sim = _cosine_similarity(query_vec, item["vector"])
            scored.append((sim, item["clause"]))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {"clause": c, "similarity": round(float(s), 4)}
            for s, c in scored[:top_k]
        ]
