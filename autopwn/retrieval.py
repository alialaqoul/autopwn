# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Semantic tool retrieval (RAG) — pass only the most relevant tools per step.

Embeds each tool's name+description once (cached), then at each agent step ranks
tools by cosine similarity to the current situation and returns the top-k. This
both improves selection (a small model picks from a handful of sharp options,
not 38) and speeds inference (a much shorter prompt). Falls back gracefully to
"all tools" if the embedding model is unavailable.
"""
from __future__ import annotations

import math


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class ToolRetriever:
    def __init__(self, provider, tools):
        self.provider = provider
        self.tools = list(tools)
        self._vecs: list[list[float]] | None = None
        self._ok = hasattr(provider, "embed")

    def _ensure(self) -> bool:
        if not self._ok:
            return False
        if self._vecs is None:
            docs = [f"{t.name}: {t.description} category:{getattr(t,'category','')}"
                    for t in self.tools]
            try:
                self._vecs = self.provider.embed(docs)
            except Exception:
                self._ok = False
                return False
        return True

    def top_k(self, query: str, k: int):
        """Return the k tools most relevant to *query* (or all on any failure)."""
        if k <= 0 or k >= len(self.tools) or not self._ensure():
            return self.tools
        try:
            qv = self.provider.embed([query])[0]
        except Exception:
            return self.tools
        ranked = sorted(zip(self._vecs, self.tools),
                        key=lambda pair: -_cosine(qv, pair[0]))
        return [t for _, t in ranked[:k]]
