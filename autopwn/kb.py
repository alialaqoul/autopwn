# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Knowledge base (RAG) that grounds the agent's decisions in pentest playbooks.

The `knowledge/` folder holds methodology written for Autopwn's own tools. This
module chunks those docs, embeds each chunk once (cached to disk so it's cheap on
later runs), and at each agent step retrieves the few chunks most relevant to the
current situation — so the model knows the right next technique, the correct
command, and how to read the output, instead of guessing.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

_KB_DIR = Path(__file__).parent / "knowledge"


def _cosine(a, b) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _chunk(text: str, source: str) -> list[str]:
    """Split a markdown doc into section chunks (one per '## ' heading)."""
    title = ""
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip(); break
    chunks: list[str] = []
    cur: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if cur:
                chunks.append("\n".join(cur).strip())
            cur = [f"[{title}] {line[3:].strip()}"]
        else:
            cur.append(line)
    if cur:
        chunks.append("\n".join(cur).strip())
    return [c for c in chunks if len(c) > 40]


class KnowledgeBase:
    def __init__(self, provider, kb_dir: Path | None = None):
        self.provider = provider
        self.dir = Path(kb_dir or _KB_DIR)
        self.chunks: list[str] = []
        self.vecs: list[list[float]] = []
        self.ok = hasattr(provider, "embed")

    def _cache_path(self) -> Path:
        return self.dir / ".emb_cache.json"

    def load(self) -> bool:
        """Load and embed the knowledge chunks (using the on-disk cache)."""
        if not self.ok or not self.dir.is_dir():
            return False
        docs = sorted(self.dir.glob("*.md"))
        for f in docs:
            self.chunks += _chunk(f.read_text(encoding="utf-8"), f.stem)
        if not self.chunks:
            return False
        try:
            cache = json.loads(self._cache_path().read_text(encoding="utf-8"))
        except Exception:
            cache = {}
        missing = [c for c in self.chunks
                   if hashlib.sha1(c.encode()).hexdigest() not in cache]
        if missing:
            try:
                embs = self.provider.embed(missing)
            except Exception:
                self.ok = False
                return False
            for c, e in zip(missing, embs):
                cache[hashlib.sha1(c.encode()).hexdigest()] = e
            try:
                self._cache_path().write_text(json.dumps(cache), encoding="utf-8")
            except Exception:
                pass
        self.vecs = [cache[hashlib.sha1(c.encode()).hexdigest()] for c in self.chunks]
        return True

    def retrieve(self, query: str, k: int = 3) -> list[str]:
        if not self.ok or not self.vecs:
            return []
        try:
            qv = self.provider.embed([query])[0]
        except Exception:
            return []
        ranked = sorted(zip(self.vecs, self.chunks),
                        key=lambda p: -_cosine(qv, p[0]))
        return [c for _, c in ranked[:k]]
