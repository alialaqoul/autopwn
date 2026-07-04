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
import re
from pathlib import Path

_KB_DIR = Path(__file__).parent / "knowledge"

# A chunk may declare preconditions so retrieval reflects the ACTUAL situation,
# not just text similarity:  <!-- when: port:88, port:445, fact:smb_guest -->
_WHEN_RE = re.compile(r"<!--\s*when:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)


def _cosine(a, b) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _parse_conds(text: str) -> dict:
    """Extract {ports:set[int], facts:set[str]} from a chunk's `when:` tag."""
    ports: set[int] = set()
    facts: set[str] = set()
    m = _WHEN_RE.search(text)
    if m:
        for tok in re.split(r"[,\s]+", m.group(1)):
            tok = tok.strip().lower()
            if tok.startswith("port:") and tok[5:].isdigit():
                ports.add(int(tok[5:]))
            elif tok.startswith("fact:") and tok[5:]:
                facts.add(tok[5:])
    return {"ports": ports, "facts": facts}


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
        self.conds: list[dict] = []
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
        self.conds = [_parse_conds(c) for c in self.chunks]
        return True

    def retrieve(self, query: str, k: int = 3, state: dict | None = None) -> list[str]:
        """Return the top-k chunks. When `state` (open ports + present facts) is
        given, chunks whose declared preconditions match the real situation are
        boosted, so retrieval tracks tool results — not just text similarity."""
        if not self.ok or not self.vecs:
            return []
        try:
            qv = self.provider.embed([query])[0]
        except Exception:
            return []
        st_ports = set(state.get("ports", ())) if state else set()
        st_facts = set(state.get("facts", ())) if state else set()

        def score(i: int) -> float:
            s = _cosine(qv, self.vecs[i])
            if state is not None:
                c = self.conds[i]
                need_p, need_f = c["ports"], c["facts"]
                if need_p or need_f:
                    total = len(need_p) + len(need_f)
                    hit = len(need_p & st_ports) + len(need_f & st_facts)
                    if hit:
                        s += 0.20 * (hit / total)           # boost matched context
                    # a chunk gated on a fact we lack is probably premature
                    if need_f and not (need_f & st_facts):
                        s -= 0.05
            return s

        order = sorted(range(len(self.chunks)), key=score, reverse=True)
        return [self.chunks[i] for i in order[:k]]

    def learn(self, title: str, body: str) -> None:
        """Append a distilled, genericised playbook learned from a successful run
        to the knowledge corpus so future retrievals can use it."""
        path = self.dir / "learned.md"
        try:
            new = not path.exists()
            with open(path, "a", encoding="utf-8") as f:
                if new:
                    f.write("# Learned playbooks\n\n"
                            "Auto-distilled from successful engagements.\n")
                f.write(f"\n## {title}\n{body.strip()}\n")
        except Exception:
            pass
