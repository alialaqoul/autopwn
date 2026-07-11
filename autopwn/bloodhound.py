# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""BloodHound-collection-driven escalation-path analysis — no CE server required.

Parses a ``bloodhound-python`` collection (the ``*_bloodhound.zip`` Autopwn
already produces) into a directed graph of AD principals and the *abusable* edges
between them, then finds the shortest paths from the engagement's foothold
principal (and any authenticated user) to high-value targets — Domain Admins,
Domain Controllers, or DCSync on the domain. This makes escalation data-driven
(pick the shortest real path) and renders BloodHound-style attack paths in the
console and report, entirely offline (the appliance has no Docker/Neo4j to run
BloodHound Community Edition).
"""
from __future__ import annotations

import glob
import json
import os
import zipfile
from collections import deque
from typing import Optional

# Rights that let the holder take over / abuse the target object (BloodHound edges).
ABUSE_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "WriteAccountRestrictions", "WriteSPN",
    "ReadLAPSPassword", "ReadGMSAPassword",
}
_EDGE_LABEL = {
    "AddKeyCredentialLink": "AddKeyCredentialLink (Shadow Creds)",
    "AllowedToAct": "AllowedToAct (RBCD)",
    "DCSync": "GetChanges + GetChangesAll (DCSync)",
    "ForceChangePassword": "ForceChangePassword",
}
# Well-known high-value RIDs (relative to the domain SID).
_HVT_RIDS = {"512": "Domain Admins", "519": "Enterprise Admins",
             "544": "Administrators", "516": "Domain Controllers",
             "518": "Schema Admins"}
# First abusable edge on a path -> (recommended action, Autopwn tool that runs it).
_ABUSE_TOOL = {
    "AddKeyCredentialLink (Shadow Creds)": ("Add a Key Credential and PKINIT-auth as the target",
                                            "certipy_shadow"),
    "GetChanges + GetChangesAll (DCSync)": ("Replicate directory secrets directly (DCSync)",
                                            "secretsdump"),
    "AllowedToAct (RBCD)": ("Configure resource-based constrained delegation and impersonate",
                            "bloodyad"),
    "ForceChangePassword": ("Reset the target's password, then authenticate as it",
                            "bloodyad"),
    "GenericAll": ("Take full control of the object (reset password / add shadow creds / add to group)",
                   "bloodyad"),
    "GenericWrite": ("Write a targeted attribute (SPN for kerberoast, or key credential)",
                     "targeted_kerberoast"),
    "WriteDacl": ("Grant yourself DCSync/GenericAll on the object, then abuse it",
                  "dacledit"),
    "WriteOwner": ("Take ownership, then grant yourself control", "dacledit"),
    "Owns": ("You own the object — grant yourself control and abuse it", "dacledit"),
    "AddMember": ("Add yourself to the privileged group", "bloodyad"),
    "MemberOf": ("Already a member of the privileged group", ""),
    "WriteAccountRestrictions": ("Configure resource-based constrained delegation (RBCD) and "
                                 "impersonate a privileged user to the target computer", "bloodyad"),
    "AllExtendedRights": ("Read the target's LAPS local-admin password / all extended rights",
                          "netexec_module"),
    "AllExtendedRights (LAPS/DCSync)": ("Read the target's LAPS password / all extended rights",
                                        "netexec_module"),
}
# preference order when picking the strongest single abusable right the foothold holds
_RIGHT_PRIORITY = ["DCSync", "AddKeyCredentialLink", "GenericAll", "WriteAccountRestrictions",
                   "AllExtendedRights", "WriteDacl", "WriteOwner", "Owns", "GenericWrite",
                   "ForceChangePassword", "AllowedToAct", "AddMember"]


def latest_collection(dirs) -> Optional[str]:
    """Newest *_bloodhound.zip across the given dirs (session dir + app cwd)."""
    zs = []
    for d in dirs:
        try:
            zs += glob.glob(os.path.join(str(d), "*_bloodhound.zip"))
        except OSError:
            pass
    return max(zs, key=os.path.getmtime) if zs else None


def load(zip_path):
    """Parse a collection into (nodes, edges, domain_sid). nodes: sid->{name,type};
    edges: list of (src_sid, dst_sid, right)."""
    data = {}
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            for kind in ("users", "groups", "computers", "domains"):
                if n.endswith(f"_{kind}.json"):
                    try:
                        data[kind] = json.loads(z.read(n))
                    except (json.JSONDecodeError, KeyError):
                        pass
    nodes: dict = {}
    edges: list = []

    def node(sid, name, typ):
        if sid:
            nodes.setdefault(sid, {"name": name or sid, "type": typ})

    domain_sid = None
    for o in data.get("domains", {}).get("data", []):
        domain_sid = domain_sid or o.get("ObjectIdentifier")

    # DCSync is GetChanges *and* GetChangesAll on the domain — track the pair.
    domain_repl: dict = {}
    for kind, typ in (("users", "User"), ("groups", "Group"),
                      ("computers", "Computer"), ("domains", "Domain")):
        for o in data.get(kind, {}).get("data", []):
            sid = o.get("ObjectIdentifier")
            props = o.get("Properties") or {}
            node(sid, props.get("name"), typ)
            is_domain = (typ == "Domain")
            for a in (o.get("Aces") or []):
                r = a.get("RightName")
                psid = a.get("PrincipalSID")
                if not psid:
                    continue
                if is_domain and r in ("GetChanges", "GetChangesAll"):
                    domain_repl.setdefault(psid, set()).add(r)
                    node(psid, psid, a.get("PrincipalType", "Base"))
                    continue
                if r in ABUSE_RIGHTS and psid != sid:   # skip self-loops (admin owns self)
                    node(psid, psid, a.get("PrincipalType", "Base"))
                    edges.append((psid, sid, r))
            for p in (o.get("AllowedToAct") or []):
                psid = p.get("ObjectIdentifier") if isinstance(p, dict) else p
                if psid and psid != sid:
                    node(psid, psid, "Base")
                    edges.append((psid, sid, "AllowedToAct"))
    # synthetic DCSync edge for principals holding both replication rights
    for psid, rights in domain_repl.items():
        if {"GetChanges", "GetChangesAll"} <= rights and domain_sid:
            edges.append((psid, domain_sid, "DCSync"))
    # group membership: member -> group
    for o in data.get("groups", {}).get("data", []):
        gsid = o.get("ObjectIdentifier")
        for m in (o.get("Members") or []):
            msid = m.get("ObjectIdentifier")
            if msid:
                edges.append((msid, gsid, "MemberOf"))
    return nodes, edges, domain_sid


def high_value(nodes, domain_sid) -> dict:
    """High-value target SIDs -> label (Domain Admins / DCs / domain for DCSync)."""
    hv = {}
    if domain_sid:
        hv[domain_sid] = "Domain (DCSync)"
    for sid in nodes:
        if domain_sid and sid.startswith(domain_sid + "-"):
            rid = sid.rsplit("-", 1)[-1]
            if rid in _HVT_RIDS:
                hv[sid] = _HVT_RIDS[rid]
    return hv


def _principal_sid(nodes, name) -> Optional[str]:
    if not name:
        return None
    n = name.lower()
    for sid, meta in nodes.items():
        nm = (meta.get("name") or "").lower()
        if nm == n or nm.split("@")[0] == n:
            return sid
    return None


def escalation_paths(nodes, edges, owned_sids, hvts, max_len=8, max_paths=10):
    """Shortest abusable paths from any owned principal to a high-value target."""
    adj: dict = {}
    for s, d, r in edges:
        adj.setdefault(s, []).append((d, r))
    prev: dict = {}
    q = deque()
    for s in owned_sids:
        if s:
            prev[s] = None
            q.append(s)
    while q:
        cur = q.popleft()
        for (nxt, r) in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = (cur, r)
                q.append(nxt)
    out = []
    for hvt, label in hvts.items():
        if hvt in prev and prev[hvt] is not None:
            chain = []
            node = hvt
            while prev.get(node):
                p, r = prev[node]
                chain.append((p, r, node))
                node = p
            chain.reverse()
            if 0 < len(chain) <= max_len:
                out.append({
                    "target": hvt, "target_name": nodes.get(hvt, {}).get("name", hvt),
                    "target_label": label, "length": len(chain),
                    "edges": [{"from": nodes.get(a, {}).get("name", a),
                               "from_type": nodes.get(a, {}).get("type", "Base"),
                               "right": _EDGE_LABEL.get(r, r),
                               "to": nodes.get(b, {}).get("name", b),
                               "to_type": nodes.get(b, {}).get("type", "Base")}
                              for a, r, b in chain]})
    out.sort(key=lambda x: x["length"])
    return out[:max_paths]


def recommend(paths) -> Optional[dict]:
    """From the shortest path, the recommended abuse action + the tool that runs it."""
    if not paths:
        return None
    top = paths[0]
    first = top["edges"][0]["right"]
    key = first.split(" (")[0] if first in _ABUSE_TOOL else first
    action, tool = _ABUSE_TOOL.get(first) or _ABUSE_TOOL.get(key) or ("Abuse the first edge on the path", "")
    return {"path_to": top["target_label"], "length": top["length"],
            "first_edge": first, "action": action, "tool": tool}


def _control_action(right):
    return (_ABUSE_TOOL.get(right) or _ABUSE_TOOL.get(_EDGE_LABEL.get(right, right))
            or ("Abuse this right over the target", ""))


def analyze(dirs, foothold_name=None) -> dict:
    """End-to-end: newest collection -> shortest ACL paths from the foothold (and
    Domain Users) to a high-value target, the foothold's direct abusable control,
    and a data-driven escalation recommendation."""
    zp = latest_collection(dirs)
    if not zp:
        return {"collected": False}
    try:
        nodes, edges, domain_sid = load(zp)
    except (zipfile.BadZipFile, OSError) as e:
        return {"collected": False, "error": str(e)}
    hvts = high_value(nodes, domain_sid)
    fsid = _principal_sid(nodes, foothold_name)
    owned = [s for s in ([fsid] if fsid else []) +
             ([domain_sid + "-513"] if domain_sid else []) if s in nodes]
    paths = escalation_paths(nodes, edges, set(owned), hvts)

    # First-degree abusable control the foothold directly holds (opportunities).
    control = []
    if fsid:
        seen = set()
        for s, d, r in edges:
            if s == fsid and (d, r) not in seen:
                seen.add((d, r))
                label = _EDGE_LABEL.get(r, r)
                action, tool = _control_action(r)
                control.append({"target": nodes.get(d, {}).get("name", d),
                                "target_type": nodes.get(d, {}).get("type", "Base"),
                                "right": label, "action": action, "tool": tool})

    rec = recommend(paths)
    if not rec and control:
        def _pri(c):
            return next((i for i, p in enumerate(_RIGHT_PRIORITY)
                         if c["right"].startswith(p)), 99)
        best = min(control, key=_pri)
        rec = {"path_to": best["target"], "length": 1, "first_edge": best["right"],
               "action": best["action"], "tool": best["tool"]}

    if paths:
        summary = (f"{len(paths)} abusable ACL path(s) from the foothold to a high-value "
                   "target were found.")
    elif control:
        summary = (f"No pure-ACL path to Domain Admin, but the foothold directly controls "
                   f"{len(control)} object(s) — abusable footholds for further escalation.")
    else:
        summary = ("No abusable ACL paths from the foothold — the achieved domain compromise "
                   "used coercion + NTLM relay (AD CS ESC8), not an ACL edge.")

    return {"collected": True, "collection": os.path.basename(zp),
            "domain": nodes.get(domain_sid, {}).get("name", ""),
            "foothold": foothold_name, "foothold_found": bool(fsid),
            "counts": {"nodes": len(nodes), "edges": len(edges), "high_value": len(hvts)},
            "paths": paths, "foothold_control": control,
            "recommendation": rec, "summary": summary}


if __name__ == "__main__":  # quick CLI test: python -m autopwn.bloodhound <dir> <foothold>
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    fh = sys.argv[2] if len(sys.argv) > 2 else None
    print(json.dumps(analyze([d], fh), indent=2)[:4000])
