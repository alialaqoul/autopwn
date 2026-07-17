# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Management-server tooling — recognise and safely test the enterprise
management / monitoring appliances that dominate real estates.

Two native tools, both **non-destructive** (read-only GETs + ordinary login
attempts; no writes, no exploitation, no persistence):

  * ``product_recon`` — fingerprint a host against ``signatures.PRODUCTS``
    (Trellix ePO, SolarWinds Orion/NPM, Splunk, Acronis Cyber Protect, Tripwire,
    ExtremeCloud IQ Site Engine, WSUS, NPS). Tags the host (``is_<product>``),
    raises an *Exposed management interface* finding carrying the product's CVEs
    and credential-vault loot, and runs the product's **read-only** proof-of-
    access PoC (a GET that confirms an auth-bypass / exposure without changing
    state). Optionally runs nuclei CVE templates against the console.
  * ``default_creds`` — try each product's known default credentials against its
    login endpoint. A login attempt only (no state change); reports which, if
    any, authenticate.

The catalogue is data (`signatures.py`) — adding a product needs no code here.
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from .. import signatures
from .macro import MacroTool, Results

_UA = "Autopwn/1.0 (+management-server recon)"
_TIMEOUT = 8
_NO_VERIFY = ssl.create_default_context()
_NO_VERIFY.check_hostname = False
_NO_VERIFY.verify_mode = ssl.CERT_NONE   # appliances ship self-signed certs

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HIDDEN = re.compile(
    r"""<input[^>]*\btype=["']?hidden["']?[^>]*>""", re.I)
_ATTR = re.compile(r"""\b(name|value)=["']([^"']*)["']""", re.I)


def _http(method: str, url: str, headers: Optional[dict] = None,
          data: Optional[bytes] = None) -> tuple[int, dict, str]:
    """One HTTP(S) request. Returns (status, headers, body_text). Never raises —
    (0, {}, "") on connection error; HTTP error responses come back normally so
    a 401/403/500 body can be inspected."""
    req = urllib.request.Request(url, method=method, data=data,
                                 headers={"User-Agent": _UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_NO_VERIFY) as r:
            body = r.read(200_000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return 0, {}, ""


def _base(prod: signatures.Product, host: str, port: int) -> str:
    scheme = prod.scheme or "https"
    return f"{scheme}://{host}:{port}"


def _form_hidden_inputs(html: str) -> dict:
    """Scrape hidden <input> name/value pairs (ASP.NET __VIEWSTATE, CSRF tokens)
    so a form-login POST is accepted."""
    fields = {}
    for tag in _HIDDEN.findall(html):
        attrs = dict((k.lower(), v) for k, v in _ATTR.findall(tag))
        if attrs.get("name"):
            fields[attrs["name"]] = attrs.get("value", "")
    return fields


# --------------------------------------------------------------------------- #
class ProductReconTool(MacroTool):
    name = "product_recon"
    category = "recon"
    description = ("Fingerprint a host against the management-server catalogue "
                   "(ePO, SolarWinds, Splunk, Acronis, Tripwire, Extreme XIQ SE, "
                   "WSUS, NPS), tag it, and raise an Exposed-management-interface "
                   "finding with the product's CVEs, credential-vault loot and a "
                   "read-only proof-of-access PoC. Non-destructive.")
    plan = [
        "Read the host's scanned ports/banners",
        "Fetch each candidate console's title/Server header (read-only GET)",
        "Match against signatures.PRODUCTS; tag host is_<product>",
        "Run each product's read-only PoC (auth-bypass/exposure confirmation)",
        "Optionally run nuclei CVE templates (cve_scan=true)",
        "Report each exposed product as a finding with CVEs + loot",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to fingerprint."},
            "cve_scan": {"type": "string",
                         "description": "'true' → also run nuclei against each console."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        from .. import store
        host = kw["target"]
        entry = (store.all_hosts() or {}).get(host, {})
        cve_scan = str(kw.get("cve_scan", "")).lower() in ("true", "1", "yes")

        # 1) gather HTTP evidence (titles/Server headers) from candidate consoles
        open_ports = signatures._host_open_ports(entry)
        evidence = []
        for prod in signatures.by_kind("mgmt"):
            if not (open_ports & set(prod.ports)) or not prod.web_port:
                continue
            st, hdrs, body = _http("GET", _base(prod, host, prod.url_port) + "/")
            if st:
                t = _TITLE.search(body)
                evidence.append((t.group(1).strip() if t else "")
                                + " " + hdrs.get("Server", ""))
        found = signatures.identify(entry, " ".join(evidence), kind="mgmt")
        if not found:
            self.log("no management-server products recognised on this host")
            return

        # 2) per detected product: tag, finding, loot, safe PoC, optional nuclei
        for hit in found:
            prod: signatures.Product = hit["product"]
            self.log(f"[+] {prod.name} on {host} — {hit['reason']}")
            store.set_host_fact(host, f"is_{prod.id}", "true")

            poc_note = self._safe_poc(prod, host)
            cve_note = self._nuclei(prod, host) if cve_scan and prod.nuclei else ""

            desc = (f"{prod.name} is exposed on port(s) {', '.join(map(str, hit['ports']))} "
                    f"({hit['reason']}). "
                    + (f"Notable CVEs: {'; '.join(prod.cves)}. " if prod.cves else "")
                    + (f"Impact: {prod.loot}" if prod.loot else "")
                    + (f" {poc_note}" if poc_note else "")
                    + (f" {cve_note}" if cve_note else ""))
            self.add_finding(f"Exposed {prod.name} management interface",
                             prod.severity, description=desc, cvss=prod.cvss)
            if prod.loot:
                self.add_loot(f"{prod.name} @ {host}", prod.loot)

    def _safe_poc(self, prod: signatures.Product, host: str) -> str:
        poc = prod.safe_poc
        if not poc:
            return ""
        url = _base(prod, host, prod.url_port) + poc["path"]
        st, _h, body = _http("GET", url)
        if st and re.search(poc["ok"], body):
            tag = f" ({poc['cve']})" if poc.get("cve") else ""
            self.log(f"  │ PoC confirmed{tag}: {poc.get('desc', '')}")
            return f"Read-only PoC confirmed{tag}: {poc.get('desc', '')}"
        return ""

    def _nuclei(self, prod: signatures.Product, host: str) -> str:
        url = _base(prod, host, prod.url_port)
        self.log(f"  │ nuclei CVE scan → {url}")
        out = self.sub("nuclei", url=url, severity="critical,high,medium")
        hits = [ln for ln in (out or "").splitlines() if "[" in ln and "]" in ln]
        if hits:
            for h in hits[:8]:
                self.log(f"  │   {h.strip()}")
            return f"nuclei flagged {len(hits)} template(s): " \
                   + "; ".join(h.strip()[:120] for h in hits[:4])
        return ""


# --------------------------------------------------------------------------- #
class DefaultCredsTool(MacroTool):
    name = "default_creds"
    category = "credentials"
    description = ("Try each recognised management product's known default "
                   "credentials against its login endpoint (a login attempt only "
                   "— no state change). Reports which, if any, authenticate. "
                   "Non-destructive.")
    plan = [
        "Identify management products on the host (signatures)",
        "For each product with a safe login test, try its default credentials",
        "Report any that authenticate as a credential + finding",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to test."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        from .. import store
        host = kw["target"]
        entry = (store.all_hosts() or {}).get(host, {})
        found = signatures.identify(entry, "")
        if not found:
            self.log("no management products recognised — nothing to test")
            return
        for hit in found:
            prod: signatures.Product = hit["product"]
            if not (prod.login and prod.default_creds):
                continue
            self.log(f"[test] {prod.name} default credentials on {host}")
            for user, pw in prod.default_creds:
                if self._try_login(prod, host, user, pw):
                    shown = pw if pw else "(blank)"
                    self.log(f"  │ [+] VALID default credential: {user}:{shown}")
                    self.add_cred(user, pw, note=f"{prod.name} default credential")
                    self.add_finding(
                        f"Default credentials on {prod.name}: {user}:{shown}",
                        "Critical", cvss="9.8",
                        description=f"{prod.name} accepts the vendor/default "
                                    f"credential {user}:{shown}. {prod.loot}")
                    break   # one working cred per product is enough

    def _try_login(self, prod: signatures.Product, host: str,
                   user: str, pw: str) -> bool:
        login = prod.login or {}
        url = _base(prod, host, prod.url_port) + login.get("path", "/")
        if login.get("type") == "basic":
            import base64
            tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
            st, _h, body = _http("GET", url, headers={"Authorization": f"Basic {tok}"})
            if st in (401, 403) or st == 0:
                return False
            if login.get("fail") and re.search(login["fail"], body):
                return False
            return st == 200 and bool(re.search(login.get("ok", "."), body))
        if login.get("type") == "form":
            # GET the login page to harvest hidden tokens, then submit.
            st, _h, page = _http("GET", url)
            if not st:
                return False
            fields = _form_hidden_inputs(page)
            fields[login["user_field"]] = user
            fields[login["pass_field"]] = pw
            data = urllib.parse.urlencode(fields).encode()
            st2, hdrs2, body2 = _http("POST", url,
                                      headers={"Content-Type": "application/x-www-form-urlencoded"},
                                      data=data)
            if not st2:
                return False
            # success = redirect away from the login page, or no failure marker on a 200
            if st2 in (301, 302, 303) and "login" not in hdrs2.get("Location", "").lower():
                return True
            if st2 == 200 and login.get("fail") and not re.search(login["fail"], body2):
                return True
            return False
        return False
