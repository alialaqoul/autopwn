# Web attack techniques (injection, auth, API, upload)

Deeper tradecraft for the `web-injection`, `wordpress-attack` and `cve-web-check`
playbooks. Fingerprint first (`http_probe`, `whatweb`, `httpx`) and only test what
the stack actually is.

## Parameter and endpoint discovery
<!-- when: port:80 -->
- `arjun` on any parameterised page: hidden GET/POST parameters are the inputs for
  every injection test. Re-run per interesting path (`/search`, `/api/...`).
- `katana` crawls the app and extracts JS endpoints (`-jc`); `gau` adds historical
  URLs from archives. Both feed `ffuf`/`arjun` with real paths instead of guesses.
- Map the client-side JS of SPAs for `/api/...` routes; test each for missing
  authentication and object-level authorization (IDOR: change ids, not just values).

## Injection classes (test in this order)
- **SQLi**: `sqlmap -u <url>` (add `--data` for POST, `--level 3` when a form looks
  promising). On a hit: `--dbs` then `--dump` for user tables; crack dumped hashes
  with `crack_hashes` and pivot them with `netexec_spray`. On MSSQL backends,
  `--os-shell` / xp_cmdshell is direct RCE.
- **OS command injection**: `commix --url <url>` — the highest-severity class; a
  confirmed hit is remote code execution as the web service account.
- **XSS**: `dalfox url <url>` — proves reflected/DOM XSS with a working PoC; pair
  with a session-theft narrative for the report.
- **SSTI / template injection**: error-based probes (`{{7*7}}`, `${7*7}`) on
  parameters of template-heavy apps (Jinja2/Twig/Freemarker) — confirm manually.

## Authentication and session attacks
- Login forms: test a handful of default/known creds by hand first; only then a
  small `hydra http-post-form` run with the form string (never a full brute force).
- JWT: capture the token from a login and run `jwt_tool <token>` locally — alg
  confusion (RS256→HS256 with the public key), `alg:none`, weak HMAC secrets, and
  claim tampering (`"role":"admin"`).
- Session cookies: missing HttpOnly/Secure/SameSite, predictable session ids, and
  long-lived "remember me" tokens are reportable even without a PoC.

## File upload → RCE
- Find upload endpoints via `ffuf`/crawl. Test: double extension (`.php.jpg`),
  content-type swap, null byte, SVG-with-script (stored XSS), and path traversal in
  the filename. If the upload is web-accessible, request the uploaded file.
- IIS: try `.asp;.jpg` / `.aspx` shortname tricks (tilde enumeration); Apache:
  `.htaccess` override when allowed.

## CMS-specific
- WordPress: `wpscan -e vp,u` (vulnerable plugins + users), then `nuclei_cve`
  against the site; brute force `wp-login.php` only with the enumerated user list.
- Known product + version (any CMS/framework): `searchsploit "<product> <version>"`
  plus `nuclei_cve` — known CVEs beat manual testing for speed.
