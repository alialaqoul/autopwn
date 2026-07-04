# Web application playbook

## When to use
Apply this when a port serves a real HTTP application (Apache/nginx/IIS or an app
banner). Do NOT treat Windows RPC-over-HTTP (ncacn_http), WinRM/HTTPAPI (5985),
WSDAPI (5357), or agent services (e.g. McAfee 8081) as web apps — they are not
browsable and web content tools will fail against them.

## Step 1 — fingerprint
- `whatweb` and `http_probe`: server, technologies, title, and security headers.
- `httpx`: quickly confirm the service is live and detect technologies/status.
  Use the fingerprint to pick the next tool (e.g. WordPress => wpscan).

## Step 2 — content and vulnerability discovery
- `feroxbuster` or `ffuf` or `gobuster_dir`: discover hidden directories/files.
  For ffuf put FUZZ in the URL. Use a wordlist appropriate to the app.
- `nuclei`: templated vulnerability checks; filter by severity for signal.
- `nikto`: server misconfigurations and dangerous files.
- `testssl` on HTTPS/TLS ports: weak ciphers, expired/misconfigured certs,
  Heartbleed and other TLS issues.

## Step 3 — application testing
- `arjun`: discover hidden request parameters (feed the results to injection
  testing).
- `sqlmap` on a parameterised URL/POST body: automated SQL injection.
- `wpscan` only if the app is WordPress: vulnerable plugins/themes/users.

## Interpreting output
- 401/403 on interesting paths => try auth bypass / different methods.
- Discovered parameters => test for SQLi/XSS.
- Server/version banners => cross-check `searchsploit` for known exploits.
