# General methodology

## Recon and fingerprinting
Always start by fingerprinting the target so later choices are evidence-based.
Use `nmap_scan` with profile `default` (service/version detection) — never assume
the host role. Read the open ports, services, and version banners to classify the
host before enumerating. If nmap is unavailable use `native_port_scan`.

## Identifying the host role from open ports
- 53 (DNS) + 88 (Kerberos) + 389/636 (LDAP) + 445 (SMB) + 3268 (Global Catalog)
  => Active Directory Domain Controller. Follow the Active Directory playbook.
- 445 + 139 (and Windows banners) without Kerberos => Windows / file server.
- 80/443/8080/8443 with an HTTP server banner (Apache/nginx/IIS) => web server.
- 3389 => RDP exposed; 5985/5986 => WinRM; 22 => SSH.
- 1433 MSSQL, 3306 MySQL, 5432 Postgres, 27017 Mongo, 6379 Redis => database.

## Enumerate, then analyse, then act
For each open service pick the matching enumeration tool, run it, and read the
output before deciding the next step. Chain findings: an open port implies a
service to enumerate; a discovered domain implies AD attacks; a discovered
credential implies authenticated actions. Do not run tools that do not match any
open port on the target.

## Interpreting tool output
- "Null Auth: True" / "Anonymous login successful" on SMB => null sessions are
  allowed; enumerate shares and users without credentials.
- "signing:False" on SMB => SMB signing not required (NTLM relay candidate).
- A discovered domain (e.g. cyberlab.local) => set it for Kerberos tools.
- An exit code / "bad arguments" => the tool needs more inputs; supply them or
  choose a different technique. Do not repeat the same failing call.

## Assess the whole environment, then find the weak link
A single hardened host (e.g. a DC that denies null enumeration) is rarely the way
in. Enumerate the WHOLE authorized range first — the foothold is usually the
weakest host: an exposed web application, a default/old service, or a member
server with SMB signing disabled. Typical chain: web app or service => initial
credential/foothold => then Active Directory attacks (Kerberoast, BloodHound,
relay, secretsdump) using that credential. Note domains with MULTIPLE domain
controllers (primary + secondary) — enumerate and attack all of them.

## Finishing
When you have enumerated the exposed services and identified attack paths, set
action to finish and summarise: host role, concrete findings actually observed,
and the most likely attack paths.
