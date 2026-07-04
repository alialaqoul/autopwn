# Active Directory / Domain Controller playbook

## When to use
Apply this when the target exposes Kerberos (88), LDAP (389/636), Global Catalog
(3268/3269), and SMB (445) — i.e. a Domain Controller. First learn the domain
name (it appears in nmap LDAP banners and NetExec output, e.g. corp.local).

## Step 1 — unauthenticated SMB/LDAP enumeration (no creds needed)
- `netexec_smb` with just target: reveals OS, hostname, domain, SMB signing, and
  whether null authentication is allowed. Look for "(domain:...)",
  "(signing:True/False)" and "Null Auth: True".
- `smbclient_shares` and `smbmap`: list shares reachable anonymously.
- `enum4linux`: broad users/groups/shares/policy enumeration.
- `ldapsearch_anon` with base_dn derived from the domain
  (corp.local => DC=corp,DC=local): test anonymous LDAP bind. `netexec_ldap`
  does the same with more structure.

## The reality of a hardened DC (tested)
On a modern, hardened Domain Controller, unauthenticated enumeration is usually
locked down even though a null session is "accepted":
- `netexec_smb -u '' -p '' --users` / `--shares` => STATUS_ACCESS_DENIED (no data).
- RID cycling `netexec_smb -u guest -p '' --rid-brute` => usually blocked/empty
  (guest disabled).
- Anonymous LDAP (`ldapsearch -x -s base`) reads only the ROOT DSE
  (defaultNamingContext, dnsHostName) — object/user queries return
  "Operations error" without a bind.
So do NOT assume "Null Auth: True" yields users or shares. When it doesn't, the
remaining no-credential paths are: Kerberos user enumeration, AS-REP roasting of
KNOWN usernames, and abusing weak SMB signing on member servers. Realistically
you often need an initial foothold/credential from elsewhere (a web app, a
service, phishing) before AD attacks become productive.

## Step 2 — username enumeration (no creds needed)
- `kerbrute_userenum` with the domain and a usernames wordlist validates which
  accounts exist via Kerberos pre-auth, without causing lockouts. It is fast
  (10k names in ~1s). A hardened lab may use non-default usernames, so common
  lists (top-usernames, first-names) can return 0 valid — try larger/targeted
  lists and names derived from context (org name, host naming scheme, service
  accounts like svc_sql, backup, ldap). Needs seclists installed
  (/usr/share/seclists/Usernames/...).
- RID-cycling is often the BEST way to get the real user list: if the `guest`
  account is enabled (no password) or you have any creds, `netexec_rid_brute`
  enumerates every domain user by walking RIDs (SidTypeUser). This returns the
  actual account names (not guesses) — save them to a file for spraying. Always
  try `guest`/null first (`netexec_smb -u guest -p ''`).

## Step 2b — password spraying (batch, never one-by-one)
- With a real user list, `netexec_spray` tests many accounts in ONE server-side
  batch with `--no-bruteforce` (one attempt per user → no lockout). Do NOT guess
  passwords one at a time in the agent loop.
- The highest-yield first spray is `userpass='true'` (username == password): weak
  labs and real environments seed accounts like `bmarley:bmarley`. It frequently
  yields the initial foothold.
- After you crack ANY password (e.g. a service account), spray that same password
  across all users with `password=<cracked>` to find reuse — a common path to a
  privileged account.

## SMB signing and NTLM relay (member servers)
Check `signing` on EVERY host from the netexec_smb banner. Domain Controllers
require signing (signing:True). Member servers frequently have
`signing:False` — these are NTLM/SMB relay targets: capture a victim's NTLM
authentication (e.g. Responder poisoning LLMNR/NBT-NS/mDNS) and relay it with
impacket ntlmrelayx to the signing-disabled host for command execution or a
SAM/secrets dump. Enumerate relay targets with
`netexec smb <range> --gen-relay-list targets.txt`.

## Step 3 — AS-REP roasting (no creds needed)
- `asrep_roast` (impacket GetNPUsers) requests tickets for accounts that have
  "Do not require Kerberos pre-authentication" set. It needs the domain and a
  usernames file. Output hashes are crackable offline with `hashcat` (mode 18200)
  or `john`. This is a top no-credential AD attack path.

## Step 4 — with any valid credential
- `kerberoast` (impacket GetUserSPNs) requests service-ticket hashes for accounts
  with SPNs; crack offline (hashcat mode 13100). Needs domain + username +
  password.
- `netexec_ldap`/`netexec_smb` with -u/-p: enumerate users, groups, and shares
  authenticated; check for further access.
- `netexec_winrm` with creds: confirm remote command execution (WinRM 5985).

## Step 4b — loot readable shares for credentials
- With any credential, re-check shares (`netexec_smb enumerate=shares`). Beyond
  the defaults (SYSVOL/NETLOGON), a custom READ share (backup, IT, transfer) is a
  classic credential leak. Pull interesting files with `smb_get` (share + path).
- A common find is a `secretsdump`-style export of NTLM hashes, including MACHINE
  accounts (`NAME$:RID:LM:NT:::`). Any such hash is usable for pass-the-hash.

## Step 4c — pass-the-hash to escalate
- Try each recovered hash against the DC with `netexec_smb -u <acct> -H <nt>`.
  Watch for `Pwn3d!` — that account is a local admin on the target. Machine
  accounts (`FileServer$`) are sometimes over-privileged and grant admin on the DC.
- Once an account shows `Pwn3d!`, run commands with `netexec_smb command=...`, read
  the flag/loot from the `C$` share, or DCSync with `secretsdump -hashes :<nt>`.

## Step 5 — escalate and dump
- Once a privileged account is obtained, `secretsdump` dumps SAM/NTDS/LSA secrets
  (and supports DCSync against a DC). This yields domain hashes for lateral
  movement and persistence.

## Worked chain (no creds → Domain Admin) — reference
1. `netexec_smb -u guest -p ''` → guest enabled.
2. `netexec_rid_brute` (guest) → full user list (save to users.txt).
3. `netexec_spray userfile=users.txt userpass=true` → foothold user==password.
4. `kerberoast` with that user → service-ticket hashes.
5. `john`/`hashcat` (mode 13100) + rockyou → cracked service-account password.
6. `netexec_smb enumerate=shares` → readable `backup` share; `smb_get` the file →
   machine-account NTLM hashes.
7. `netexec_smb -u <machine>$ -H <nt>` → `Pwn3d!` (admin on DC).
8. Read the flag from `C$` (or `secretsdump` for domain hashes).

## Credential flow
Autopwn captures a username/password automatically from a NetExec success line
("[+] domain\\user:pass"). Once captured, the credentialed tools above become
available and are auto-filled with the domain/creds.
