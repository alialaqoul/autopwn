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
<!-- when: port:445, fact:has_users -->
The single fastest way to root an AD lab: call `ad_kill_chain` with the DC target
to run guest -> RID -> spray -> Kerberoast -> crack -> loot -> pass-the-hash end
to end. Use the individual tools below when you need finer control.
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
<!-- when: port:88, fact:has_users -->
- `asrep_roast` (impacket GetNPUsers) requests tickets for accounts that have
  "Do not require Kerberos pre-authentication" set. It needs the domain and a
  usernames file. Output hashes are crackable offline with `hashcat` (mode 18200)
  or `john --format=krb5asrep`. This is a top no-credential AD attack path — and
  the FALLBACK FOOTHOLD when guest is disabled and RID cycling is blocked.
- The cracked AS-REP password is a real domain credential — use it to Kerberoast,
  spray, and enumerate further. `ad_kill_chain` does this automatically.

## Hardened DC: guest disabled — how to still get in
<!-- when: port:88, port:445 -->
Many real/CTF DCs disable `guest` (STATUS_ACCOUNT_DISABLED) and restrict
anonymous LDAP, so null-session RID cycling returns nothing. Get a user list
another way, then roast:
1. `kerbrute_userenum` with a names wordlist (first.last, service-account names)
   — Kerberos pre-auth validation, no lockout, no creds needed.
2. AS-REP roast the discovered users (`asrep_roast`) → crack → foothold.
3. With any foothold cred, do an authenticated `netexec_ldap --users` to get the
   COMPLETE user list, then Kerberoast and re-roast for more creds.

## Multi-domain / multi-forest (e.g. a parent + child + a trusted forest)
Enumerate and roast EACH domain separately — users, SPNs, and AS-REP flags differ
per domain, and each has its own DC. AS-REP/Kerberoast against domain A's DC with
domain B's user list returns nothing. After compromising one domain, pivot across
the trust (SID history / cross-forest Kerberoast / delegation) to the others.

## Constrained/unconstrained delegation → escalation
If a Kerberoastable (or otherwise owned) account shows `constrained` or
`unconstrained` delegation, that is a privilege-escalation path: crack/own the
account, then `get_st -spn <target> -impersonate Administrator` (S4U2Proxy) to
mint a ticket as a privileged user to the delegated service, and use it with `-k`.

## Step 4 — with any valid credential
- `kerberoast` (impacket GetUserSPNs) requests service-ticket hashes for accounts
  with SPNs; crack offline (hashcat mode 13100). Needs domain + username +
  password.
- `netexec_ldap`/`netexec_smb` with -u/-p: enumerate users, groups, and shares
  authenticated; check for further access.
- `netexec_winrm` with creds: confirm remote command execution (WinRM 5985).

## Step 4b — loot readable shares for credentials
<!-- when: port:445, fact:username -->

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
<!-- when: port:88, port:445 -->
Shortcut: `ad_kill_chain target=<DC>` performs all of the following automatically
and returns the credentials, admin access, and any flags it captured.
1. `netexec_smb -u guest -p ''` → guest enabled.
2. `netexec_rid_brute` (guest) → full user list (save to users.txt).
3. `netexec_spray userfile=users.txt userpass=true` → foothold user==password.
4. `kerberoast` with that user → service-ticket hashes.
5. `john`/`hashcat` (mode 13100) + rockyou → cracked service-account password.
6. `netexec_smb enumerate=shares` → readable `backup` share; `smb_get` the file →
   machine-account NTLM hashes.
7. `netexec_smb -u <machine>$ -H <nt>` → `Pwn3d!` (admin on DC).
8. Read the flag from `C$` (or `secretsdump` for domain hashes).

## Assumed-breach / authenticated engagements
Many real tests start WITH a credential ("assumed breach"). Provide it up front —
`agent --target <dc> --username <u> --password <p> --domain <d>` (or the menu's
"Starting credentials" prompt). The creds seed the store, so every credentialed
tool and the agent use them from step one. With a foothold user, always run the
authenticated enumeration: BloodHound (`bloodhound_python`), `kerberoast`,
`netexec_ldap --users`, share/SYSVOL looting, and check delegation / RBCD rights.

## Finding the next credential (lateral movement)
When you have one user but no ACL path to the target, the next credential is
usually hidden, not crackable:
- Loot readable shares and SYSVOL/NETLOGON for scripts, configs, GPP cpassword,
  and credential stores (`.kdbx` KeePass DBs, `.xml`, `unattend`, `web.config`).
- **Password reuse is the most common bridge** — once you recover ANY password
  (from a share, a KeePass DB, a cracked hash), spray it across every user with
  `netexec_spray password=<pw>`. Help-desk / service accounts frequently share one.
- Check user `description`/`info`/`comment` LDAP attributes for passwords.

## RBCD to Domain Admin (write over a computer + MachineAccountQuota)
<!-- when: port:88, port:445, fact:username -->
If a controllable account can write `msDS-AllowedToActOnBehalfOfOtherIdentity`
on a computer (BloodHound edge `AddAllowedToAct`/`GenericWrite`/`GenericAll` over
a Computer — often the DC), you get Domain Admin via Resource-Based Constrained
Delegation:
1. `add_computer` — create a machine account (needs MachineAccountQuota>0; check
   with `netexec_ldap -M maq`). Default ATTACK$ / Attack123!.
2. `rbcd` — as the account with write rights, delegate-from your new computer,
   delegate-to the target computer (e.g. DC01$), action write.
3. `get_st` — as your new computer, request a ticket with `-spn cifs/<dc.fqdn>
   -impersonate Administrator` (S4U2Proxy). It saves a `.ccache`.
4. Use the ticket: `export KRB5CCNAME=<file>.ccache` then `secretsdump -k
   -no-pass <dc.fqdn>` (DCSync) or read `C$` with Kerberos auth. Add the DC FQDN
   to /etc/hosts and sync the clock to the DC (Kerberos is time-sensitive).
This does NOT need the target computer's password — only write access to its
delegation attribute plus a machine account you create.

## Credential flow
Autopwn captures a username/password automatically from a NetExec success line
("[+] domain\\user:pass"). Once captured, the credentialed tools above become
available and are auto-filled with the domain/creds.
