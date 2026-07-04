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

## Step 5 — escalate and dump
- Once a privileged account is obtained, `secretsdump` dumps SAM/NTDS/LSA secrets
  (and supports DCSync against a DC). This yields domain hashes for lateral
  movement and persistence.

## Credential flow
Autopwn captures a username/password automatically from a NetExec success line
("[+] domain\\user:pass"). Once captured, the credentialed tools above become
available and are auto-filled with the domain/creds.
