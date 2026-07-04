# Active Directory / Domain Controller playbook

## When to use
Apply this when the target exposes Kerberos (88), LDAP (389/636), Global Catalog
(3268/3269), and SMB (445) — i.e. a Domain Controller. First learn the domain
name (it appears in nmap LDAP banners and NetExec output, e.g. cyberlab.local).

## Step 1 — unauthenticated SMB/LDAP enumeration (no creds needed)
- `netexec_smb` with just target: reveals OS, hostname, domain, SMB signing, and
  whether null authentication is allowed. Look for "(domain:...)" and
  "Null Auth: True".
- `smbclient_shares` and `smbmap`: list shares reachable anonymously.
- `enum4linux`: broad users/groups/shares/policy enumeration.
- `ldapsearch_anon` with base_dn derived from the domain
  (cyberlab.local => DC=cyberlab,DC=local): test anonymous LDAP bind and dump
  directory objects. `netexec_ldap` does the same with more structure.

## Step 2 — username enumeration (no creds needed)
- `kerbrute_userenum` with the domain and a usernames wordlist validates which
  accounts exist via Kerberos pre-auth, without causing lockouts.

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
