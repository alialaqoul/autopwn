# Credentials, hashes, and cracking

## Capturing credentials
Any valid credential unlocks authenticated enumeration and privilege escalation.
NetExec prints a success line "[+] domain\\user:password (Pwn3d!)" which Autopwn
harvests into the username/password variables automatically; downstream tools are
then auto-filled with them.

## Getting crackable hashes (no creds needed)
- AS-REP roasting (`asrep_roast`) => Kerberos AS-REP hashes (hashcat mode 18200).
- Kerberoasting (`kerberoast`, needs one valid credential) => TGS-REP hashes
  (hashcat mode 13100).
- `secretsdump` (needs privileged creds) => NTLM hashes from SAM/NTDS.

## Cracking hashes
- `hashid` identifies the hash type first.
- `hashcat -m <mode> <hashfile> <wordlist>`: common modes — 18200 AS-REP,
  13100 Kerberoast TGS, 1000 NTLM, 5600 NetNTLMv2.
- `john --wordlist=<list> <hashfile>` auto-detects many formats.
- Default wordlist on Kali: /usr/share/wordlists/rockyou.txt.
Once a password is cracked, feed it back as a credential to unlock more.

## Online brute force (use sparingly, noisy)
- `hydra` against a service (ssh, ftp, rdp, smb) with username and password
  lists. Prefer targeted password spraying over broad brute force to avoid
  lockouts. Only when the objective calls for it and wordlists are available.
