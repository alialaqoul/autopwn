# Network poisoning & relay playbook (LLMNR/NBT-NS, IPv6 takeover)

## When to use
Apply this on a Windows/Active Directory subnet (SMB 445 open on several hosts)
when you are on the same broadcast segment as Windows clients/servers and have
no credentials yet — or when coercion-based relay (`ntlm_relay`) is not
available. Poisoning is opportunistic (you wait for victims to misresolve
names); relay is targeted (you coerce a specific host). Both need root.

## LLMNR/NBT-NS poisoning → NetNTLMv2 capture
<!-- when: port:445 -->
Windows hosts fall back to LLMNR/NBT-NS broadcast name resolution when DNS
fails; anyone on the segment can answer and capture the victim's NetNTLMv2
authentication. Run this EARLY in the engagement and let it soak while other
work proceeds:
1. `responder_capture` (built-in, **intrusive**, run as root) starts Responder
   on the local interface for a bounded window (default `duration=120` seconds)
   and writes every captured NetNTLMv2 hash to the chain `hashfile` fact.
2. `crack_hashes` — crack the captured hashes offline with john + rockyou.
   NetNTLMv2 is slow to crack, so weak passwords are what you get; that is fine.
3. `spray_cracked` — spray each recovered password across the domain user list
   to find reuse. **Never spray more than 1–2 passwords per account** — domain
   lockout policies (often 3–5 attempts) will lock accounts and alert defenders.
The whole chain ships as the **llmnr-poison playbook**. Captured hashes are
also usable for pass-the-hash — try `netexec_smb -u <user> -H <nt>` and watch
for `Pwn3d!` before spending spray attempts.

## IPv6 DNS takeover → relay to the DC (mitm6)
<!-- when: port:88, port:389, fact:domain -->
When the domain is known and the DC is reachable, IPv6 is usually enabled but
unmanaged on Windows networks. `mitm6_relay` (built-in, **intrusive**, run as
root) answers DHCPv6, makes victims use your host as DNS, and relays their
authentication with `ntlmrelayx -6` to the DC over LDAP/LDAPS. A relayed
machine account is typically used to write Resource-Based Constrained
Delegation (RBCD) onto a victim host — after it runs, check the `delegation`
loot and finish with the RBCD path (`get_st -spn cifs/<host> -impersonate
Administrator`, then `secretsdump -k`). Set `domain` and `target` (the DC).
Authentication happens in bursts (boots, logons, patch Tuesday reboots) — a
short quiet window does not mean the path is dead; re-run during business
hours. This chain ships as the **mitm6-takeover playbook** (fingerprint →
takeover+relay → crack → confirm).

## Poisoning vs targeted relay — which to prefer
<!-- when: port:445, fact:smb_signing -->
- Prefer **poisoning** (`responder_capture`) when you have no credentials and
  just joined the network: it is passive-wait, catches whatever misresolves,
  and works even when you know nothing about the domain.
- Prefer **targeted relay** (`ntlm_relay`) when you already have a credential
  (to coerce) and a known `signing:False` host: it is deterministic — coerce a
  specific host and relay to a specific target — instead of waiting.
- Either way, relay only lands on hosts with `signing:False` (DCs require
  signing). Enumerate relay targets first with `netexec_smb` and check the
  `signing` fact on every host.

## Mitigations (report content)
<!-- when: port:445 -->
When poisoning or relay succeeds, recommend: disable LLMNR and NBT-NS via GPO;
require SMB signing on all servers and workstations; enforce LDAP signing and
channel binding; disable IPv6 (or manage DHCPv6) where unused; require strong
passwords so captured NetNTLMv2 hashes resist cracking; and segment/monitor
broadcast traffic for Responder-style answers.
