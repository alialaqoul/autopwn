# Linux targets (SSH surface and privilege escalation)

The `linux-host` playbook drives the remote surface; this file is the on-host
tradecraft once a shell or credential exists.

## Remote surface first
<!-- when: port:22 -->
- `ssh_audit <target>`: weak KEX/ciphers/MACs, password auth enabled, and known
  OpenSSH CVEs (Terrapin CVE-2023-48795; regreSSHion CVE-2024-6387 on
  8.5p1–9.7p1 glibc builds — unauthenticated RCE as root, though slow and
  reliability-limited; check the banner version, do not spray the exploit).
- `hydra ssh` only with a small, deliberate list — online brute force is noisy and
  may lock accounts. Prefer credentials recovered elsewhere (web DB dump, SNMP,
  NFS, AD reuse via `spray_cracked`).
- Other doors into Linux hosts: NFS exports (`nfs_shares`), SNMP-leaked creds
  (`snmp_walk`), Redis (`redis_check`), Docker API (`docker_api_check`), and web
  app RCE (`web-injection` playbook).

## On-host enumeration (with a shell)
Run linpeas (upload + execute) and read it in this priority order:
1. **sudo**: `sudo -l` — GTFOBins-interpret every allowed binary (less, find, vim,
   python, tar...). `sudoedit`/`baron samedit` on sudo 1.8.x (CVE-2021-3156).
2. **SUID/SGID**: anything non-default → GTFOBins; custom SUID binaries with
   relative-path calls or injectable env vars.
3. **cron + timers**: world-writable scripts run by root cron; writable PATH dirs;
   wildcard tar/rsync argument injection.
4. **kernel**: `uname -a` vs `searchsploit <kernel version>` — DirtyPipe
   (CVE-2022-0847, 5.8–5.16), PwnKit (CVE-2021-4034 polkit, near-universal
   2009–2022), OverlayFS/Ubuntu variants. Prefer reliability-safe LPEs on
   production; kernel exploits can panic the box.
5. **credentials**: history files, `.env`, config files, KeePass/db dumps, cloud
   metadata (`curl 169.254.169.254/latest/meta-data/` on cloud VMs), SSH keys with
   passphrase reuse.

## Evidence
- Capture `id; hostname; sudo -l` output for the transcript; a root shell or
  readable `/etc/shadow` closes the finding.
- Pivot: recovered Linux creds frequently authenticate to AD (same admin team) —
  `netexec_spray` them against the domain.
