# Virtualization & backup infrastructure (vCenter / ESXi / Veeam)

Hypervisors and backup servers are the highest-leverage targets in a modern
enterprise: the hypervisor owns every guest VM (often including the domain
controllers), and the backup server stores credentials for everything it
protects. Ransomware crews hit both first — a thorough engagement must too.

## Fingerprinting the virtualization layer
<!-- when: port:443 -->
- `http_probe` the web root: vCenter redirects to the vSphere Client /
  IDENTITY_SERVICES endpoints; ESXi answers with its own banner on 443 (and the
  direct console on 902, HTML5 client on 9443). The `virtualization-attack`
  playbook runs this fingerprint + CVE sweep automatically.
- Build numbers map exactly to patch level — record them for the report.
- vCenter is almost always domain-joined and reachable from user VLANs; ESXi
  hosts joined to AD inherit the `ESX Admins` group trust problem below.

## vCenter / ESXi known exploits
<!-- when: port:443 -->
<!-- when: port:902 -->
- Run `nuclei_cve` with `tags=cve,kev,vmware` against the URL. The heavy
  hitters: **CVE-2021-21972** (unauth vCenter RCE via vrops plugin upload),
  **CVE-2024-37085** (ESXi AD-join auth bypass — any member of an AD group
  named `ESX Admins` becomes root on the host, exploited in the wild by
  ransomware operators), **CVE-2023-34048** (vCenter DCE/RPC OOB write).
- If `ESX Admins` (or a renamed equivalent) exists in AD, group membership is a
  finding on its own — it bypasses all ESXi host authentication.

## vCenter → domain dominance
<!-- when: port:443, fact:username -->
- With any vCenter credential: enumerate datacenters/clusters, identify the
  VMs running domain controllers, then **snapshot a DC VM** and extract NTDS
  offline from the snapshot VMDK — the live DC never sees a logon.
- VM remote consoles and guest-operations API (VMware Tools) are RCE on the
  guest with vCenter rights — quieter than RDP.
- Report framing: one unpatched virtualization host == every VM on it,
  including the ones the customer thinks are isolated.

## Backup infrastructure (Veeam)
<!-- when: port:445 -->
- Identify: Veeam Backup Enterprise Manager web UI on 9443, the
  Veeam.Backup.Service on 9401, and the local MSSQL instance (1433) that holds
  the configuration + credential store. Hostnames (`veeam`, `backup`, `bkp`)
  and SMB shares usually give it away. The `backup-attack` playbook chains
  identification → CVE sweep → credential recovery.
- **CVE-2023-27532**: unauthenticated credential disclosure from the backup
  service. **CVE-2024-40711** (and successors): RCE as SYSTEM via the backup
  service. `nuclei_cve` with `tags=cve,kev,veeam` covers the template set.

## Recovering the stored credentials
<!-- when: port:1433, fact:username -->
- `netexec_module` with `protocol=mssql, module=veeam` extracts and decrypts
  every credential stored for backup jobs — routinely vCenter root, SQL sa,
  and domain administrator. One query, full domain compromise: this is a High
  finding even without exploitation.
- Offline variant: with a copy of the configuration database (or a backup of
  it), the published DPAPI-based decryptors (veeam-decrypt / Veeam-Get-Creds)
  recover the same credentials with zero contact with the live server.
- Always recommend rotation of EVERY credential stored in the backup server
  after a finding — customers routinely forget service accounts stored there.

## Boundaries & reporting
- Do not delete or encrypt backups, snapshots, or replica jobs — ever. Proof
  of access + a screenshot of the credential store is sufficient evidence.
- Remediation themes for the report: isolate backup/virtualization management
  to a jump-host VLAN, gMSA/least-privilege service accounts, MFA on vCenter
  SSO, immutable (air-gapped or object-lock) backup copies.
