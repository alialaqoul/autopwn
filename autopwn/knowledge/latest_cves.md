# Latest / actively exploited vulnerabilities (KEV-driven)

Detection strategy: the CVE landscape moves weekly, so Autopwn leans on two
continuously-updated sources instead of hardcoded checks:
- `nuclei_cve` (nuclei `-tags cve,kev`) — the CISA Known Exploited Vulnerabilities
  catalogue and recent criticals as templates. Run `nuclei -update-templates`
  before engagements; a template match is a Critical finding (`cve-web-check`
  playbook).
- NetExec modules for the Windows/AD side (`ad-cve-check` playbook): zerologon,
  nopac, printnightmare, smbghost, ms17-010, coerce_plus, spooler, webdav.

## Workflow on any perimeter host
<!-- when: port:443 -->
1. Fingerprint the product and version (`http_probe`, `whatweb`, nmap banners).
2. `nuclei_cve` on the URL; `searchsploit "<product> <version>"` for the rest.
3. A version inside a KEV range = Critical even without exploitation; hunt for
   prior compromise (webshells, unknown local accounts, log gaps) before reporting.

## Reference list — high-impact, heavily exploited (verify version ranges live)

Edge / VPN / gateway appliances (the top ransomware entry vector):
- **Citrix NetScaler Bleed / Bleed 2** — CVE-2023-4966, CVE-2025-5777: session
  token theft, unauthenticated. Also CVE-2026-19490 auth bypass.
- **Ivanti Connect Secure** — CVE-2025-0282, CVE-2023-46805 + CVE-2024-21887
  chains, CVE-2026-104935: auth bypass → RCE; check ICT results, factory-reset and
  rebuild on confirmed exploitation.
- **Palo Alto PAN-OS / GlobalProtect / Expedition** — CVE-2024-3400 (unauth RCE),
  CVE-2024-9474, CVE-2026-0257 / CVE-2026-0322: management interface must never be
  internet-exposed.
- **Fortinet FortiOS/FortiWeb/FortiManager** — CVE-2024-21762, CVE-2024-23113,
  CVE-2024-47575 (FortiJump), CVE-2025-25249, CVE-2025-25257: pre-auth RCE and
  SQLi; massive internet exposure.
- **Cisco FMC / ASA / SEG** — CVE-2026-20079 (FMC auth bypass → root),
  CVE-2026-76519 (SEG AMP path traversal RCE).
- **BeyondTrust Remote Support** — CVE-2026-102764: unauthenticated RCE, webshell
  deployment (KEV).
- **ConnectWise ScreenConnect** — CVE-2024-1708/1709: auth bypass → RCE; trivially
  exploited, check `%ProgramData%` for webshells.

Windows / AD infrastructure (beyond the nxc module set):
- **Windows Shell MotW bypass** CVE-2026-96951 (KEV, client-side phishing chain).
- **SharePoint ToolShell** CVE-2025-53770/53771: unauth RCE on-prem SharePoint —
  check for spinstall0.aspx / webshells; machine-key theft → viewstate forgery.
- **WSUS / Exchange / Outlook** classes remain staple: CVE-2023-23397 (Outlook
  NTLM leak), Exchange ProxyShell variants — enumerate versions, match advisories.

Web / app platform:
- **React Server Components "React2Shell"** CVE-2025-55182 (CVSS 10.0, KEV,
  ransomware use): unauth RCE in RSC flight endpoint — affects Next.js and similar
  frameworks; test exposed Node front-ends.
- **MOVEit Transfer** CVE-2023-34362: SQLi → RCE + data theft (Cl0p campaign).
- **Confluence** CVE-2023-22527 (template injection RCE), CVE-2022-26134 (OGNL).
- **TeamCity** CVE-2024-27198 (auth bypass → RCE on CI server = supply chain).
- **GoAnywhere MFT** CVE-2023-0669, **PaperCut** CVE-2023-27350, **CrushFTP**
  CVE-2024-4040, **Veeam Backup** CVE-2023-27532, **Progress WS_FTP**
  CVE-2023-40044 — all file-transfer/backup platforms with mass exploitation.
- **Adobe Commerce/Magento** CVE-2026-103849 (CVSS 10.0, unauth RCE assessed
  imminent), **Langflow** CVE-2026-105740 (auth RCE via MCP command exec).

OpenSSH / Linux:
- **regreSSHion** CVE-2024-6387 (OpenSSH 8.5p1–9.7p1, glibc): unauth RCE as root;
  unreliable/slow exploit — confirm by banner version (`ssh_audit`), never
  fire-and-forget against production.
- **Terrapin** CVE-2023-48795: prefix-truncation downgrade — `ssh_audit` flags it.

## Reporting guidance
- KEV presence is always Critical severity; cite the KEV entry and vendor advisory.
- Distinguish "version in vulnerable range" (needs patch + hunt) from "exploit
  confirmed" (evidence of code execution) in the report.
