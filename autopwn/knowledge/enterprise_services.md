# Enterprise service playbooks (WSUS, AD CS, Trellix/McAfee ePO)

These roles are high value in Windows/AD environments. Most abuse paths need an
initial domain credential (or network position), so enumerate to confirm the
service and record the finding, then chain from a foothold.

## WSUS (Windows Server Update Services)
Find it on ports 8530 (HTTP) and 8531 (HTTPS); often on a member server or DC.
- Confirm it is live: `curl http://<host>:8530/ClientWebService/client.asmx`
  returns 200 => WSUS is serving over HTTP.
- WSUS served over HTTP (8530) without SSL enforced on clients is susceptible to
  **update spoofing**: an on-path attacker (ARP/DNS MITM) injects a malicious
  signed-by-Microsoft binary (e.g. PsExec) as a fake update to run code as SYSTEM
  on clients (tools: PyWSUS / WSUSpendu / SharpWSUS with admin on the WSUS host).
- Requires a man-in-the-middle position or admin on the WSUS server; record it as
  a lateral-movement finding and check whether GPO forces WSUS over HTTPS.

## AD CS (Active Directory Certificate Services)
The CA is usually on a DC or a dedicated CA host (IIS present, and pKI objects in
LDAP). Web enrollment lives at `/certsrv` (ESC8 relay target) when installed.
- Enumerate with `certipy_find` (certipy-ad find -vulnerable) — this REQUIRES a
  valid domain credential; it lists CAs and templates and flags ESC1-ESC8.
- Key escalations once you have any low-priv user:
  - **ESC1**: a template allows the enrollee to supply the subject (SAN) and is
    usable for client auth => request a cert as a Domain Admin (certipy req ...
    -upn administrator@domain) and authenticate with it.
  - **ESC8**: if web enrollment (/certsrv) is reachable over HTTP, relay a
    machine/user NTLM auth (ntlmrelayx --target http://CA/certsrv/certfnsh.asp
    -adcs) to obtain a certificate for the relayed identity.
- Without a credential and without HTTP web enrollment, AD CS abuse is not
  directly reachable — get a foothold first.

## Trellix / McAfee ePO (ePolicy Orchestrator)
Console typically on 8443 (https), Agent Handler on 8444; the McAfee/Trellix
Agent listens on 8081 on managed hosts.
- Identify: `curl -k https://<host>:8443/` shows a Trellix/ePO login.
- Test the console for default/weak admin credentials (admin / installed
  password) — do not lock accounts; try a few, not a spray.
- ePO stores agent-server secrets and can push tasks/deployments to every managed
  endpoint, so ePO admin => mass code execution across the estate. Check the ePO
  version against `searchsploit` / advisories for known auth-bypass / SQLi CVEs.
- The Agent Handler (8444) and Agent (8081) speak a proprietary protocol, not
  plain HTTP — web tools will fail against them; treat them as ePO components.
