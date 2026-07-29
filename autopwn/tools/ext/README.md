# Vendored external PoC scripts

Some playbooks call a third-party proof-of-concept exploit that is **deliberately
not shipped in this repository** — these are weaponized exploits, so distribution
is kept intentional. The integration references the script by path; **you supply
the script** on your own authorized engagement host.

Scripts placed here (`*.py`) are git-ignored, so they never get pushed to the
public repo.

## `certighost.py` — Certighost / CVE-2026-54121 (AD CS "chase")

Used by the runnable `certighost` step of the **`adcs-certighost`** playbook.

- **Authors:** [@h0j3n](https://x.com/h0j3n), [@aniqfakhrul](https://x.com/aniqfakhrul)
- **Drop it here:** `autopwn/tools/ext/certighost.py`
- **Runtime deps:** `impacket cryptography asn1crypto pycryptodomex dnspython pyasn1`
- **Run as root** with TCP **445** and **389** free — it stands up rogue LSA/SMB
  and LDAP listeners the CA "chases".

Autopwn wires the arguments automatically from the launch target + stored creds:

```
python3 certighost.py -d <domain> -u <user> (-p <pass> | -H [LM:]NT) --dc-ip <dc>
```

If the script is absent the `certighost` tool simply errors at run time and the
playbook step is skipped — the rest of Autopwn is unaffected.
