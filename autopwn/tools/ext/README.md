# Vendored external PoC scripts

Some playbooks call a third-party proof-of-concept exploit. The **plaintext**
scripts (`*.py`) are git-ignored and never pushed — they are weaponized exploits,
and the upstream code is unlicensed (all rights reserved by its authors), so the
public repo must not redistribute readable copies. The integration references the
script by path; **you supply the script** on your own authorized engagement host.

## Keeping your copy version-controlled (encrypted)

To back up your (possibly modified) copy in git without publishing readable
exploit code, an **encrypted** blob `*.py.gpg` is committed instead — same idea
as `git-crypt`, but with `gpg` (git-crypt has no Windows package). The plaintext
`*.py` stays ignored; only the AES-256 ciphertext is tracked.

```bash
# one-time: generate a key OUTSIDE the repo and BACK IT UP (losing it = losing the PoCs)
mkdir -p ~/.autopwn-secrets
python -c "import secrets; open('$HOME/.autopwn-secrets/ext-vendor.key','w').write(secrets.token_urlsafe(64))"

autopwn/tools/ext/vendor-crypt.sh lock     # ext/*.py     -> ext/*.py.gpg  (commit the .gpg)
autopwn/tools/ext/vendor-crypt.sh unlock   # ext/*.py.gpg -> ext/*.py      (after a fresh clone)
```

The key file lives outside the repo (default `~/.autopwn-secrets/ext-vendor.key`,
override with `AUTOPWN_EXT_KEY`); it is the only thing that can decrypt the blobs.
Re-run `lock` after editing a script, then commit the updated `*.py.gpg`.

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
