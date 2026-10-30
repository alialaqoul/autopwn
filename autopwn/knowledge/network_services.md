# Exposed network services (SNMP, NFS, Redis, Docker, databases, caches)

Unauthenticated infrastructure services are the quiet way in on internal estates.
The `net-services` playbook automates the checks below; each confirmed exposure is
a reportable finding even before exploitation.

## SNMP (161/udp)
<!-- when: port:161 -->
- `onesixtyone <target>` sweeps common community strings; `public` / `private` /
  the org name are the usual hits.
- `snmp_walk <target>` (community public by default): read system info, interfaces,
  running processes (`1.3.6.1.2.1.25.4.2.1.2`), installed software, and user
  accounts. Printers and NAS devices frequently leak AD credentials this way.
- A *write* community string allows device reconfiguration — escalate the finding.

## NFS (2049, via rpcbind 111)
<!-- when: port:2049 -->
- `rpcinfo -p <target>` maps every RPC program (nfs, mountd, nlockmgr, yp/NIS).
- `nfs_shares <target>` (showmount -e): exports shared to `*` or the whole subnet
  are mountable. Watch for `/home`, `/srv/backups`, web roots.
- Mount read-only and loot: SSH keys, configs, database dumps. If the export is
  writable AND `no_root_squash` is set, drop a SUID binary → root on the server.

## Redis (6379)
<!-- when: port:6379 -->
- `redis_check <target>` (redis-cli info server): an answer without a password =
  unauthenticated. Read keys (`keys *`), and note the RCE paths: write an SSH key
  to `dir`+`dbfilename`, a cron entry, a PHP webshell to a web root, or load a
  rogue module (Redis < 7 sandboxing).

## memcached (11211)
<!-- when: port:11211 -->
- `memcached_check <target>` sends `stats` over nc; an answer confirms exposure.
  `stats items` → `stats cachedump <id> 0` reads cached sessions/objects.
  Report UDP exposure too (DDoS amplification).

## Elasticsearch (9200) / MongoDB (27017)
<!-- when: port:9200 -->
- `elastic_check <target>`: `/_cat/indices?v` without auth lists every index — all
  indexed data (logs, PII, documents) is exposed; indices can be dropped.
- `mongodb_check <target>` (nmap mongodb-info NSE): databases listed without auth.
  Unauthenticated Mongo is mass-scanned and ransomed — treat as urgent.

## Docker API (2375/2376)
<!-- when: port:2375 -->
- `docker_api_check <target>`: `/version` answering on 2375 = unauthenticated
  daemon API, which is root on the host: `docker -H tcp://<target> run -v /:/host
  --privileged -it alpine chroot /host`. 2376 must require TLS client certs — if it
  does not, it is the same finding.

## RDP (3389) / VNC (5900) / Telnet (23)
<!-- when: port:3389 -->
- `netexec_rdp <target>`: confirm NLA posture and validate creds/hashes; NLA off
  exposes pre-auth surface (BlueKeep class on legacy hosts).
- VNC: frequently short-password or no-auth; brute force is trivially fast — test a
  tiny list by hand and screenshot the result (`gowitness` on a captured desktop is
  strong report evidence when policy allows).
- Telnet: cleartext credentials on the wire; always a finding, usually an easy win
  with default device creds.
