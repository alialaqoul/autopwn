# Cloud and container exposure (quick reference)

Autopwn is network-first, but engagements increasingly surface cloud and
container misconfigurations. What is reachable and testable from the network:

## Exposed container / orchestrator surfaces
- **Docker API 2375** — `docker_api_check`: unauthenticated = root on the host
  (privileged container + host mount). The single highest-impact misconfig.
- **Kubernetes API 6443/10250** — probe `https://<host>:6443/version` with
  `http_probe`: an anonymously readable API, or kubelet (10250) allowing
  `/runningpods`/`exec` unauthenticated, is cluster compromise. Check for
  `--anonymous-auth=true` and overly broad RBAC.
- **etcd 2379** — unauthenticated etcd exposes every cluster secret
  (`etcdctl get --prefix /`).

## Cloud metadata & SSRF
- On any SSRF or RCE foothold, check the instance metadata service:
  `http://169.254.169.254/latest/meta-data/` (AWS), `…/metadata/instance?api-
  version=2021-02-01` with `Metadata: true` (Azure), GCP equivalent. IAM
  credentials there often outrank the host you landed on.
- IMDSv2 requires a token (PUT first) — absence of that requirement is itself a
  reportable hardening gap.

## Storage
- S3-style buckets discovered from web recon (subfinder/gau hostnames on
  amazonaws.com / blob.core.windows.net / storage.googleapis.com): test anonymous
  LIST/READ with a plain `http_probe` on the bucket URL; public indexable buckets
  are a finding. `subzy` covers bucket/subdomain takeover of deleted buckets.
- Open Elasticsearch/Redis/Mongo (9200/6379/27017) on a cloud host = the same
  findings as on-prem (`net-services` playbook) plus public exposure.

## Boundaries (stay honest in the report)
- Do not run cloud control-plane attacks (IAM privilege escalation, assume-role
  chains) without them being explicitly in scope and credentialed for the
  engagement; record exposure and recommend a cloud config review instead.
- Never pivot from a customer VM into the provider's network or other tenants.
