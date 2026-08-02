# Production monitoring boundary

Install OpenCloudOS `node_exporter` and replace its sysconfig with the tracked
loopback-only template. Apply `workagent-monitoring.conf` after the package has
created its account; this changes the textfile directory from package mode
`0771` to `0750 root:node_exporter`, so only root can publish metrics while the
exporter remains read-only.

Install `workagent-healthcheck` and its timer. The backup service and health
collector atomically publish separate textfiles. A host-local approved
Prometheus or remote-write agent may use the checked-in scrape fragment for
node_exporter and Portal's direct-loopback `/internal/metrics`; neither endpoint
may be publicly exposed.

Load `prometheus-rules.yml` and configure real warning/critical receiver routes.
The `workagent-public` blackbox probe must run from a genuinely external network
with certificate and hostname verification. The rules alert when that probe is
missing, which prevents a successful localhost check from being presented as
public availability evidence.
