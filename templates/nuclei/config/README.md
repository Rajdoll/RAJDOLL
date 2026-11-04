# Official nuclei exposure and debug templates (pinned subset)

Copied unchanged from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
release **v10.5.0** (commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`), MIT licence (`LICENSE.md`).
The Configuration & Deployment module runs them once per host, without a session, together with
RAJDOLL's own `rajdoll/exposure/` templates. Only generic templates are kept: GET requests over a
short list of paths, no out-of-band server, no fuzzing of many file names (`php-backup-files`,
`zip-backup-files`) and no large downloads (`springboot-heapdump`). Backup copies of the
application's own files are RAJDOLL's own check (`rajdoll/modules/config_checks.py`).

The directory name is the RAJDOLL vulnerability type (`rajdoll/data/vuln_types.py`) a match is
reported as:

| Directory | Upstream path |
|---|---|
| `sensitive_file/` | `http/exposures/configs/git-config.yaml`, `exposed-svn.yaml`, `laravel-env.yaml`, `codeigniter-env.yaml`, `htpasswd-detection.yaml`, `docker-compose-config.yaml`; `http/exposures/files/ds-store-file.yaml`; `http/exposures/logs/laravel-log-file.yaml`, `error-logs.yaml`, `access-log-file.yaml` |
| `backup_file/` | `http/exposures/backups/mysql-dump.yaml`, `sql-server-dump.yaml` |
| `debug_exposed/` | `http/exposures/configs/phpinfo-files.yaml`; `http/misconfiguration/laravel-debug-enabled.yaml`, `django-debug-config-enabled.yaml`, `apache/apache-server-status.yaml`, `springboot/springboot-env.yaml` |

To update: copy the same files from a newer release tag, update the tag and commit above, check
that each template still sends only GET requests without an out-of-band server, and re-run
`tests/test_recon_e2e.py`.
