# Official nuclei DAST templates (pinned subset)

Copied unchanged from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
release **v10.5.0** (commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`), MIT licence (`LICENSE.md`).
Only the templates the Input Validation module runs are kept, and only those that need no
out-of-band server (interactsh is off by default, TRD 4.3). The upstream SSRF templates all need
one, so SSRF relies on RAJDOLL's own probe.

The directory name is the RAJDOLL vulnerability type (`rajdoll/data/vuln_types.py`) a match is
reported as:

| Directory | Upstream path |
|---|---|
| `sqli/` | `dast/vulnerabilities/sqli/sqli-error-based.yaml`, `time-based-sqli.yaml` |
| `xss_reflected/` | `dast/vulnerabilities/xss/reflected-xss.yaml` |
| `cmdi/` | `dast/vulnerabilities/injection/unix-command-injection.yaml` |
| `ssti/` | `dast/vulnerabilities/ssti/reflection-ssti.yaml`, `razor-ssti.yaml`, `smarty-ssti.yaml`, `twig-ssti.yaml`, `freemarker-sandbox-bypass-ssti.yaml` |

To update: copy the same files from a newer release tag, update the tag and commit above, and
re-run `tests/test_recon_e2e.py`.
