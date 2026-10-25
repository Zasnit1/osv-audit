# osv-audit

Find out which of your dependencies have **known vulnerabilities** — and which version fixes each one — by checking them against [OSV.dev](https://osv.dev), Google's open vulnerability database.

- Single file, **Python standard library only** (3.9+). No installs, no API keys.
- Reads a lockfile, sends only `{name, version, ecosystem}` to the public OSV API, and nothing else.
- CI-friendly: `--fail-on-vuln` returns a non-zero exit code so a vulnerable build fails loudly.

Think of it as a dependency-focused companion to a KEV watcher: KEV tells you what is being exploited in the wild, osv-audit tells you whether *your* pinned versions are affected.

## Supported inputs

| File | Ecosystem |
|---|---|
| `requirements.txt` (pinned `pkg==1.2.3` lines) | PyPI |
| `package-lock.json` (npm v1/v2/v3) | npm |

## Quick start

```bash
git clone https://github.com/Zasnit1/osv-audit.git
cd osv-audit
python3 osv_audit.py requirements.txt
```

```
Checked 2 package(s). 1 known vulnerability found:

  Django 2.2.0 (PyPI)
    GHSA-xxxx: SQL injection via a crafted query
    -> fixed in 2.2.1   https://osv.dev/vulnerability/GHSA-xxxx
```

*(Illustrative output. Run it against your own lockfile for real results.)*

## Usage

```bash
python3 osv_audit.py LOCKFILE [--format text|json] [--fail-on-vuln] [--timeout SECONDS]
```

- `--format json` — machine-readable output for pipelines.
- `--fail-on-vuln` — exit code `2` if any dependency has a known vulnerability.

### CI example (GitHub Actions)

```yaml
- run: python3 osv_audit.py requirements.txt --fail-on-vuln
```

## How it works

1. Parse the lockfile into `(name, version, ecosystem)` triples.
2. Send them in one batch request to `api.osv.dev/v1/querybatch`.
3. For each hit, fetch the vulnerability record and extract its summary and the first `fixed` version from the affected ranges.

No project code is executed and nothing is installed. The only network traffic is to OSV.dev.

## Notes and limitations

- Only **pinned** requirements (`==`) are checked; ranges and unpinned lines are skipped, because a vulnerability lookup needs an exact version.
- A result reflects what OSV currently knows. Absence of a finding is not a guarantee of safety.
- OSV covers many ecosystems; this tool currently maps PyPI and npm. Others are easy to add — PRs welcome.

## Tests

```bash
python3 -m pytest -q
```

The network layer is injectable, so the test suite runs fully offline.

## License

MIT, see [LICENSE](LICENSE).

Built by Ibrahim Maqtoush with AI assistance. Issues and pull requests welcome.
