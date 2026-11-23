# package-scanning

A catalogue of open-source libraries (and the versions in use), scanned every working day against [OSV](https://osv.dev) and, when a token is configured, [Snyk](https://snyk.io). Fixable vulnerabilities are consolidated into **one issue**, "Package update request": per library, the smallest version that fixes everything found.

The repo is public. It lists libraries only: no application names, no internal hosts, no record of who uses what. See `CLAUDE.md`.

## Layout

```
python/requirements.txt   PyPI libraries, name==version
java/dependencies.txt     Maven libraries, group:artifact:version
npm/packages.txt          npm libraries, name@version
quarantine/known.txt      versions known to be blocked by the registry (purls)
public-repos.txt          public Maven repositories the lists are checked against
scripts/sync.py           manifests -> the three lists (local)
scripts/snyk_manifests.py  lists -> synthetic manifests for snyk test
scripts/scan.py           lists -> OSV (+ Snyk results) -> consolidated report
scripts/check_registry.py are the requested versions installable from the registry? (local)
scripts/check_lists.py    PR check: list format, order, duplicates
scripts/check_public.py   PR check: every exact library version is publicly available
```

The lists are generated, one sorted, deduplicated line per version. Do not edit them by hand.

## Run it

Sync the lists. Run from the directory that holds the projects, with the Maven settings and registry credentials in the environment. `sources.local` is gitignored: one manifest path per line (`uv.lock`, `requirements*.txt`, `package-lock.json`, `pom.xml`), relative to `--root` or absolute, `#` for comments.

Internal artifacts are dropped: every groupId declared by the project's own poms (its reactor modules), plus any group under a prefix in `INTERNAL_GROUPS` (comma- or space-separated), which covers internal libraries from other projects. The PR check `check_public.py` verifies that each exact library version is published in a public registry.

```sh
python3 scripts/sync.py --sources sources.local --root .
```

Before pushing, run the strict public registry check locally. It fails if a
version cannot be verified, including when a public registry is unavailable:

```sh
python3 scripts/check_public.py --strict
```

For a `pom.xml`, `sync.py` runs `maven-dependency-plugin` 3.7.0 by its full coordinates (newer releases and their dependencies may be blocked by the proxy) with the `compile` phase and compilation skipped, so reactor modules resolve without being installed. Nothing is written to the projects except Maven's usual `target/` state.

Scan and write `reports/report.md` and `reports/report.json`:

```sh
python3 scripts/scan.py [--previous old/report.json]
```

The scanner uses OSV, plus Snyk results when given `--snyk`. An incomplete upstream response fails the scan, leaving
the existing issue unchanged.

Check the requested versions against the local JFrog registry, which needs its credentials in the environment (`UV_DEFAULT_INDEX`, `MAVEN_ARGS` with `-s`, `NPM_CONFIG_USERCONFIG`). This is a separate local availability check. It adds `registry` to each finding, a "Registry availability" section to `report.md`, and blocked versions to `quarantine/known.txt`. Credentials and URLs are never printed.

```sh
python3 scripts/check_registry.py
python3 scripts/check_registry.py --constraints   # uv constraint-dependencies from known.txt
```

Tests:

```sh
python3 -m unittest discover -s tests -v
```

## Snyk

Snyk knows advisories that OSV and GHSA lack, e.g. `SNYK-JAVA-*` ids without a CVE. It is optional: add a `SNYK_TOKEN` Actions secret to enable it. Without the secret the scan is OSV only. With it, a Snyk error fails the run, so a broken Snyk run never drops findings.

- `snyk_manifests.py` turns the lists into synthetic manifests (a `pom.xml`, a `poetry.lock`, ...). Snyk reports one version per library per manifest, so a library with N versions needs N manifests.
- The workflow runs one `snyk test` per manifest. Free-plan budget: about 6 tests per run, roughly 130 a month at 22 working days, against a free cap of about 200.
- Sent to Snyk: the public library lists only, via `snyk test`. Never `snyk monitor`, so no project is stored in Snyk.
- Raw Snyk JSON is not uploaded as an artifact. `scan.py` merges it into the report.

Run it locally:

```sh
snyk auth
python3 scripts/snyk_manifests.py --out snyk-manifests
# per line of snyk-manifests/manifests.txt: name, file, count, extra args
snyk test --file=snyk-manifests/java-1/pom.xml --json-file-output=snyk-results/java-1.json
python3 scripts/scan.py --snyk snyk-results
```

## Consolidation rules

Per library, not per advisory:

- Every advisory affecting a version in use is grouped, de-duplicated by alias (a CVE, its GHSA and its Snyk id count once), whether from OSV or Snyk.
- The request is the lowest applicable advisory fix or already-listed version that clears every fixable advisory found for that library without downgrading any listed version. The report flags requests that move to a later major.
- Advisories without a known fixed version and cases without a common fixed target are listed under "no fix yet".
- Severity is the highest CVSS among the advisories; every severity is reported.
- Each line is **new**, **open** or **resolved** against the previous run.

## The issue

`scan.yml` runs at 00:00 UTC, Monday to Friday, and on demand on the default branch. Runs are serialized while updating the issue. It downloads the `report` artifact of the latest completed default-branch run that has one (among the last 20), scans (OSV, and Snyk when the secret is set), and uploads the new report (90 days). The first run or expired artifacts start without a previous report; a download failure fails the run.

- Nothing to request: the open issue is closed. "No fix yet" advisories are shown while it is open, but do not keep it open on their own.
- Otherwise the issue body is replaced with the current report, or the issue is created.
- A short comment listing the packages is added only when something is new and the issue already exists.
- The run fails, after the issue is updated, while any library has a known vulnerability, including those with no fix yet. A green run means no known vulnerabilities.

`pr.yml` runs the tests, the list check, gitleaks, actionlint and zizmor. Make `PR / done` a required check on `main`.
