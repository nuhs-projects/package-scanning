# package-scanning

A catalogue of open-source libraries (and the versions in use), scanned every working day against [OSV](https://osv.dev). Fixable vulnerabilities are consolidated into **one issue**, "Package update request": per library, the smallest version that fixes everything found.

The repo is public. It lists libraries only: no application names, no internal hosts, no record of who uses what. See `CLAUDE.md`.

## Layout

```
python/requirements.txt   PyPI libraries, name==version
java/dependencies.txt     Maven libraries, group:artifact:version
npm/packages.txt          npm libraries, name@version
quarantine/known.txt      versions known to be blocked by the registry (purls)
public-repos.txt          public Maven repositories the lists are checked against
scripts/sync.py           manifests -> the three lists (local)
scripts/scan.py           lists -> OSV -> consolidated report
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

The scanner uses OSV. An incomplete upstream response fails the scan, leaving
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

## Consolidation rules

Per library, not per advisory:

- Every advisory affecting a version in use is grouped, de-duplicated by alias (a CVE and its GHSA count once).
- The request is the lowest applicable advisory fix or already-listed version that clears every fixable advisory found for that library without downgrading any listed version. The report flags requests that move to a later major.
- Advisories without a known fixed version and cases without a common fixed target are listed under "no fix yet".
- Severity is the highest CVSS among the advisories; every severity is reported.
- Each line is **new**, **open** or **resolved** against the previous run.

## The issue

`scan.yml` runs at 00:00 UTC, Monday to Friday, and on demand on the default branch. Runs are serialized while updating the issue. It downloads the previous successful default-branch `report` artifact, scans, and uploads the new report (90 days). The first run or an expired artifact starts without a previous report; a download failure fails the run.

- Nothing to request: the open issue is closed. "No fix yet" advisories are shown while it is open, but do not keep it open on their own.
- Otherwise the issue body is replaced with the current report, or the issue is created.
- A short comment listing the packages is added only when something is new and the issue already exists.

`pr.yml` runs the tests, the list check, gitleaks, actionlint and zizmor. Make `PR / done` a required check on `main`.
