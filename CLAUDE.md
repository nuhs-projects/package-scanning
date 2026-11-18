# Agent instructions

This repository is **public**. Anyone can read everything pushed to it: files, commit messages, branch names, PR titles, descriptions, issues and comments. Rewriting history does not remove it, because GitHub keeps old commits and edits reachable.

Commit only material about open-source libraries and the tooling around them: the lists of library versions, public advisory IDs, scripts, workflows, tests and their docs. Keep these off GitHub:

- credentials of any kind: tokens, passwords, keys, certificates
- internal hostnames, IP addresses, URLs and local file paths
- names or details of the internal applications, projects and groups, and which application uses which library
- internal artifacts: only libraries from public registries belong in the lists

The repo says nothing about who uses what. It is a catalogue of open-source libraries and versions, the way a base-image catalogue is a list of images. Do not describe the organisation, the projects or the usage in any file, issue or commit message.

Test fixtures use made-up names (`demo-app`, `com.example`), never real project paths or names. Comments in the lists, issues and reports name only libraries, versions and advisory IDs.

Local working files stay local: `sources.local` (the manifests `sync.py` reads), `reports/`, `evidence/`, `*-plan.md` and `*-execution.md`. `.gitignore` excludes them. `quarantine/known.txt` is committed, so it holds library purls only.

Python is stdlib only, 3.11 or newer, tests with `unittest`:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_lists.py
python3 scripts/check_public.py
```

Workflows read secrets only from GitHub Actions secrets (`${{ secrets.NAME }}`) and pass GitHub context to scripts through `env:`, never by interpolating it into `run:`. Pin every action by full commit SHA, with the version in a comment.

Internal Maven group prefixes are not committed. They come from `INTERNAL_GROUPS` in the environment (comma- or space-separated) for `sync.py`; in CI, `check_public.py` catches internal artifacts without any internal names, by asking the public registries whether each listed library is published there.

Before pushing, scan the new commits the same way PR CI does:

```sh
gitleaks git --log-opts="origin/main..HEAD" --redact .
```
