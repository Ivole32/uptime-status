# Contributing

Thank you for your interest in improving Uptime Status. Bug reports, ideas and pull requests are
all welcome. Please read this guide before you start, and follow the
[Code of Conduct](CODE_OF_CONDUCT.md) in all project spaces.

## Reporting security vulnerabilities

Please **do not** open an issue, discussion or pull request for a security vulnerability.
Report it privately as described in [SECURITY.md](SECURITY.md).

## Reporting bugs

Before you open an issue, check that it has not been reported already and that it still
happens on the latest `main`. Please include:

- What you did, what you expected and what happened instead.
- Steps to reproduce, ideally from a fresh `docker compose up`.
- The commit hash, your `UPTIME_*` settings and how you deploy the app (Docker Compose, reverse
  proxy).
- Relevant log output. Remove passwords, password hashes, session cookies, internal hostnames
  and other secrets first.

## Suggesting features

Open an issue that describes the problem you want to solve, not only the solution. Uptime
Status is deliberately small: a single admin, SQLite, a handful of dependencies and a frontend
without a build step. Proposals that keep it that way are the most likely to be accepted. For
larger changes, please agree on the approach in an issue before you write the code.

## Development setup

See [Development](README.md#development) in the README for the full instructions. In short:

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.txt   # Linux, as in CI
.venv/bin/python -m pytest
```

On Windows or macOS, install from `requirements-dev.in` instead, because the hashed lock files
are generated for Linux.

## Guidelines for changes

### Code

- Match the style of the surrounding code: type hints, `from __future__ import annotations`,
  short docstrings and comments that explain *why*. Do not reformat unrelated code.
- Keep changes focused. One pull request should do one thing.
- `app/passwords.py` and `app/cli.py` must only use the standard library, so the password tool
  runs without installing anything.
- Database schema changes need an Alembic migration (see the README). Never edit an existing
  migration that has been released.

### Security

The app is exposed to the internet and fetches admin-supplied URLs, so a few rules apply to
every change:

- **Frontend:** never use `innerHTML` or similar HTML sinks. Build DOM with `textContent` and
  attributes, as the existing code in `app/static/js/` does. No inline scripts, inline styles
  or external resources: the Content Security Policy blocks them.
- **Input:** validate all request data with Pydantic models (`extra="forbid"`, length limits,
  bounded numbers). Do not echo submitted values back in error responses.
- **Outbound requests:** anything that connects to a user-supplied address must go through
  `app/checker.py`, so the SSRF checks, IP pinning and deadline apply.
- **Admin API:** new admin routes belong on the router in `app/routes/admin.py`, which enforces
  the session and CSRF checks.
- **Public data:** the public status payload must never expose hidden monitors, URLs that are
  not marked as public, check intervals or detailed error reasons.
- **Secrets:** never commit `config/admin.toml`, `.env`, database files or real credentials.

If a change touches a security control, add a test for it and update [SECURITY.md](SECURITY.md).

### Dependencies

- Avoid new runtime dependencies where the standard library or an existing dependency will do.
  Explain why a new one is needed in the pull request.
- Edit the `.in` files only. Then regenerate all hashed `.txt` lock files as described in
  [Updating dependencies](README.md#updating-dependencies). Never edit the `.txt` files by hand.

### Tests and documentation

- Add or update tests for every behavior change, and make sure `python -m pytest` passes.
- When you add or change a setting, update the configuration table in the README and
  `.env.example`. If it affects deployment, update `docker-compose.yml` as well.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests and documentation.
3. Write commit messages with a short summary line in the imperative ("Add X", "Fix Y") and,
   where useful, a body that explains why.
4. Open a pull request that describes what changed, why, and how you tested it. Link the
   related issue.
5. CI must pass: the tests, `pip-audit`, the Docker image build (which audits the installed
   packages again) and the Trivy image scan.

The maintainer reviews every pull request and may ask for changes. Please be patient: this is a
small project, so reviews can take a while.

Thank you for contributing.
