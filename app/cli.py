"""Generate the admin password hash for the credentials file.

Usage::

    python -m app.cli hash-password            # prompts twice, prints the hash
    python -m app.cli hash-password --stdin    # reads the password from stdin

Uses only the standard library, so it runs without installing anything.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .passwords import hash_password

MIN_PASSWORD_LENGTH = 12


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        sys.exit("Passwords do not match.")
    return first


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    hp = sub.add_parser("hash-password", help="hash a password for config/admin.toml")
    hp.add_argument("--stdin", action="store_true", help="read the password from stdin")
    args = parser.parse_args(argv)

    if args.command == "hash-password":
        password = _read_password(args.stdin)
        if len(password) < MIN_PASSWORD_LENGTH:
            sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        encoded = hash_password(password)
        print("Put this line into config/admin.toml:\n", file=sys.stderr)
        print(f'password_hash = "{encoded}"')


if __name__ == "__main__":
    main()
