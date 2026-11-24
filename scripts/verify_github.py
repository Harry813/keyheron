"""Opt-in KeyHeron acceptance check using a single-repository GitHub App installation token."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ENV_KEY = "KEYHERON_TEST_INSTALLATION_TOKEN"
ROUTE = "/installation/repositories"
URL = "https://api.github.com" + ROUTE
MAX_RESPONSE = 8 * 1024 * 1024


def check_client(repository):
    # The unmodified urllib client knows only the API address; proxy auth and CA
    # come from KeyHeron. Never echo the response, repository list or environment.
    if any(
        name in os.environ
        for name in (ENV_KEY, "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN")
    ):
        return 1
    if os.environ.get("KEYHERON_URL") != URL or not os.environ.get("HTTPS_PROXY"):
        return 1
    request = Request(URL, headers={"Accept": "application/vnd.github+json"})
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read(MAX_RESPONSE + 1)
            if response.status != 200 or len(body) > MAX_RESPONSE:
                return 1
            value = json.loads(body)
            # This check is intended for a token explicitly restricted to this repo.
            repos = value.get("repositories", [])
            if (
                value.get("total_count") != 1
                or len(repos) != 1
                or repos[0].get("full_name", "").casefold() != repository.casefold()
            ):
                return 1
            print("HTTP 200")
            return 0
    except HTTPError as exc:
        print(f"HTTP {exc.code}")
    except (OSError, URLError, ValueError, AttributeError, TypeError):
        pass
    return 1


def verify(repository, installation_token):
    sys.path.insert(0, str(ROOT))
    from agent_access import running_external

    with tempfile.TemporaryDirectory(prefix="keyheron-github-") as tmp:
        base = Path(tmp)
        base.chmod(0o700)
        with os.fdopen(
            os.open(
                base / "installation-token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            ),
            "w",
        ) as secret:
            secret.write(installation_token)
        config = base / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "task": "ci-github-installation-read",
                    "identities": {"applicant": "ci-agent", "approver": "ci-reviewer"},
                    "environments": {
                        "DEV": {
                            "origin": "https://api.github.com",
                            "credential_files": {
                                "ci-installation": "installation-token"
                            },
                            "routes": {
                                "read": {
                                    "method": "GET",
                                    "path": ROUTE,
                                    "credential": "ci-installation",
                                    "resource": "installation-repository",
                                    "max_ttl": 120,
                                }
                            },
                        }
                    },
                }
            )
        )
        config.chmod(0o600)
        state = base / "state"
        with running_external(config, state):
            # Pass inert markers to the trusted CLI to exercise its child-env filter,
            # without giving that CLI the upstream token used for this test.
            cli_env = {
                k: os.environ[k]
                for k in ("PATH", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR")
                if k in os.environ
            }
            cli_env.update(
                {
                    ENV_KEY: "must-stay-at-launcher",
                    "GITHUB_TOKEN": "must-stay-at-launcher",
                }
            )
            run = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "keyheron.py"),
                    "run",
                    "--state-dir",
                    str(state),
                    "--env",
                    "DEV",
                    "--",
                    sys.executable,
                    "-I",
                    "-B",
                    str(Path(__file__).resolve()),
                    "--client",
                    "--repository",
                    repository,
                ],
                env=cli_env,
                capture_output=True,
                text=True,
                timeout=45,
            )
            if run.returncode != 0 or run.stdout.strip() != "HTTP 200":
                indicator = run.stdout.strip()
                if re.fullmatch(r"HTTP [1-5][0-9]{2}", indicator):
                    print(indicator, file=sys.stderr)
                raise RuntimeError(
                    "GitHub SDK read failed or token was not restricted to the requested repository"
                )
        with closing(sqlite3.connect(state / "events.sqlite3")) as db:

            def recorded(action, actor):
                return db.execute(
                    "SELECT COUNT(*) FROM events WHERE environment='DEV' AND action=? AND actor=? AND result='allowed'",
                    (action, actor),
                ).fetchone()[0]

            if (
                recorded("sdk_read", "agent") != 1
                or recorded("sdk-session", "ci-agent") != 1
                or recorded("sdk-revoke", "ci-agent") != 1
            ):
                raise RuntimeError("expected credential-proxy audit lifecycle missing")
    print(
        "PASS: scoped GitHub installation read, HTTP 200, SDK credential isolation and audit"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="expected owner/repository",
    )
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.client:
        return check_client(args.repository)
    if os.environ.get("GITHUB_ACTIONS") == "true" and (
        os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        print("Use a trusted push job on a GitHub-hosted runner.", file=sys.stderr)
        return 2
    token = os.environ.pop(ENV_KEY, "")
    if not token or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository
    ):
        print(
            "Supply KEYHERON_TEST_INSTALLATION_TOKEN and GITHUB_REPOSITORY (or --repository) explicitly.",
            file=sys.stderr,
        )
        return 2
    try:
        verify(args.repository, token)
    except (
        OSError,
        ValueError,
        RuntimeError,
        sqlite3.Error,
        subprocess.TimeoutExpired,
    ) as exc:
        # No exception or child stderr is echoed: it may contain credential-bearing URLs or data.
        print(f"FAIL: GitHub acceptance ({type(exc).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
