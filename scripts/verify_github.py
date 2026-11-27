"""Opt-in KeyHeron acceptance check using a single-repository GitHub App installation token."""

import argparse
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ENV_KEY = "KEYHERON_TEST_INSTALLATION_TOKEN"
ROUTE = "/installation/repositories"
MAX_RESPONSE = 8 * 1024 * 1024


def verify_installation_scope(repository, installation_token):
    # The trusted CI process checks the repository list directly. No redirects or
    # proxy forwarding, and no raw response or credential reaches an SDK client.
    with closing(http.client.HTTPSConnection("api.github.com", timeout=20)) as conn:
        conn.request("GET", ROUTE, headers={
            "Authorization": "Bearer " + installation_token,
            "Accept": "application/vnd.github+json",
            "User-Agent": "KeyHeron-acceptance",
        })
        with conn.getresponse() as response:
            if response.status != 200:
                raise RuntimeError("GitHub installation scope request failed")
            body = response.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise ValueError("installation scope response too large")
    value = json.loads(body)
    repos = value.get("repositories") if isinstance(value, dict) else None
    if (
        not isinstance(repos, list) or len(repos) != 1 or value.get("total_count") != 1
        or not isinstance(repos[0], dict) or not isinstance(repos[0].get("full_name"), str)
        or repos[0]["full_name"].casefold() != repository.casefold()
    ):
        raise ValueError("installation token is not restricted to the expected repository")


def verify(repository, installation_token):
    sys.path.insert(0, str(ROOT))
    from agent_access import control, running_external

    verify_installation_scope(repository, installation_token)
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
        with running_external(config, state) as info:
            control(info, "switch", {"environment": "DEV"})
            try:
                control(info, "sdk-session", {"environment": "DEV", "ttl": 60})
            except RuntimeError as exc:
                if not str(exc).startswith("sdk-session: HTTP 403 "):
                    raise
            else:
                raise RuntimeError("SDK session unexpectedly issued for a bearer credential")
            metadata = control(info, "read", {})
            if metadata != {
                "environment": "DEV",
                "account": "ci-installation",
                "status_source": "configured-credential",
                "upstream_status": 200,
                "operation_id": None,
            }:
                raise RuntimeError("unexpected managed read metadata")
        with closing(sqlite3.connect(state / "events.sqlite3")) as db:
            events = db.execute(
                "SELECT actor, environment, action, resource, result FROM events "
                "WHERE action IN ('sdk-session', 'sdk_read', 'read') ORDER BY id"
            ).fetchall()
            if events != [
                ("ci-agent", "DEV", "sdk-session", "installation-repository", "denied"),
                ("ci-agent", "DEV", "read", "installation-repository", "allowed"),
            ]:
                raise RuntimeError("expected managed read and denied SDK issuance audit missing")
    print("PASS: single-repository GitHub token, managed read metadata, SDK refusal and audit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="expected owner/repository",
    )
    args = parser.parse_args()
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
        http.client.HTTPException,
    ) as exc:
        # Exceptions and upstream responses can contain private data.
        print(f"FAIL: GitHub acceptance ({type(exc).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
