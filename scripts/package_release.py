"""Package a local working preview or a release from an exact Git tag."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
ROOT_FILES = {
    ".gitignore", "README.md", "LICENSE", "NOTICE", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
    "access.py", "agent_access.py", "keyheron.py", "bench.py", "console.py", "demo.py", "guard.py",
    "runtime.py", "tools.py", "verify.py", "verify_external.py", "verify_web.py", "web_demo.py",
    "打开工作台.command", "performance.json", "verification.json", "web-verification.json",
    "requirements-db-postgres.txt", "requirements-credentials.txt", "credential_store.py", "secret_cli.py",
    "warden.py", "warden_client.py", "warden_control.py", "warden_plugins.py", "warden_admin.py",
    "warden_storage.py", "plugin_runtime.py", "warden_mcp.py", "requirements-mcp.txt",
}
NATIVE = ("keyheron-core-darwin-arm64", "keyheron-core-linux-amd64")
PENDING = (
    "Local evaluation archive. The copyright holder has not selected an open-source license "
    "for the original project code. Third-party notices apply only to their respective works.\n"
).encode()


def selected(name):
    if name in ROOT_FILES or name in {
        "rust-core/Cargo.toml", "rust-core/Cargo.lock", "web/LICENSE", "web/NOTICE",
        "examples/github-readonly.json", "examples/read_resource.py", "examples/databases.json", "docs/workbench.png",
        "examples/warden-policy.json", "examples/warden-plugins.json", "examples/team-issues.plugin.json",
    }:
        return True
    path = Path(name)
    if any(p.startswith(".") for p in path.parts[1:]):
        return False
    suffixes = {
        ".github/workflows": {".yml"}, "docs": {".md"}, "scripts": {".py"},
        "rust-core/src": {".rs"}, "rust-core/examples": {".rs"}, "dbproxy": {".py"},
        "third_party": {".txt"}, "web": {".html", ".css", ".js", ".md"},
    }
    return any(name.startswith(prefix + "/") and path.suffix in ext for prefix, ext in suffixes.items())


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def working_sources(root):
    files = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "bin", "data", "dist", "__pycache__", "node_modules", ".venv"}]
        for leaf in names:
            path = Path(folder) / leaf
            name = path.relative_to(root).as_posix()
            if not selected(name):
                continue
            if path.is_symlink():
                raise ValueError(f"refusing a symlink in the source manifest: {name}")
            if path.is_file():
                files[name] = path.read_bytes()
    return files


def tagged_sources(root, tag):
    if not TAG.fullmatch(tag):
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH with an optional prerelease suffix")
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root.resolve():
        raise ValueError("the project directory must be the Git repository root")
    commit = git(root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").decode().strip()
    if commit != git(root, "rev-parse", "HEAD").decode().strip():
        raise ValueError("check out the requested release tag before packaging")
    files = {}
    for entry in git(root, "ls-tree", "-r", "-z", commit).split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        name = raw_name.decode()
        if selected(name):
            mode, kind, oid = metadata.decode().split()
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise ValueError(f"unexpected git entry type for {name}")
            files[name] = git(root, "cat-file", "blob", oid)
    return files, commit


def license_confirmed(files):
    # Apache-2.0 contains a sample copyright notice in its appendix; sample
    # placeholders there do not invalidate the actual license.
    license_text = files.get("LICENSE", b"").decode().strip()
    if len(license_text) < 400 or not re.search(r"(?i)license|licence|permission", license_text):
        return False
    if "Apache License" in license_text:
        notice = files.get("NOTICE", b"").decode()
        if not re.search(r"(?im)^copyright[^\n]*[0-9]{4}[^\n]*\w", notice) or re.search(
            r"(?im)^copyright[^\n]*(?:\[[^\]]+\]|<[^@>]+>|YOUR NAME|TBD)", notice
        ):
            return False
    if re.search(r"(?im)^\s*(?:TODO|TBD|PENDING|LICENSE PENDING)\b", license_text):
        return False
    if "Apache License" not in license_text and re.search(
        r"(?im)^copyright[^\n]*(?:<[^@>]+>|\[[^\]]+\]|YOUR NAME|TBD)", license_text
    ):
        return False
    return True


def validate(files, release):
    required = {"README.md", "web/index.html", "web/app.js", "web/styles.css",
                "rust-core/Cargo.toml", "rust-core/Cargo.lock", "rust-core/src/main.rs"}
    if release:
        required.update({"LICENSE", "CONTRIBUTING.md", "SECURITY.md", "verify_external.py", "agent_access.py", "keyheron.py",
                         "examples/github-readonly.json", "examples/read_resource.py", "docs/QUICKSTART.md",
                         "scripts/verify_github.py", "credential_store.py", "secret_cli.py",
                         "requirements-credentials.txt", "docs/CREDENTIALS.md"})
    missing = sorted(required - files.keys())
    if missing:
        raise ValueError("missing required source files: " + ", ".join(missing))
    for name, contents in files.items():
        if re.search(rb"(?m)^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\s*$", contents):
            raise ValueError(f"private key material detected in {name}")
        local_home = str(Path.home()).encode()
        if local_home != b"/" and local_home + b"/" in contents:
            raise ValueError(f"developer home path detected in {name}")
    if release and not license_confirmed(files):
        raise ValueError("original project license is missing, incomplete or pending")


def json_bytes(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def archive(path, prefix, files):
    # Fixed UTC date, Unix modes and stored entries make the source artifact
    # independent of checkout timestamps, umask and zlib version.
    with ZipFile(path, "w", ZIP_STORED) as dest:
        for name, contents in sorted(files.items()):
            member = ZipInfo(f"{prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".command") else 0o644)) << 16
            dest.writestr(member, contents)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root, out, tag=None, binaries=None):
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("choose a new or empty destination directory")
    if binaries and not tag:
        raise ValueError("attach tested CI binaries only to a tagged release")
    files, commit = tagged_sources(root, tag) if tag else (working_sources(root), None)
    validate(files, release=tag is not None)
    if tag:
        version = re.search(rb'(?m)^version\s*=\s*"([^"]+)"', files["rust-core/Cargo.toml"])
        if not version or version.group(1).decode() not in (tag[1:], tag[1:].split("-", 1)[0]):
            raise ValueError("the tag and Rust package version do not match")
    name = tag or "working-preview"
    if not license_confirmed(files):
        files.pop("LICENSE", None)
        files["LICENSE-STATUS.txt"] = PENDING
    manifest = {
        "tag": tag, "commit": commit, "source": "git-tag" if tag else "local-working-tree",
        "original_license": "included" if "LICENSE" in files else "pending",
        "cargo_lock_sha256": hashlib.sha256(files["rust-core/Cargo.lock"]).hexdigest(),
        "keyfence": {"bundled": False, "version": "v0.4.0",
                     "upstream": "https://github.com/atgreen/keyfence/releases/tag/v0.4.0",
                     "verification": "platform-specific SHA-256 pinned in tools.py"},
    }
    licenses = {n: files[n] for n in ("LICENSE", "NOTICE", "LICENSE-STATUS.txt") if n in files}
    source_metadata = json_bytes(manifest)
    web = {k.removeprefix("web/"): v for k, v in files.items() if k.startswith("web/")}
    for key, value in licenses.items():
        web.setdefault(key, value)
    if tag and files.get("web/LICENSE", files["LICENSE"]) != files["LICENSE"]:
        raise ValueError("frontend and root licenses differ; review the intended distribution scopes")
    if tag and not license_confirmed(web):
        raise ValueError("standalone frontend license or its copyright notice is incomplete")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as temporary:
        staging = Path(temporary)
        if binaries:
            if "third_party/RUST-NOTICES.txt" not in files:
                raise ValueError("native distribution requires the Rust dependency notices")
            for license_name in ("LICENSE", "NOTICE"):
                if license_name in files:
                    (staging / license_name).write_bytes(files[license_name])
            (staging / "RUST-NOTICES.txt").write_bytes(files["third_party/RUST-NOTICES.txt"])
            for asset in NATIVE:
                binary = binaries / asset
                if binary.is_symlink() or not binary.is_file() or not binary.stat().st_size:
                    raise ValueError(f"missing tested build: {asset}")
                shutil.copyfile(binary, staging / asset)
                (staging / asset).chmod(0o755)
            manifest["native_sha256"] = {asset: sha(staging / asset) for asset in NATIVE}
        for label, content in (("source", files), ("web", web)):
            archive(staging / f"keyheron-{label}-{name}.zip", f"keyheron-{label}",
                    {**content, "RELEASE-METADATA.json": source_metadata})
        (staging / "RELEASE-METADATA.json").write_bytes(json_bytes(manifest))
        sums = [f"{sha(p)}  {p.name}\n" for p in sorted(staging.iterdir())]
        (staging / "SHA256SUMS").write_text("".join(sums), encoding="ascii")
        out.mkdir(exist_ok=True)
        for asset in staging.iterdir():
            asset.replace(out / asset.name)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tag", help="package this checked-out Git tag")
    mode.add_argument("--preview", action="store_true", help="local working copy, no release authority")
    parser.add_argument("--out", type=Path, required=True, help="new or empty destination")
    parser.add_argument("--binaries", type=Path, help="directory of native binaries supplied by successful tag CI")
    args = parser.parse_args()
    try:
        manifest = build(ROOT, args.out.resolve(), args.tag, args.binaries)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Packaging failed: {exc}\n")
    print(json_bytes(manifest).decode().strip())


if __name__ == "__main__":
    main()
