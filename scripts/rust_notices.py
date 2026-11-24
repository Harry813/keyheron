"""Generate the redistributable dependency notices from the resolved Cargo manifests."""
import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "third_party" / "RUST-NOTICES.txt"
PREFIXES = ("license", "licence", "copying", "copyright", "notice", "unlicense")


def license_files(pkg):
    source = Path(pkg["manifest_path"]).parent
    found = {
        p for p in source.rglob("*")
        if p.is_file() and not p.is_symlink()
        and p.name.lower().startswith(PREFIXES)
        and p.suffix.lower() in ("", ".txt", ".md", ".rst")
    }
    if pkg.get("license_file"):
        declared = source / pkg["license_file"]
        if not declared.is_file() or not declared.resolve().is_relative_to(source.resolve()):
            raise ValueError(f"unavailable license_file for {pkg['name']} {pkg['version']}")
        found.add(declared)
    return sorted(found, key=lambda f: f.relative_to(source).as_posix())


def render(packages):
    documents, rows = {}, []
    for pkg in sorted((p for p in packages if p.get("source")), key=lambda p: (p["name"], p["version"])):
        source = Path(pkg["manifest_path"]).parent
        refs = []
        for file in license_files(pkg):
            body = file.read_text(encoding="utf-8").strip()
            if body:
                number = documents.setdefault(body, len(documents) + 1)
                refs.append(f"{file.relative_to(source).as_posix()} [{number}]")
        name, version = pkg["name"], pkg["version"]
        upstream = f"https://crates.io/crates/{name}/{version}"
        license_id = pkg.get("license") or pkg.get("license_file") or "see upstream"
        rows.append(f"{name} {version} | {license_id} | {upstream} | " +
                    (", ".join(refs) if refs else "see published crate source"))
    out = ["KeyHeron — upstream notices for the Rust core",
           "Source: cargo metadata --locked; includes target-specific packages in the resolved graph.",
           "Each version links to its published source. Shared license texts are included once.",
           "", *rows]
    for body, number in documents.items():
        out.extend(["", f"------------ [{number}] ------------", body])
    return ("\n".join(out) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without rewriting the notices")
    parser.add_argument("--offline", action="store_true", help="use an already populated Cargo cache")
    args = parser.parse_args()
    cmd = ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path",
           str(ROOT / "rust-core" / "Cargo.toml")]
    if args.offline:
        cmd.append("--offline")
    generated = render(json.loads(subprocess.check_output(cmd))["packages"])
    if args.check:
        if not DEST.is_file() or DEST.read_bytes() != generated:
            parser.exit(1, "Dependency notices changed. Run python3 scripts/rust_notices.py and review the diff.\n")
        print("Dependency notices match Cargo.lock.")
    else:
        DEST.write_bytes(generated)
        print(f"Wrote {DEST.relative_to(ROOT)} ({len(generated)} bytes).")


if __name__ == "__main__":
    main()
