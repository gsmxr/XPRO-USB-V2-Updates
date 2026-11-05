"""Sign a prebuilt XPRO V2 GitHub draft release; no XPRO app source is used.

Runs only in GitHub Actions, with an existing ED25519 publisher key in Secrets.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pe_checks import inspect_exe

REPO = "gsmxr/XPRO-USB-V2-Updates"
EXPECTED_PUBLIC_FINGERPRINT = "584ce69f5f6d322e"
VERSION_PATTERN = re.compile(r"^2\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


def canonical_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def validate_version(version):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Version must be 2.x.y, e.g. 2.0.0 or 2.0.1")
    return tuple(map(int, version.split(".")))


def load_trusted_signer(encoded):
    if not encoded:
        raise ValueError("XPRO_SIGNING_KEY_B64 missing from GitHub Actions Secrets")
    pem = base64.b64decode(encoded, validate=True)
    signer = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(signer, Ed25519PrivateKey):
        raise ValueError("Signing key is not Ed25519")
    pub = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fingerprint = hashlib.sha256(pub).hexdigest()[:16]
    if fingerprint != EXPECTED_PUBLIC_FINGERPRINT:
        raise ValueError("Signing key does not match the pinned V2 trusted key fingerprint")
    return signer


def build_manifest(signer, exe_path, version, notes):
    validate_version(version)
    path = Path(exe_path)
    info = inspect_exe(path)
    size = info['size']
    print(f'[OK] Downloaded EXE: {path.name}; size={size:,} bytes, sha256={info["sha256"]}', flush=True)
    expected_name = f"XPRO_USB_{version}.exe"
    if path.name != expected_name:
        raise ValueError(f"Incorrect EXE asset filename; expected {expected_name}")
    payload = {
        "product": "xpro-usb",
        "version": version,
        "url": f"https://github.com/{REPO}/releases/download/v{version}/{expected_name}",
        "sha256": info["sha256"],
        "size": size,
        "notes": str(notes)[:300],
    }
    sig = signer.sign(canonical_bytes(payload))
    pub = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, canonical_bytes(payload))
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def main():
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise ValueError("Wrong GitHub repository")
    if os.environ.get("GITHUB_ACTOR", "").lower() != "gsmxr":
        raise ValueError("Only owner gsmxr may start release signing")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Only main branch may publish")
    version = os.environ["XPRO_VERSION"].strip()
    new_version = validate_version(version)
    tag = "v" + version
    releases = json.loads(gh("release", "list", "--repo", REPO,
                             "--json", "tagName,isDraft,isPrerelease", "--limit", "100"))
    existing_versions = []
    for release in releases:
        if release["isDraft"] or release["isPrerelease"]:
            continue
        old_tag = release["tagName"]
        if not old_tag.startswith("v"):
            raise ValueError("Unexpected published tag " + old_tag)
        existing_versions.append(validate_version(old_tag[1:]))
    if existing_versions and new_version <= max(existing_versions):
        raise ValueError("Version must be greater than all published V2 releases")

    release = json.loads(gh("release", "view", tag, "--repo", REPO,
                            "--json", "isDraft,isPrerelease,assets,tagName"))
    if not release["isDraft"] or release["isPrerelease"]:
        raise ValueError("Release must be draft and not prerelease")
    expected_name = f"XPRO_USB_{version}.exe"
    names = [x["name"] for x in release["assets"]]
    if names != [expected_name]:
        raise ValueError("Draft must contain exactly one file: " + expected_name)

    signer = load_trusted_signer(os.environ.get("XPRO_SIGNING_KEY_B64", ""))
    dest = Path(os.environ.get("RUNNER_TEMP", ".")) / "xpro_release"
    dest.mkdir(parents=True, exist_ok=True)
    advertised = release['assets'][0].get('size')
    print(f'[INFO] Draft asset {expected_name}: GitHub-reported size={advertised!r} bytes', flush=True)
    if isinstance(advertised, int) and advertised < 10000:
        raise ValueError(
            f'Draft EXE asset is only {advertised:,} bytes, so it is NOT a complete app. '
            'Re-upload the actual Windows dist EXE using UPLOAD_OR_REPAIR_DRAFT.bat, then rerun workflow.'
        )
    gh("release", "download", tag, "--repo", REPO,
       "--pattern", expected_name, "--dir", str(dest))
    exe = dest / expected_name
    if isinstance(advertised, int) and exe.stat().st_size != advertised:
        raise ValueError(f'Download size mismatch: GitHub reports {advertised:,} bytes, downloaded {exe.stat().st_size:,}; do not publish.')
    try:
        inspect_exe(exe)
    except ValueError as exc:
        raise ValueError(
            f'{exc}. Fix by running UPLOAD_OR_REPAIR_DRAFT.bat on your PC '
            'and selecting the actual tested dist EXE, then rerun this workflow.'
        ) from exc
    manifest = build_manifest(signer, exe, version, os.environ.get("XPRO_NOTES", "Stability improvements"))
    manifest_path = dest / "latest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    gh("release", "upload", tag, str(manifest_path), "--repo", REPO)

    # Verify the uploaded release asset list before making it publicly downloadable.
    updated = json.loads(gh("release", "view", tag, "--repo", REPO, "--json", "isDraft,assets"))
    if not updated["isDraft"] or set(x["name"] for x in updated["assets"]) != {expected_name, "latest.json"}:
        raise ValueError("Release asset list changed; keep draft for inspection")

    gh("release", "edit", tag, "--repo", REPO, "--draft=false", "--latest")
    print(f"SUCCESS: Signed and published {tag} with EXE + latest.json. No XPRO source uploaded.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
