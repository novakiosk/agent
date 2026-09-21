#!/usr/bin/env python3
"""Check the checkout's version, then let GitHub CLI create and upload its release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote


def api(endpoint, *options):
    return json.loads(subprocess.check_output(["gh", "api", endpoint, *options], text=True))


def version():
    value = Path("VERSION").read_text().strip()
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value):
        raise RuntimeError("VERSION must contain a stable major.minor.patch release version")
    return value


def main():
    mode = sys.argv[1]
    if mode == "version":
        print(version())
        return
    if mode not in ("check", "publish"):
        raise RuntimeError("Expected check or publish")
    value = version()
    tag = "v" + value
    repo = "repos/" + os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    pages = api(f"{repo}/releases?per_page=100", "--paginate", "--slurp")
    matches = [release for page in pages for release in page if release["tag_name"] == tag]
    if any(release["draft"] for release in matches):
        raise RuntimeError(f"{tag} has an unfinished draft; review/remove it manually, then retry")
    if matches:
        print(f"{tag} is already published; nothing to change")
        if mode == "check":
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("build=false\n")
        return
    refs = api(f"{repo}/git/matching-refs/tags/{quote(tag, safe='')}")
    if any(ref["ref"] == "refs/tags/" + tag for ref in refs):
        raise RuntimeError(f"{tag} already exists without a published release; review/remove it manually, then retry")
    if mode == "check":
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"build=true\nversion={value}\n")
        return
    archive = Path(f"dist/novakiosk-agent-{value}-linux-x86_64.tar.gz")
    if not archive.is_file():
        raise RuntimeError(f"Expected release archive: {archive}")
    checksum = Path("dist/SHA256SUMS")
    if checksum.read_text() != f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n":
        raise RuntimeError("Release archive checksum mismatch")
    command = ["gh", "release", "create", tag, str(archive), str(checksum),
               "--repo", os.environ["GITHUB_REPOSITORY"], "--target", sha,
               "--title", "NOVA Kiosk Agent " + value,
               "--notes", f"Static Linux x86_64 agent for NOVA Kiosk and Print Bridge.\nSource: {sha}"]
    # gh creates a draft, uploads the supplied assets, then publishes it.
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
