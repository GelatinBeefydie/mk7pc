"""
make_manifest.py - builds manifest.json from a folder of YOUR runtime files.

  python make_manifest.py <folder> <base_url> [--version 0.1.0] [--entry mk7pc.exe]

Example:
  python make_manifest.py ./release https://raw.githubusercontent.com/you/mk7pc/main/release

Every file under <folder> is listed with its SHA-256 and url = <base_url>/<relative path>.
Add the "known_roms" hashes by hand afterwards (sha256 of dumps you've verified).
"""
import hashlib
import json
import os
import sys


def main():
    if len(sys.argv) < 3 or not sys.argv[2].startswith("https://"):
        sys.exit(__doc__)
    folder, base = sys.argv[1], sys.argv[2].rstrip("/")
    version = sys.argv[sys.argv.index("--version") + 1] if "--version" in sys.argv else "0.1.0"
    entry = sys.argv[sys.argv.index("--entry") + 1] if "--entry" in sys.argv else "mk7pc.exe"
    files = []
    for root, _, names in os.walk(folder):
        for n in sorted(names):
            full = os.path.join(root, n)
            rel = os.path.relpath(full, folder).replace(os.sep, "/")
            if rel == "manifest.json":
                continue
            with open(full, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            files.append({"path": rel, "url": base + "/" + rel, "sha256": digest})
    manifest = {"version": version, "entry": entry, "known_roms": {}, "files": files}
    out = os.path.join(folder, "manifest.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print("Wrote", out, "with", len(files), "file(s)")


if __name__ == "__main__":
    main()
