"""File integrity checker: hash files, save a baseline, report changes."""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Read files in 64 KB chunks so a huge file never has to fit in memory.
CHUNK_SIZE = 65536
# Recorded in the baseline so future versions can tell which hash was used.
ALGORITHM = "sha256"


def hash_file(path):
    """Return the SHA-256 hex digest of a file."""
    sha256 = hashlib.sha256()
    # "rb" (binary) hashes the exact bytes. Text mode could alter line
    # endings and change the hash between operating systems.
    with open(path, "rb") as f:
        # iter(callable, sentinel) calls f.read repeatedly and stops when it
        # returns b"" (end of file).
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256.update(chunk)  # feeds each chunk into the running hash
    return sha256.hexdigest()


def scan_folder(folder):
    """Return a dict mapping file paths to their SHA-256 hex digest."""
    folder = Path(folder)
    if not folder.is_dir():
        raise NotADirectoryError(f"is not a folder: {folder}")

    hashes = {}
    # rglob("*") walks the folder and its subfolders; sorted() makes the order the same on each run
    for path in sorted(folder.rglob("*")):
        # Skip symlinks (they could point outside the folder) and folders.
        if path.is_symlink() or not path.is_file():
            continue

        # as_posix() uses "/" on every OS, so baselines match across Windows and Linux.
        key = path.relative_to(folder).as_posix()
        hashes[key] = hash_file(path)
    return hashes


def save_baseline(hashes, baseline_path):
    """Write the hashes to a JSON baseline file."""
    data = {
        "algorithm": ALGORITHM,
        # UTC avoids confusion about time zones if the baseline is shared.
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": hashes,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        # indent makes the file readable; sort_keys keeps its layout stable.
        json.dump(data, f, indent=2, sort_keys=True)


def load_baseline(baseline_path):
    """Read a baseline file and return its {relative_path: sha256} dict."""
    with open(baseline_path, encoding="utf-8") as f:
        data = json.load(f)  # raises JSONDecodeError (a ValueError) if corrupt

    # The baseline is untrusted input too: check its shape before using it.
    if not isinstance(data, dict) or data.get("algorithm") != ALGORITHM:
        raise ValueError("baseline is not a valid sha256 baseline")
    files = data.get("files")
    if not isinstance(files, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in files.items()
    ):
        raise ValueError("baseline 'files' section is malformed")
    return files


def compare_hashes(baseline, current):
    """Return (added, modified, deleted) as sorted lists of relative paths."""
    # Dict keys behave like sets, so set maths finds the differences directly.
    added = sorted(current.keys() - baseline.keys())      # only in the new scan
    deleted = sorted(baseline.keys() - current.keys())    # only in the baseline
    # In both, but the hash differs: the contents changed.
    modified = sorted(
        name for name in baseline.keys() & current.keys()
        if baseline[name] != current[name]
    )
    return added, modified, deleted


def build_report(folder, added, modified, deleted):
    """Return the change report as a single string."""
    lines = [
        "File integrity check",
        f"Folder: {folder}",
        f"Added: {len(added)}  Modified: {len(modified)}  Deleted: {len(deleted)}",
    ]
    if not (added or modified or deleted):
        lines.append("No changes detected.")
        return "\n".join(lines)

    lines.append("")
    # Each prefix makes the change type visible at a glance.
    lines += [f"  + added:    {name}" for name in added]
    lines += [f"  ~ modified: {name}" for name in modified]
    lines += [f"  - deleted:  {name}" for name in deleted]
    return "\n".join(lines)


def is_inside(path, folder):
    """Return True if path is located inside folder."""
    try:
        # resolve() makes both paths absolute, so ".." tricks can't fool us.
        path.resolve().relative_to(folder.resolve())
        return True
    except ValueError:  # relative_to raises ValueError when not inside
        return False


def main():
    # Options shared by both subcommands.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("folder", help="folder to scan")
    common.add_argument(
        "-b", "--baseline", default="baseline.json",
        help="baseline file to write or read (default: baseline.json)",
    )

    parser = argparse.ArgumentParser(
        description="Detect added, modified and deleted files using SHA-256 baselines."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("baseline", parents=[common], help="record a new baseline")
    create.add_argument(
        "--force", action="store_true", help="overwrite an existing baseline file"
    )
    sub.add_parser("check", parents=[common], help="compare the folder to the baseline")

    args = parser.parse_args()
    folder = Path(args.folder)
    baseline_path = Path(args.baseline)

    try:
        # A baseline inside the scanned folder would change the folder it
        # describes, so every check would report a change.
        if is_inside(baseline_path, folder):
            print("Error: keep the baseline file outside the scanned folder.", file=sys.stderr)
            return 2

        current = scan_folder(folder)

        if args.command == "baseline":
            # Silently replacing a baseline could hide tampering, so make it explicit.
            if baseline_path.exists() and not args.force:
                print(f"Error: {baseline_path} already exists (use --force to overwrite).", file=sys.stderr)
                return 2
            save_baseline(current, baseline_path)
            print(f"Baseline saved: {len(current)} files -> {baseline_path}")
            return 0

        baseline = load_baseline(baseline_path)
    except (OSError, ValueError) as err:
        # OSError: missing or unreadable files. ValueError: corrupt baseline.
        print(f"Error: {err}", file=sys.stderr)
        return 2

    added, modified, deleted = compare_hashes(baseline, current)
    print(build_report(folder, added, modified, deleted))
    # Exit code 1 means "changes found", so scripts and schedulers can react.
    return 1 if (added or modified or deleted) else 0


if __name__ == "__main__":
    sys.exit(main())