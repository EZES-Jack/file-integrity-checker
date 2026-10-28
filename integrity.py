"""File integrity checker: hash files, save a baseline, report changes."""
import hashlib
from pathlib import Path

# Read files in 64 KB chunks so a huge file never has to fit in memory.
CHUNK_SIZE = 65536


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
    # rglob("*") walk the folder and its subfolders; sorted() makes the order the same on each run
    for path in sorted(folder.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue

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



# Temporary demo;
if __name__ == "__main__":
    # Build paths from this script's location, so it works from any folder.
    here = Path(__file__).resolve().parent
    hashes = scan_folder(here / "sample_data")

    save_baseline(hashes, here / "baseline.json")
    loaded = load_baseline(here / "baseline.json")

    # A save/load round trip must give back exactly what we saved.
    print("Round trip OK:", loaded == hashes)