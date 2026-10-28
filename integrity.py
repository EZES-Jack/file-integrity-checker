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


# Temporary demo; the CLI replaces it in Step 6.
if __name__ == "__main__":
    # Build the path from this script's location, so it works from any folder.
    sample = Path(__file__).resolve().parent / "sample_data" / "notes.txt"
    print(hash_file(sample))