\# File Integrity Checker



A small command-line tool that hashes every file in a folder with SHA-256, saves

a baseline to JSON, and on a later run reports which files were added, modified

or deleted. This is the same idea behind tools like Tripwire and AIDE, and it is

useful in digital forensics for showing that evidence has not changed.



> \*\*Authorised use only.\*\* Use this tool only on systems and folders you own or

> have explicit permission to test. The sample data in this repo is fake.



\## What it does



\- Hashes every regular file under a folder (including subfolders) with SHA-256

\- Stores relative paths, so a baseline still works if the folder is moved

\- Saves the baseline as JSON, with the algorithm and a UTC creation time

\- Compares a later scan to the baseline and reports added, modified and deleted files

\- Skips symlinks, so the scan cannot wander outside the chosen folder

\- Refuses to overwrite a baseline without `--force`, and refuses a baseline

&#x20; stored inside the scanned folder



Standard library only. Requires Python 3.8+.



\## How to run



```

python integrity.py baseline sample\_data      # record a baseline

python integrity.py check sample\_data         # compare against it

python integrity.py baseline sample\_data --force   # replace the baseline

python integrity.py check sample\_data -b other.json   # use another baseline file

python integrity.py --help

```



Review the `check` report before replacing a baseline. A new baseline treats

every current file as normal.



| Exit code | Meaning |

|---|---|

| 0 | No changes |

| 1 | Changes found |

| 2 | Error (bad folder, bad baseline, overwrite refused) |



\## Example output



```

File integrity check

Folder: sample\_data

Added: 1  Modified: 1  Deleted: 1



&#x20; + added:    new.txt

&#x20; \~ modified: notes.txt

&#x20; - deleted:  config.ini

```



\## Tests



```

python -m unittest -v

```



\## Limitations



\- The baseline is not signed. Anyone who can change the files can also change

&#x20; the baseline, so keep it somewhere they cannot reach (read-only or offline)

\- A renamed file appears as one deletion and one addition

\- Permissions, ownership and timestamps are not recorded

\- Symlinks are skipped

\- The whole folder is rescanned each time (no incremental scanning)



## What I learned

- **Hashes detect tampering better than timestamps.** SHA-256 changes completely if even one byte changes, whereas a modified time can be faked. I chose SHA-256 over MD5 and SHA-1 because those are broken for integrity checking.
- **Reading files in chunks, in binary mode, keeps hashing correct and efficient.** Chunks keep memory use constant for any file size, and binary mode hashes the exact bytes, regardless of operating system line endings.
- **Safe defaults matter in a security tool.** Baselines use relative paths so they survive a move, symlinks are skipped so the scan can't leave the folder, and a baseline can't be overwritten without `--force` or stored inside the scanned folder.
- **Exit codes make a tool usable in automation.** 0 means no changes, 1 means changes found, and 2 means an error, so a scheduled job can react without parsing text.
- **Debugging and testing.** I fixed a missing colon, missing imports and a constant that wasn't defined, and learned that a CLI needs arguments when run. Unit tests with temporary folders let me check failure paths without touching real files.
- **Next steps:** sign the baseline, detect renames by matching hashes, and add JSON output.

