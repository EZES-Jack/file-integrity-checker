"""Unit tests for integrity.py (standard library unittest)."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import integrity


class TempDirTestCase(unittest.TestCase):
    """Base class: gives each test a fresh temporary folder, cleaned up after."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        # The scanned folder; the baseline lives beside it, not inside it.
        self.folder = self.root / "data"
        self.folder.mkdir()
        self.baseline = self.root / "baseline.json"

    def write(self, relative, content=b"hello"):
        """Create a file (and any parent folders) inside the scanned folder."""
        path = self.folder / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class TestHashFile(TempDirTestCase):
    def test_known_value(self):
        # Published SHA-256 of the bytes b"hello".
        path = self.write("a.txt", b"hello")
        self.assertEqual(
            integrity.hash_file(path),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_empty_file(self):
        path = self.write("empty.txt", b"")
        self.assertEqual(
            integrity.hash_file(path),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_one_byte_change_changes_hash(self):
        a = self.write("a.txt", b"hello")
        b = self.write("b.txt", b"hellp")
        self.assertNotEqual(integrity.hash_file(a), integrity.hash_file(b))


class TestScanFolder(TempDirTestCase):
    def test_relative_paths_with_subfolders(self):
        self.write("top.txt")
        self.write("logs/app.log")
        result = integrity.scan_folder(self.folder)
        # Keys are relative, use "/", and the subfolder itself is not listed.
        self.assertEqual(set(result), {"top.txt", "logs/app.log"})

    def test_not_a_folder_raises(self):
        with self.assertRaises(NotADirectoryError):
            integrity.scan_folder(self.root / "does_not_exist")

    def test_skips_symlinks(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"secret")
        link = self.folder / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            # Windows needs special rights to create symlinks.
            self.skipTest("symlinks not available on this system")
        self.assertNotIn("link.txt", integrity.scan_folder(self.folder))


class TestBaselineFile(TempDirTestCase):
    def test_round_trip(self):
        hashes = {"a.txt": "abc", "logs/app.log": "def"}
        integrity.save_baseline(hashes, self.baseline)
        self.assertEqual(integrity.load_baseline(self.baseline), hashes)

    def test_rejects_wrong_algorithm(self):
        self.baseline.write_text(json.dumps({"algorithm": "md5", "files": {}}))
        with self.assertRaises(ValueError):
            integrity.load_baseline(self.baseline)

    def test_rejects_malformed_files_section(self):
        bad = {"algorithm": "sha256", "files": {"a.txt": 123}}  # hash not a string
        self.baseline.write_text(json.dumps(bad))
        with self.assertRaises(ValueError):
            integrity.load_baseline(self.baseline)

    def test_rejects_invalid_json(self):
        self.baseline.write_text("{ not json")
        # JSONDecodeError is a subclass of ValueError, which main() catches.
        with self.assertRaises(ValueError):
            integrity.load_baseline(self.baseline)


class TestCompareHashes(unittest.TestCase):
    def test_detects_added_modified_deleted(self):
        baseline = {"same.txt": "1", "changed.txt": "2", "gone.txt": "3"}
        current = {"same.txt": "1", "changed.txt": "X", "new.txt": "4"}
        added, modified, deleted = integrity.compare_hashes(baseline, current)
        self.assertEqual(added, ["new.txt"])
        self.assertEqual(modified, ["changed.txt"])
        self.assertEqual(deleted, ["gone.txt"])

    def test_no_changes(self):
        same = {"a.txt": "1"}
        self.assertEqual(integrity.compare_hashes(same, dict(same)), ([], [], []))


class TestIsInside(TempDirTestCase):
    def test_inside(self):
        self.assertTrue(integrity.is_inside(self.folder / "baseline.json", self.folder))

    def test_outside(self):
        self.assertFalse(integrity.is_inside(self.baseline, self.folder))


class TestCli(TempDirTestCase):
    def run_cli(self, *args):
        """Run main() with fake command-line arguments; return (code, out, err)."""
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["integrity.py", *args]), \
                redirect_stdout(out), redirect_stderr(err):
            code = integrity.main()
        return code, out.getvalue(), err.getvalue()

    def test_clean_check_returns_zero(self):
        self.write("a.txt")
        self.run_cli("baseline", str(self.folder), "-b", str(self.baseline))
        code, out, _ = self.run_cli("check", str(self.folder), "-b", str(self.baseline))
        self.assertEqual(code, 0)
        self.assertIn("No changes detected", out)

    def test_check_detects_changes_and_returns_one(self):
        self.write("a.txt")
        self.write("b.txt")
        self.run_cli("baseline", str(self.folder), "-b", str(self.baseline))
        self.write("a.txt", b"changed")   # modified
        self.write("c.txt")               # added
        (self.folder / "b.txt").unlink()  # deleted
        code, out, _ = self.run_cli("check", str(self.folder), "-b", str(self.baseline))
        self.assertEqual(code, 1)
        self.assertIn("added:    c.txt", out)
        self.assertIn("modified: a.txt", out)
        self.assertIn("deleted:  b.txt", out)

    def test_refuses_overwrite_without_force(self):
        self.write("a.txt")
        self.run_cli("baseline", str(self.folder), "-b", str(self.baseline))
        code, _, err = self.run_cli("baseline", str(self.folder), "-b", str(self.baseline))
        self.assertEqual(code, 2)
        self.assertIn("--force", err)

    def test_rejects_baseline_inside_scanned_folder(self):
        inside = self.folder / "baseline.json"
        code, _, err = self.run_cli("baseline", str(self.folder), "-b", str(inside))
        self.assertEqual(code, 2)
        self.assertIn("outside", err)


if __name__ == "__main__":
    unittest.main()