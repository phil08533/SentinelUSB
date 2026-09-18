import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "live-build/config/includes.chroot/usr/local/lib/sentinelusb"))
import scanner


class ScannerTests(unittest.TestCase):
    def test_detect_windows(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Windows").mkdir()
            (root / "Users").mkdir()
            self.assertEqual(scanner.detect_os(root), "Windows")

    def test_detect_linux(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "etc").mkdir()
            (root / "etc/os-release").write_text("NAME=test")
            (root / "etc/systemd").mkdir()
            (root / "usr/bin").mkdir(parents=True)
            (root / "var").mkdir()
            self.assertEqual(scanner.detect_os(root), "Linux")

    def test_detect_macos(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "System/Library").mkdir(parents=True)
            (root / "Library").mkdir()
            (root / "Users").mkdir()
            (root / "Applications").mkdir()
            self.assertEqual(scanner.detect_os(root), "macOS")

    def test_unknown_volume(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scanner.detect_os(Path(d)), "Unknown")

    @patch("scanner.run")
    def test_normal_mount_is_read_only(self, mocked_run):
        mocked_run.side_effect = [
            type("R", (), {"returncode": 0, "stdout": "ntfs\n", "stderr": ""})(),
            type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        ]
        with patch("scanner.Path") as _:
            pass
        # Command construction is checked through the real function with a temporary mountpoint.
        with tempfile.TemporaryDirectory() as mount_parent:
            with patch("scanner.tempfile.mkdtemp", return_value=mount_parent):
                point = scanner.mount_read_only("/dev/test")
                self.assertEqual(point, Path(mount_parent))
        mount_cmd = mocked_run.call_args_list[1].args[0]
        self.assertIn("ro", mount_cmd[2])
        self.assertIn("nosuid", mount_cmd[2])
        self.assertIn("nodev", mount_cmd[2])
        self.assertIn("noexec", mount_cmd[2])

    def test_finding_paths_are_portable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            findings = [{"path": str(root / "Windows" / "bad.exe")}]
            scanner.normalize_finding_paths(findings, root)
            self.assertEqual(findings[0]["path"], "Windows/bad.exe")

    def test_html_escapes_report_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.html"
            report = {
                "device": "/dev/test",
                "os": "Windows",
                "finding_count": 1,
                "started_at": "now",
                "completed_at": "now",
                "findings": [{
                    "engine": "test",
                    "severity": "medium",
                    "reason": "<script>alert(1)</script>",
                    "path": "x",
                }],
            }
            scanner.write_html(report, path)
            text = path.read_text()
            self.assertNotIn("<script>alert(1)</script>", text)
            self.assertIn("&lt;script&gt;", text)


if __name__ == "__main__":
    unittest.main()
