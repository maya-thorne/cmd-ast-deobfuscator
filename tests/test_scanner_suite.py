"""
Unit and integration test suite for the high-throughput batch file directory
scanner and bulk deobfuscation pipeline (M17).
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from src.scanner import (
    DirectoryScanner,
    FileCollector,
    ScannerWorker,
    ScanConfig,
    ScanItem,
    ScanSummary,
    FileScanStatus,
    compute_sha256,
    compute_shannon_entropy,
)
from src.cli import main as cli_main


class TestScannerSuite(unittest.TestCase):
    """Test suite for FileCollector, ScannerWorker, DirectoryScanner, and CLI integration."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cmd_scanner_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_file(self, rel_path: str, content: str, encoding: str = "utf-8") -> str:
        full_path = os.path.join(self.test_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding=encoding, errors="replace") as f:
            f.write(content)
        return full_path

    # =========================================================================
    # 1. FileCollector Tests
    # =========================================================================

    def test_collector_basic_discovery(self):
        """Verify discovery of target batch extensions while ignoring others."""
        self._create_sample_file("test1.bat", "echo 1")
        self._create_sample_file("test2.cmd", "echo 2")
        self._create_sample_file("test3.btm", "echo 3")
        self._create_sample_file("ignored.txt", "text")
        self._create_sample_file("ignored.ps1", "powershell")

        cfg = ScanConfig(input_dir=self.test_dir)
        files = FileCollector.collect(cfg)

        basenames = [os.path.basename(f) for f in files]
        self.assertEqual(len(files), 3)
        self.assertIn("test1.bat", basenames)
        self.assertIn("test2.cmd", basenames)
        self.assertIn("test3.btm", basenames)
        self.assertNotIn("ignored.txt", basenames)

    def test_collector_recursive_and_depth_limits(self):
        """Verify recursive traversal and maximum depth restrictions."""
        self._create_sample_file("root.bat", "root")
        self._create_sample_file(os.path.join("sub1", "l1.bat"), "l1")
        self._create_sample_file(os.path.join("sub1", "sub2", "l2.bat"), "l2")
        self._create_sample_file(os.path.join("sub1", "sub2", "sub3", "l3.bat"), "l3")

        # Non-recursive
        cfg_non_rec = ScanConfig(input_dir=self.test_dir, recursive=False)
        files_non_rec = FileCollector.collect(cfg_non_rec)
        self.assertEqual(len(files_non_rec), 1)
        self.assertEqual(os.path.basename(files_non_rec[0]), "root.bat")

        # Depth = 1 (root + sub1)
        cfg_depth1 = ScanConfig(input_dir=self.test_dir, max_depth=1)
        files_depth1 = FileCollector.collect(cfg_depth1)
        basenames_d1 = [os.path.basename(f) for f in files_depth1]
        self.assertIn("root.bat", basenames_d1)
        self.assertIn("l1.bat", basenames_d1)
        self.assertNotIn("l2.bat", basenames_d1)
        self.assertNotIn("l3.bat", basenames_d1)

    def test_collector_directory_exclusions(self):
        """Verify excluded directories (.git, node_modules, custom) are skipped."""
        self._create_sample_file("valid.bat", "valid")
        self._create_sample_file(os.path.join(".git", "hooks", "hook.bat"), "git hook")
        self._create_sample_file(os.path.join("node_modules", "pkg", "run.bat"), "npm")
        self._create_sample_file(os.path.join("custom_skip", "skip.bat"), "skip")

        cfg = ScanConfig(
            input_dir=self.test_dir,
            exclude_patterns=[".git", "node_modules", "custom_skip"]
        )
        files = FileCollector.collect(cfg)
        self.assertEqual(len(files), 1)
        self.assertEqual(os.path.basename(files[0]), "valid.bat")

    # =========================================================================
    # 2. ScannerWorker & Multi-Encoding Ingestion Tests
    # =========================================================================

    def test_worker_multi_encoding_reading(self):
        """Verify safe reading of scripts encoded in UTF-8 BOM, CP437, and Latin-1."""
        utf8_bom_path = os.path.join(self.test_dir, "bom.bat")
        with open(utf8_bom_path, "wb") as f:
            f.write("set A=Hello".encode("utf-8-sig"))

        text, enc, sz = ScannerWorker.read_file_multi_encoding(
            utf8_bom_path, ["utf-8-sig", "utf-8", "cp437"]
        )
        self.assertEqual(enc, "utf-8-sig")
        self.assertEqual(text.strip(), "set A=Hello")

    def test_worker_deobfuscation_transform(self):
        """Verify single-file deobfuscation of caret and slicing obfuscations."""
        obf_script = (
            '@echo off\n'
            'set "a=c"\n'
            'set "b=m"\n'
            'set "c=d"\n'
            '^%a^%^%b^%^%c^% /c whoami\n'
        )
        sample_path = self._create_sample_file("obf.bat", obf_script)
        cfg = ScanConfig(input_dir=self.test_dir, dry_run=True)

        item = ScannerWorker.process_file(sample_path, cfg)
        self.assertEqual(item.status, FileScanStatus.SUCCESS)
        self.assertGreater(item.nodes_before, 0)
        self.assertGreater(item.entropy_before, 0.0)
        self.assertIsNotNone(item.sha256_original)
        self.assertIsNotNone(item.sha256_deobfuscated)

    def test_worker_unchanged_file(self):
        """Verify that an already clean script is classified as UNCHANGED."""
        clean_script = '@echo off\necho hello world\n'
        sample_path = self._create_sample_file("clean.bat", clean_script)
        cfg = ScanConfig(input_dir=self.test_dir, dry_run=True)

        item = ScannerWorker.process_file(sample_path, cfg)
        self.assertEqual(item.status, FileScanStatus.UNCHANGED)

    def test_worker_file_size_cap(self):
        """Verify that files exceeding max_file_size are skipped safely."""
        large_script = "echo " + ("A" * 2000)
        sample_path = self._create_sample_file("large.bat", large_script)
        cfg = ScanConfig(input_dir=self.test_dir, max_file_size=500, dry_run=True)

        item = ScannerWorker.process_file(sample_path, cfg)
        self.assertEqual(item.status, FileScanStatus.SKIPPED)
        self.assertIn("exceeds maximum size", item.error_message)

    def test_worker_in_place_and_backup(self):
        """Verify in-place script overwriting and .bak backup generation."""
        obf_script = 'set "X=c"\nset "Y=md"\n%X%%Y%\n'
        sample_path = self._create_sample_file("inplace.bat", obf_script)

        cfg = ScanConfig(input_dir=self.test_dir, in_place=True, backup=True)
        item = ScannerWorker.process_file(sample_path, cfg)

        self.assertEqual(item.status, FileScanStatus.SUCCESS)
        # Verify backup was created
        bak_file = f"{sample_path}.bak"
        self.assertTrue(os.path.exists(bak_file))
        with open(bak_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), obf_script)

        # Verify target file was updated
        with open(sample_path, "r", encoding="utf-8") as f:
            deob_content = f.read()
        self.assertIn("cmd", deob_content)

    def test_worker_output_dir_mirroring(self):
        """Verify output directory creation and relative structure mirroring."""
        obf_script = 'set "K=whoami"\n%K%\n'
        nested_path = self._create_sample_file(os.path.join("tier1", "tier2", "deep.bat"), obf_script)

        out_dir = os.path.join(self.test_dir, "output_export")
        cfg = ScanConfig(input_dir=self.test_dir, output_dir=out_dir)

        item = ScannerWorker.process_file(nested_path, cfg)
        self.assertEqual(item.status, FileScanStatus.SUCCESS)

        mirrored_file = os.path.join(out_dir, "tier1", "tier2", "deep.bat")
        self.assertTrue(os.path.exists(mirrored_file))
        with open(mirrored_file, "r", encoding="utf-8") as f:
            self.assertIn("whoami", f.read())

    # =========================================================================
    # 3. DirectoryScanner Pipeline & Aggregates Tests
    # =========================================================================

    def test_directory_scanner_multi_file_pipeline(self):
        """Verify end-to-end bulk scanning across multiple files with progress callbacks."""
        self._create_sample_file("s1.bat", 'set "a=c"\nset "b=md"\n%a%%b%')
        self._create_sample_file("s2.bat", '@echo off\necho already clean')
        self._create_sample_file(os.path.join("nested", "s3.cmd"), 'set "p=calc"\n%p%')

        out_dir = os.path.join(self.test_dir, "dist")
        cfg = ScanConfig(input_dir=self.test_dir, output_dir=out_dir, workers=2)

        progress_log = []

        def cb(item, cur, total):
            progress_log.append((item.relative_path, cur, total))

        scanner = DirectoryScanner(cfg)
        summary = scanner.scan_and_deobfuscate(cfg, progress_callback=cb)

        self.assertEqual(summary.total_files_discovered, 3)
        self.assertEqual(summary.total_files_processed, 3)
        self.assertEqual(summary.successful_count, 2)
        self.assertEqual(summary.unchanged_count, 1)
        self.assertEqual(summary.failed_count, 0)
        self.assertEqual(len(progress_log), 3)
        self.assertGreater(summary.throughput_files_sec, 0.0)

    def test_directory_scanner_reports_export(self):
        """Verify JSON, CSV, and Markdown report generation and serialization."""
        self._create_sample_file("rep1.bat", 'set "s=echo 123"\n%s%')
        cfg = ScanConfig(input_dir=self.test_dir, dry_run=True)

        scanner = DirectoryScanner(cfg)
        summary = scanner.scan_and_deobfuscate(cfg)

        json_out = os.path.join(self.test_dir, "report.json")
        csv_out = os.path.join(self.test_dir, "report.csv")
        md_out = os.path.join(self.test_dir, "report.md")

        DirectoryScanner.export_reports(summary, json_path=json_out, csv_path=csv_out, markdown_path=md_out)

        self.assertTrue(os.path.exists(json_out))
        self.assertTrue(os.path.exists(csv_out))
        self.assertTrue(os.path.exists(md_out))

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["total_files_processed"], 1)

        with open(csv_out, "r", encoding="utf-8") as f:
            csv_lines = f.readlines()
            self.assertGreaterEqual(len(csv_lines), 2)

        with open(md_out, "r", encoding="utf-8") as f:
            md_text = f.read()
            self.assertIn("# Batch Directory Deobfuscation Scan Report", md_text)

    def test_directory_scanner_zeroize(self):
        """Verify memory zeroization of scan items and summary."""
        item = ScanItem(
            file_path="secret/path/test.bat",
            relative_path="test.bat",
            status=FileScanStatus.SUCCESS,
            sha256_original="1234567890abcdef" * 4,
            sha256_deobfuscated="fedcba0987654321" * 4,
            error_message="diagnostic detail",
            passes_modified=["Pass1", "Pass2"]
        )
        summary = ScanSummary(items=[item])
        self.assertEqual(len(summary.items), 1)

        summary.zeroize()
        self.assertEqual(len(summary.items), 0)
        self.assertEqual(item.sha256_original, "0" * 64)
        self.assertEqual(item.error_message, "")
        self.assertEqual(len(item.passes_modified), 0)

    # =========================================================================
    # 4. CLI Integration Tests
    # =========================================================================

    def test_cli_scan_dir_dry_run_and_reports(self):
        """Verify CLI execution with --scan-dir, --dry-run, and report outputs."""
        self._create_sample_file("cli_sample.bat", 'set "Z=dir"\n%Z%')
        rep_json = os.path.join(self.test_dir, "cli_rep.json")

        old_argv = sys.argv
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            sys.argv = [
                "cli.py",
                "--scan-dir", self.test_dir,
                "--dry-run",
                "--report-json", rep_json,
                "-q"
            ]
            with self.assertRaises(SystemExit) as cm:
                cli_main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

        self.assertTrue(os.path.exists(rep_json))
        with open(rep_json, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["total_files_discovered"], 1)
            self.assertEqual(data["successful_count"], 1)

    def test_cli_scan_dir_with_output_dir(self):
        """Verify CLI execution with --scan-dir and --output-dir."""
        self._create_sample_file("cli_out_sample.bat", 'set "V=hostname"\n%V%')
        target_dir = os.path.join(self.test_dir, "cli_destination")

        old_argv = sys.argv
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            sys.argv = [
                "cli.py",
                "--scan-dir", self.test_dir,
                "--output-dir", target_dir,
                "-q"
            ]
            with self.assertRaises(SystemExit) as cm:
                cli_main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

        expected_dest = os.path.join(target_dir, "cli_out_sample.bat")
        self.assertTrue(os.path.exists(expected_dest))
        with open(expected_dest, "r", encoding="utf-8") as f:
            self.assertIn("hostname", f.read())


if __name__ == "__main__":
    unittest.main()
