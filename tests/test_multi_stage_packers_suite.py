"""
Unit and Integration Test Suite for Multi-Stage Batch Packer Engine (Milestone M21).
Validates PowerShell base64/deflate decoding, echo dropper reassembly, cascading multi-tier
unpacking, cycle detection, DoS payload limits, entropy calculation, zeroize, and CLI flags.
"""

import base64
import gzip
import io
import json
import subprocess
import sys
import unittest
import zlib

from src.packers.models import (
    PackerType,
    PackerSignature,
    PackerMetrics,
    LayerTransition,
    LayeredUnpackResult,
)
from src.packers.heuristics import PackerHeuristicDetector
from src.packers.detector import PackerSignatureDetector
from src.packers.engine import MultiStagePackerEngine, compute_shannon_entropy
from src.packers.unpacker import PackerUnpacker


class TestMultiStagePackersSuite(unittest.TestCase):
    """Comprehensive test suite for Milestone M21 multi-stage packing and unpacking."""

    def setUp(self):
        self.detector = PackerSignatureDetector()
        self.engine = MultiStagePackerEngine(detector=self.detector)
        self.unpacker = PackerUnpacker(detector=self.detector, engine=self.engine)

    # 1. PowerShell Base64 (-enc) Unpacking
    def test_powershell_base64_unpacking(self):
        target_payload = "@echo off\nwhoami /all\nnet localgroup administrators\n"
        # PowerShell EncodedCommand requires UTF-16LE base64
        utf16le_bytes = target_payload.encode("utf-16le")
        b64_str = base64.b64encode(utf16le_bytes).decode("ascii")

        wrapped_script = (
            "@echo off\n"
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {b64_str}\n"
        )

        res = self.engine.unpack(wrapped_script)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.layers_unpacked, 1)
        self.assertEqual(res.transitions[0].from_packer, PackerType.POWERSHELL_BASE64)
        self.assertEqual(res.transitions[0].unpacker_strategy, "powershell_base64_decode")
        self.assertIn("whoami /all", res.final_source)
        self.assertIn("net localgroup administrators", res.final_source)

    # 2. PowerShell Deflate / GZip Stream Unpacking
    def test_powershell_deflate_stream_unpacking(self):
        target_payload = "@echo off\necho Running In-Memory Payload\ndir C:\\Windows\n"
        # Compress with raw Deflate (-MAX_WBITS)
        raw_deflate = zlib.compress(target_payload.encode("utf-8"))[2:-4]  # raw deflate stream
        b64_compressed = base64.b64encode(raw_deflate).decode("ascii")

        powershell_stub = (
            "@echo off\n"
            f"$ms = [Convert]::FromBase64String('{b64_compressed}');\n"
            "$ds = New-Object IO.Compression.DeflateStream(New-Object IO.MemoryStream(,$ms), "
            "[IO.Compression.CompressionMode]::Decompress);\n"
            "(New-Object IO.StreamReader($ds)).ReadToEnd() | iex\n"
        )

        res = self.engine.unpack(powershell_stub)
        self.assertTrue(res.is_packed)
        self.assertGreaterEqual(res.layers_unpacked, 1)
        self.assertEqual(res.transitions[0].from_packer, PackerType.POWERSHELL_DEFLATE)
        self.assertEqual(res.transitions[0].unpacker_strategy, "powershell_deflate_decompress")
        self.assertIn("Running In-Memory Payload", res.final_source)
        self.assertIn("dir C:\\Windows", res.final_source)

    def test_powershell_gzip_stream_unpacking(self):
        target_payload = "@echo off\nwhoami\nnet user\n"
        gzip_bytes = gzip.compress(target_payload.encode("utf-8"))
        b64_gzip = base64.b64encode(gzip_bytes).decode("ascii")

        gzip_stub = (
            "@echo off\n"
            f"[System.Convert]::FromBase64String('{b64_gzip}')\n"
            "New-Object System.IO.Compression.GZipStream($s, [IO.Compression.CompressionMode]::Decompress)\n"
        )

        res = self.engine.unpack(gzip_stub)
        self.assertTrue(res.is_packed)
        self.assertIn("whoami", res.final_source)
        self.assertIn("net user", res.final_source)

    # 3. Echo Dropper Payload Reassembly
    def test_echo_dropper_payload_reassembly(self):
        dropper_script = (
            "@echo off\n"
            ":: Staging drop sequence\n"
            "echo @echo off > %TEMP%\\stage.bat\n"
            "echo echo Staged Dropper Execution >> %TEMP%\\stage.bat\n"
            "echo whoami /priv ^> privs.txt >> %TEMP%\\stage.bat\n"
            "echo net user Guest /active:no >> %TEMP%\\stage.bat\n"
            "call %TEMP%\\stage.bat\n"
        )

        # Detect echo dropper
        detection = self.detector.detect(dropper_script)
        self.assertTrue(detection.is_packed)
        has_echo = any(s.packer_type == PackerType.ECHO_DROPPER for s in detection.detected_signatures)
        self.assertTrue(has_echo)

        # Unpack echo dropper
        res = self.engine.unpack(dropper_script)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.layers_unpacked, 1)
        self.assertEqual(res.transitions[0].unpacker_strategy, "echo_dropper_stage_assembler")
        self.assertIn("Staged Dropper Execution", res.final_source)
        self.assertIn("whoami /priv > privs.txt", res.final_source)
        self.assertIn("net user Guest /active:no", res.final_source)

    # 4. CertUtil Multi-Tier Cascading Unpack (Layer 1 CertUtil -> Layer 2 PowerShell -> Layer 3 Clean Batch)
    def test_certutil_multi_tier_cascading_unpack(self):
        # Layer 3: Clean Batch Payload
        layer3_clean = "@echo off\necho Clean Core Payload\nnet user Administrator\n"

        # Layer 2: PowerShell UTF-16LE Base64 Wrapper enclosing Layer 3
        layer2_b64 = base64.b64encode(layer3_clean.encode("utf-16le")).decode("ascii")
        layer2_ps = (
            "@echo off\n"
            f"powershell.exe -ExecutionPolicy Bypass -enc {layer2_b64}\n"
        )

        # Layer 1: CertUtil Base64 PEM Wrapper enclosing Layer 2
        layer1_b64 = base64.b64encode(layer2_ps.encode("utf-8")).decode("ascii")
        layer1_certutil = (
            "@echo off\n"
            "certutil -decode %~f0 %temp%\\run.bat & call %temp%\\run.bat\n"
            "exit /b\n"
            "-----BEGIN CERTIFICATE-----\n"
            f"{layer1_b64}\n"
            "-----END CERTIFICATE-----\n"
        )

        res = self.engine.unpack(layer1_certutil)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.layers_unpacked, 2)

        # Check Transition 1 (CertUtil decode)
        t1 = res.transitions[0]
        self.assertEqual(t1.depth, 1)
        self.assertEqual(t1.from_packer, PackerType.CERTUTIL_BASE64)
        self.assertEqual(t1.unpacker_strategy, "certutil_base64_decode")

        # Check Transition 2 (PowerShell decode)
        t2 = res.transitions[1]
        self.assertEqual(t2.depth, 2)
        self.assertEqual(t2.from_packer, PackerType.POWERSHELL_BASE64)
        self.assertEqual(t2.unpacker_strategy, "powershell_base64_decode")

        # Check Final Deobfuscated Payload
        self.assertIn("Clean Core Payload", res.final_source)
        self.assertIn("net user Administrator", res.final_source)

    # 5. Cycle & Infinite Loop Detection and Halt
    def test_cycle_infinite_loop_detection_and_halt(self):
        # Create an engine subclass that returns an oscillating payload to simulate loop
        class MockOscillatingEngine(MultiStagePackerEngine):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = 0

            def _unpack_single_layer(self, source, detection):
                self.calls += 1
                # Alternate between payload A and payload B
                if self.calls % 2 == 1:
                    return ("payload_A_state", PackerType.CERTUTIL_BASE64, "mock_strategy", [], {})
                else:
                    return ("payload_B_state", PackerType.POWERSHELL_BASE64, "mock_strategy", [], {})

        osc_engine = MockOscillatingEngine(detector=self.detector)
        dummy_input = "initial_packed_source"
        # Pre-seed detection to packed so it enters loop
        res = osc_engine.unpack("-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----\n")
        self.assertTrue(res.cycle_detected)
        self.assertGreaterEqual(res.metrics.cycles_halted, 1)

    # 6. Payload Size & DoS Limits
    def test_payload_size_dos_limits(self):
        target_payload = "@echo off\n" + ("echo DoS Line\n" * 100)
        b64_str = base64.b64encode(target_payload.encode("utf-16le")).decode("ascii")
        wrapped_script = f"powershell.exe -enc {b64_str}\n"

        # Limit engine to only 50 bytes
        strict_engine = MultiStagePackerEngine(detector=self.detector, max_payload_size=50)
        res = strict_engine.unpack(wrapped_script)
        # Should not unpack because payload exceeds max_payload_size
        self.assertEqual(res.layers_unpacked, 0)

    # 7. Shannon Entropy Delta & Transition Provenance Tracking
    def test_shannon_entropy_delta_and_provenance(self):
        payload = "@echo off\necho Low Entropy Repetitive Repetitive Repetitive\n"
        b64_str = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
        wrapped = f"powershell -enc {b64_str}\n"

        res = self.engine.unpack(wrapped)
        self.assertTrue(res.is_packed)
        self.assertGreater(len(res.transitions), 0)

        t = res.transitions[0]
        self.assertIsInstance(t.input_entropy, float)
        self.assertIsInstance(t.output_entropy, float)
        self.assertIsInstance(t.entropy_delta, float)
        self.assertGreater(len(t.payload_sha256), 0)
        self.assertGreater(res.metrics.entropy_reduction, 0.0)

    # 8. Memory Zeroize() Verification
    def test_memory_zeroize_verification(self):
        payload = "@echo off\necho Confidential Secret\n"
        b64_str = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
        wrapped = f"powershell -enc {b64_str}\n"

        res = self.engine.unpack(wrapped)
        self.assertIn("Confidential Secret", res.final_source)
        self.assertGreater(len(res.transitions), 0)

        # Zeroize result
        res.zeroize()
        self.assertEqual(res.root_source, "")
        self.assertEqual(res.final_source, "")
        self.assertEqual(len(res.transitions), 0)
        self.assertEqual(res.metrics.total_input_bytes, 0)
        self.assertEqual(res.metrics.decompressed_bytes, 0)
        self.assertEqual(res.metrics.layers_unpacked, 0)

        # Test LayerTransition zeroize individually
        trans = LayerTransition(
            depth=1,
            from_packer=PackerType.POWERSHELL_BASE64,
            to_packer=PackerType.CLEAN_BATCH,
            unpacker_strategy="test_strategy",
            input_entropy=5.0,
            output_entropy=3.0,
            entropy_delta=-2.0,
            input_bytes=100,
            output_bytes=50,
            payload_sha256="abcdef1234567890",
            indicators=["sensitive indicator"],
            metadata={"key": "secret"}
        )
        trans.zeroize()
        self.assertEqual(trans.payload_sha256, "")
        self.assertEqual(trans.indicators, [])
        self.assertEqual(trans.metadata, {})
        self.assertEqual(trans.input_bytes, 0)

    # 9. CLI Flags Integration Tests
    def test_cli_flags_integration(self):
        test_script = "powershell -enc ZQBjAGgAbwAgAEgAZQBsAGwAbwA=\n"

        # 9a. Test --packers-detect text mode
        proc_detect = subprocess.run(
            [sys.executable, "src/cli.py", "-c", test_script, "--packers-detect"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_detect.returncode, 0)
        self.assertIn("[BATCH PACKER & OBFUSCATOR DETECTION]", proc_detect.stdout)
        self.assertIn("powershell_base64", proc_detect.stdout)

        # 9b. Test --packers-unpack text mode
        proc_unpack = subprocess.run(
            [sys.executable, "src/cli.py", "-c", test_script, "--packers-unpack"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_unpack.returncode, 0)
        self.assertIn("[MULTI-STAGE PACKER UNPACKING REPORT]", proc_unpack.stdout)
        self.assertIn("echo Hello", proc_unpack.stdout)

        # 9c. Test --packers-layers --json
        proc_json = subprocess.run(
            [sys.executable, "src/cli.py", "-c", test_script, "--packers-layers", "--json"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_json.returncode, 0)
        parsed = json.loads(proc_json.stdout.strip())
        self.assertEqual(parsed["layers_unpacked"], 1)
        self.assertEqual(parsed["primary_packer"], "powershell_base64")

        # 9d. Test --packers-layers --md
        proc_md = subprocess.run(
            [sys.executable, "src/cli.py", "-c", test_script, "--packers-layers", "--md"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc_md.returncode, 0)
        self.assertIn("# Multi-Stage Batch Packer Layer Transitions Report", proc_md.stdout)
        self.assertIn("| 1 | `powershell_base64_decode` |", proc_md.stdout)


if __name__ == "__main__":
    unittest.main()
