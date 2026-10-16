"""
FFI Data Models, Enums, Metrics, and Memory Security Protocols.

Provides standard C ABI compatible status codes, bitwise transformation flags,
telemetry metrics, execution options, and buffer zeroization routines.
"""

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Any, Dict, Optional
import ctypes
import math


class FFIStatusCode(IntEnum):
    """Native and bridge status codes matching cmd_ffi_status_t."""
    OK = 0
    ERR_NULL_POINTER = -1
    ERR_INVALID_UTF8 = -2
    ERR_BUFFER_OVERFLOW = -3
    ERR_EXECUTION_FAILED = -4
    ERR_INVALID_STATE = -5
    ERR_TIMEOUT = -6


class FFIFlags(IntFlag):
    """Transformation and optimization bitmask flags."""
    NONE = 0x00000000
    STRIP_CARETS = 0x00000001
    FOLD_CONSTANTS = 0x00000002
    DCE = 0x00000004
    NORMALIZE_QUOTES = 0x00000008
    EXTRACT_IOCS = 0x00000010
    FAST_PATH = 0x00000020
    DEFANG_IOCS = 0x00000040
    ALL_OPTIMIZATIONS = 0x0000003F


@dataclass
class FFIOptions:
    """Execution options for C/Rust FFI deobfuscation engine."""
    flags: int = FFIFlags.ALL_OPTIMIZATIONS
    max_passes: int = 10
    timeout_ms: int = 5000
    max_unroll_depth: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flags": int(self.flags),
            "max_passes": self.max_passes,
            "timeout_ms": self.timeout_ms,
            "max_unroll_depth": self.max_unroll_depth,
        }


@dataclass
class FFIMetrics:
    """Quantitative performance and execution telemetry matching cmd_ffi_metrics_t."""
    elapsed_ns: int = 0
    ast_nodes_initial: int = 0
    ast_nodes_final: int = 0
    passes_executed: int = 0
    iocs_extracted: int = 0
    entropy_initial: float = 0.0
    entropy_final: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "elapsed_ns": self.elapsed_ns,
            "elapsed_ms": round(self.elapsed_ns / 1_000_000.0, 4),
            "ast_nodes_initial": self.ast_nodes_initial,
            "ast_nodes_final": self.ast_nodes_final,
            "passes_executed": self.passes_executed,
            "iocs_extracted": self.iocs_extracted,
            "entropy_initial": round(self.entropy_initial, 4),
            "entropy_final": round(self.entropy_final, 4),
        }


@dataclass
class FFIResult:
    """Result of FFI operation containing output text, status, error, and metrics."""
    text: str
    length: int
    status: FFIStatusCode = FFIStatusCode.OK
    error: Optional[str] = None
    metrics: FFIMetrics = field(default_factory=FFIMetrics)

    @property
    def is_ok(self) -> bool:
        return self.status == FFIStatusCode.OK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "length": self.length,
            "status": int(self.status),
            "status_name": self.status.name,
            "error": self.error,
            "metrics": self.metrics.to_dict(),
        }


@dataclass
class FFIContext:
    """Python-side representation of FFI execution context."""
    options: FFIOptions = field(default_factory=FFIOptions)
    is_active: bool = True
    native_handle: Optional[int] = None

    def close(self) -> None:
        self.is_active = False
        self.native_handle = None


def compute_entropy(text: str) -> float:
    """Computes Shannon entropy of an ASCII/UTF-8 string."""
    if not text:
        return 0.0
    byte_counts = {}
    raw = text.encode("utf-8", errors="replace")
    for b in raw:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    total = len(raw)
    entropy = 0.0
    for count in byte_counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def zeroize_buffer(buf: Any) -> None:
    """
    Securely zeroes a mutable buffer, bytearray, or ctypes memory region
    to prevent memory scraping or dead-store elimination.
    """
    if buf is None:
        return

    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, (ctypes.Array, ctypes.Structure)):
        ctypes.memset(ctypes.addressof(buf), 0, ctypes.sizeof(buf))
    elif hasattr(buf, "__len__") and hasattr(buf, "__setitem__"):
        try:
            for i in range(len(buf)):
                buf[i] = 0
        except (TypeError, ValueError):
            pass
