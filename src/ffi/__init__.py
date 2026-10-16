"""
C/Rust FFI Bindings & Native Acceleration Subsystem for cmd-ast-deobfuscator.

Exposes C ABI compatible data models, bridge orchestrator, ctypes structures,
and standalone deployment verification helpers.
"""

from .models import (
    FFIStatusCode,
    FFIFlags,
    FFIOptions,
    FFIMetrics,
    FFIResult,
    FFIContext,
    compute_entropy,
    zeroize_buffer,
)
from .c_api import (
    CCmdFFIOptions,
    CCmdFFIMetrics,
    find_cdylib_path,
    init_native_library,
)
from .bridge import CmdDeobfuscatorBridge
from .standalone import (
    export_c_header,
    build_native_library,
    verify_roundtrip,
)

__all__ = [
    "FFIStatusCode",
    "FFIFlags",
    "FFIOptions",
    "FFIMetrics",
    "FFIResult",
    "FFIContext",
    "compute_entropy",
    "zeroize_buffer",
    "CCmdFFIOptions",
    "CCmdFFIMetrics",
    "find_cdylib_path",
    "init_native_library",
    "CmdDeobfuscatorBridge",
    "export_c_header",
    "build_native_library",
    "verify_roundtrip",
]
