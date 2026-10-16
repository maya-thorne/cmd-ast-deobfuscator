"""
ctypes-based C ABI Data Structures, Function Bindings, and Library Loader.

Provides exact binary memory layout matching include/cmd_deobfuscator.h and
dynamically loads the compiled Rust cdylib on Windows, Linux, and macOS.
"""

import ctypes
import os
import sys
from typing import Optional, Tuple


class CCmdFFIOptions(ctypes.Structure):
    """C ABI binary layout for cmd_ffi_options_t."""
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("max_passes", ctypes.c_uint32),
        ("timeout_ms", ctypes.c_uint32),
        ("max_unroll_depth", ctypes.c_uint32),
    ]


class CCmdFFIMetrics(ctypes.Structure):
    """C ABI binary layout for cmd_ffi_metrics_t."""
    _fields_ = [
        ("elapsed_ns", ctypes.c_uint64),
        ("ast_nodes_initial", ctypes.c_uint32),
        ("ast_nodes_final", ctypes.c_uint32),
        ("passes_executed", ctypes.c_uint32),
        ("iocs_extracted", ctypes.c_uint32),
        ("entropy_initial", ctypes.c_double),
        ("entropy_final", ctypes.c_double),
    ]


def find_cdylib_path(custom_path: Optional[str] = None) -> Optional[str]:
    """
    Locates the compiled native dynamic library (.dll, .so, .dylib).
    """
    if custom_path and os.path.isfile(custom_path):
        return os.path.abspath(custom_path)

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    if sys.platform == "win32":
        lib_names = ["cmd_deobfuscator.dll", "libcmd_deobfuscator.dll"]
    elif sys.platform == "darwin":
        lib_names = ["libcmd_deobfuscator.dylib"]
    else:
        lib_names = ["libcmd_deobfuscator.so"]

    candidates = []
    for name in lib_names:
        candidates.append(os.path.join(base_dir, "target", "release", name))
        candidates.append(os.path.join(base_dir, "target", "debug", name))
        candidates.append(os.path.join(base_dir, name))
        candidates.append(os.path.join(base_dir, "lib", name))

    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)

    return None


def init_native_library(dll_path: Optional[str] = None) -> Tuple[Optional[ctypes.CDLL], Optional[str]]:
    """
    Loads and binds function prototypes for the native C ABI shared library.
    Returns (cdll_instance, resolved_path) or (None, None).
    """
    path = find_cdylib_path(dll_path)
    if not path:
        return None, None

    try:
        lib = ctypes.CDLL(path)
    except Exception:
        return None, None

    # Bind function signatures
    try:
        lib.cmd_ffi_version.restype = ctypes.c_char_p
        lib.cmd_ffi_version.argtypes = []

        lib.cmd_ffi_context_create.restype = ctypes.c_int32
        lib.cmd_ffi_context_create.argtypes = [
            ctypes.POINTER(CCmdFFIOptions),
            ctypes.POINTER(ctypes.c_void_p),
        ]

        lib.cmd_ffi_context_destroy.restype = ctypes.c_int32
        lib.cmd_ffi_context_destroy.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_deobfuscate.restype = ctypes.c_int32
        lib.cmd_ffi_deobfuscate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]

        lib.cmd_ffi_extract_iocs.restype = ctypes.c_int32
        lib.cmd_ffi_extract_iocs.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]

        lib.cmd_ffi_parse_ast.restype = ctypes.c_int32
        lib.cmd_ffi_parse_ast.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]

        lib.cmd_ffi_result_get_text.restype = ctypes.c_char_p
        lib.cmd_ffi_result_get_text.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_result_get_length.restype = ctypes.c_size_t
        lib.cmd_ffi_result_get_length.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_result_get_status.restype = ctypes.c_int32
        lib.cmd_ffi_result_get_status.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_result_get_error.restype = ctypes.c_char_p
        lib.cmd_ffi_result_get_error.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_result_get_metrics.restype = ctypes.c_int32
        lib.cmd_ffi_result_get_metrics.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(CCmdFFIMetrics),
        ]

        lib.cmd_ffi_result_free.restype = None
        lib.cmd_ffi_result_free.argtypes = [ctypes.c_void_p]

        lib.cmd_ffi_zeroize.restype = None
        lib.cmd_ffi_zeroize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

        return lib, path
    except AttributeError:
        return None, None
