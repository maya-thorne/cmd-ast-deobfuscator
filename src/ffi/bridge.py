"""
Bridge coordinator connecting Python AST engine with Native C/Rust FFI cdylib.

Provides unified dispatch, automatic fallback between native acceleration and
pure-Python compiler passes, memory buffer safety, and quantitative telemetry.
"""

import ctypes
import json
import time
from typing import Any, Optional

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
from .c_api import CCmdFFIOptions, CCmdFFIMetrics, init_native_library


class CmdDeobfuscatorBridge:
    """
    High-level FFI bridge orchestrator supporting both native Rust C ABI
    acceleration and pure-Python AST pushdown automaton execution.
    """

    def __init__(self, lib_path: Optional[str] = None, force_python: bool = False):
        self._force_python = force_python
        self._lib = None
        self._lib_path = None
        if not force_python:
            self._lib, self._lib_path = init_native_library(lib_path)

    @property
    def is_native_accelerated(self) -> bool:
        """True if the native compiled shared library is loaded and active."""
        return self._lib is not None and not self._force_python

    @property
    def native_library_path(self) -> Optional[str]:
        """Path to the loaded native shared library, or None."""
        return self._lib_path

    def get_version(self) -> str:
        """Returns the version string of the active engine."""
        if self.is_native_accelerated:
            try:
                raw = self._lib.cmd_ffi_version()
                if raw:
                    return raw.decode("utf-8")
            except Exception:
                pass
        return "0.19.0"

    def deobfuscate(
        self,
        input_text: str,
        flags: Optional[int] = None,
        options: Optional[FFIOptions] = None,
    ) -> FFIResult:
        """
        Deobfuscates batch script input text via native FFI or Python engine.
        """
        if input_text is None:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_NULL_POINTER,
                error="Input text pointer cannot be null",
            )

        active_flags = flags if flags is not None else (options.flags if options else FFIFlags.ALL_OPTIMIZATIONS)

        if self.is_native_accelerated:
            return self._native_deobfuscate(input_text, active_flags, options)
        else:
            return self._python_deobfuscate(input_text, active_flags, options)

    def extract_iocs(
        self,
        input_text: str,
        flags: Optional[int] = None,
        options: Optional[FFIOptions] = None,
    ) -> FFIResult:
        """
        Extracts malware IOCs from batch script input.
        """
        if input_text is None:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_NULL_POINTER,
                error="Input text pointer cannot be null",
            )

        active_flags = flags if flags is not None else (options.flags if options else FFIFlags.EXTRACT_IOCS)

        if self.is_native_accelerated:
            return self._native_extract_iocs(input_text, active_flags, options)
        else:
            return self._python_extract_iocs(input_text, active_flags, options)

    def parse_ast(
        self,
        input_text: str,
        flags: Optional[int] = None,
        options: Optional[FFIOptions] = None,
    ) -> FFIResult:
        """
        Parses batch script input and serializes AST as JSON.
        """
        if input_text is None:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_NULL_POINTER,
                error="Input text pointer cannot be null",
            )

        active_flags = flags if flags is not None else (options.flags if options else FFIFlags.NONE)

        if self.is_native_accelerated:
            return self._native_parse_ast(input_text, active_flags, options)
        else:
            return self._python_parse_ast(input_text, active_flags, options)

    def run_fast_path(self, input_text: str) -> str:
        """Runs ultra-fast caret stripping and delimiter normalization."""
        res = self.deobfuscate(
            input_text,
            flags=FFIFlags.STRIP_CARETS | FFIFlags.FAST_PATH | FFIFlags.NORMALIZE_QUOTES,
        )
        return res.text if res.is_ok else input_text

    def zeroize(self, buffer: Any) -> None:
        """Securely zeroes buffer memory."""
        zeroize_buffer(buffer)

    # --- Native C ABI Call Handlers ---

    def _native_deobfuscate(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        try:
            encoded = input_text.encode("utf-8")
        except UnicodeEncodeError as e:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_INVALID_UTF8,
                error=f"Invalid UTF-8 encoding: {e}",
            )

        out_res = ctypes.c_void_p(0)
        c_opts = None
        if options:
            c_opts = CCmdFFIOptions(
                flags=int(options.flags),
                max_passes=options.max_passes,
                timeout_ms=options.timeout_ms,
                max_unroll_depth=options.max_unroll_depth,
            )

        status_code = self._lib.cmd_ffi_deobfuscate(
            None,
            encoded,
            len(encoded),
            ctypes.c_uint32(flags),
            ctypes.byref(out_res),
        )

        return self._extract_native_result(status_code, out_res)

    def _native_extract_iocs(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        try:
            encoded = input_text.encode("utf-8")
        except UnicodeEncodeError as e:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_INVALID_UTF8,
                error=f"Invalid UTF-8 encoding: {e}",
            )

        out_res = ctypes.c_void_p(0)
        status_code = self._lib.cmd_ffi_extract_iocs(
            None,
            encoded,
            len(encoded),
            ctypes.c_uint32(flags),
            ctypes.byref(out_res),
        )

        return self._extract_native_result(status_code, out_res)

    def _native_parse_ast(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        try:
            encoded = input_text.encode("utf-8")
        except UnicodeEncodeError as e:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode.ERR_INVALID_UTF8,
                error=f"Invalid UTF-8 encoding: {e}",
            )

        out_res = ctypes.c_void_p(0)
        status_code = self._lib.cmd_ffi_parse_ast(
            None,
            encoded,
            len(encoded),
            ctypes.c_uint32(flags),
            ctypes.byref(out_res),
        )

        return self._extract_native_result(status_code, out_res)

    def _extract_native_result(self, status_code: int, out_res: ctypes.c_void_p) -> FFIResult:
        if status_code != 0 or not out_res.value:
            return FFIResult(
                text="",
                length=0,
                status=FFIStatusCode(status_code) if status_code in FFIStatusCode._value2member_map_ else FFIStatusCode.ERR_EXECUTION_FAILED,
                error="Native execution returned error code",
            )

        try:
            text_ptr = self._lib.cmd_ffi_result_get_text(out_res)
            text = text_ptr.decode("utf-8", errors="replace") if text_ptr else ""
            length = self._lib.cmd_ffi_result_get_length(out_res)
            status_val = self._lib.cmd_ffi_result_get_status(out_res)
            err_ptr = self._lib.cmd_ffi_result_get_error(out_res)
            err_str = err_ptr.decode("utf-8", errors="replace") if err_ptr else None

            c_metrics = CCmdFFIMetrics()
            self._lib.cmd_ffi_result_get_metrics(out_res, ctypes.byref(c_metrics))

            metrics = FFIMetrics(
                elapsed_ns=c_metrics.elapsed_ns,
                ast_nodes_initial=c_metrics.ast_nodes_initial,
                ast_nodes_final=c_metrics.ast_nodes_final,
                passes_executed=c_metrics.passes_executed,
                iocs_extracted=c_metrics.iocs_extracted,
                entropy_initial=c_metrics.entropy_initial,
                entropy_final=c_metrics.entropy_final,
            )

            return FFIResult(
                text=text,
                length=length,
                status=FFIStatusCode(status_val) if status_val in FFIStatusCode._value2member_map_ else FFIStatusCode.OK,
                error=err_str,
                metrics=metrics,
            )
        finally:
            self._lib.cmd_ffi_result_free(out_res)

    # --- Pure Python AST Engine Fallback Handlers ---

    def _python_deobfuscate(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        start_ns = time.perf_counter_ns()
        entropy_init = compute_entropy(input_text)

        try:
            from ..parser import CmdASTParser
            from ..normalizer import ASTNormalizer
            from ..transforms.caret_normalizer import CaretNormalizerPass
            from ..transforms.constant_folder import ConstantFolderPass
            from ..transforms.dce import DeadCodeEliminationPass
            from ..quotes.normalizer import QuoteNormalizer

            text = input_text
            passes_run = 0

            # 1. Caret stripping
            if flags & FFIFlags.STRIP_CARETS:
                ast_parser = CmdASTParser.from_source(text)
                ast = ast_parser.parse()
                caret_pass = CaretNormalizerPass()
                ast = caret_pass.transform(ast)
                normalizer = ASTNormalizer()
                ast = normalizer.normalize(ast)
                text = normalizer.to_source(ast)
                passes_run += 1

            # 2. Quote normalization
            if flags & FFIFlags.NORMALIZE_QUOTES:
                quote_norm = QuoteNormalizer()
                text = quote_norm.normalize_text(text)
                passes_run += 1

            # 3. Constant folding
            if flags & FFIFlags.FOLD_CONSTANTS:
                ast_parser = CmdASTParser.from_source(text)
                ast = ast_parser.parse()
                folder = ConstantFolderPass()
                ast = folder.transform(ast)
                normalizer = ASTNormalizer()
                ast = normalizer.normalize(ast)
                text = normalizer.to_source(ast)
                passes_run += 1

            # 4. Dead Code Elimination
            if flags & FFIFlags.DCE:
                ast_parser = CmdASTParser.from_source(text)
                ast = ast_parser.parse()
                dce_pass = DeadCodeEliminationPass()
                ast = dce_pass.transform(ast)
                normalizer = ASTNormalizer()
                ast = normalizer.normalize(ast)
                text = normalizer.to_source(ast)
                passes_run += 1

            # Fallback if no passes were requested
            if passes_run == 0:
                ast_parser = CmdASTParser.from_source(text)
                ast = ast_parser.parse()
                normalizer = ASTNormalizer()
                ast = normalizer.normalize(ast)
                text = normalizer.to_source(ast)

            entropy_fin = compute_entropy(text)
            elapsed_ns = time.perf_counter_ns() - start_ns

            return FFIResult(
                text=text,
                length=len(text.encode("utf-8")),
                status=FFIStatusCode.OK,
                metrics=FFIMetrics(
                    elapsed_ns=elapsed_ns,
                    ast_nodes_initial=len(input_text.splitlines()),
                    ast_nodes_final=len(text.splitlines()),
                    passes_executed=passes_run,
                    iocs_extracted=0,
                    entropy_initial=entropy_init,
                    entropy_final=entropy_fin,
                ),
            )
        except Exception as e:
            return FFIResult(
                text=input_text,
                length=len(input_text.encode("utf-8")),
                status=FFIStatusCode.ERR_EXECUTION_FAILED,
                error=str(e),
                metrics=FFIMetrics(
                    elapsed_ns=time.perf_counter_ns() - start_ns,
                    entropy_initial=entropy_init,
                ),
            )

    def _python_extract_iocs(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        start_ns = time.perf_counter_ns()
        try:
            from ..ioc.transforms import extract_iocs

            defang = bool(flags & FFIFlags.DEFANG_IOCS)
            res = extract_iocs(input_text)
            if defang:
                res = res.defang()
            json_text = json.dumps([item.to_dict() for item in res.iocs])

            return FFIResult(
                text=json_text,
                length=len(json_text.encode("utf-8")),
                status=FFIStatusCode.OK,
                metrics=FFIMetrics(
                    elapsed_ns=time.perf_counter_ns() - start_ns,
                    ast_nodes_initial=len(input_text.splitlines()),
                    iocs_extracted=len(res.iocs),
                    entropy_initial=compute_entropy(input_text),
                ),
            )
        except Exception as e:
            return FFIResult(
                text="[]",
                length=2,
                status=FFIStatusCode.ERR_EXECUTION_FAILED,
                error=str(e),
                metrics=FFIMetrics(
                    elapsed_ns=time.perf_counter_ns() - start_ns,
                ),
            )

    def _python_parse_ast(
        self,
        input_text: str,
        flags: int,
        options: Optional[FFIOptions],
    ) -> FFIResult:
        start_ns = time.perf_counter_ns()
        try:
            from ..parser import CmdASTParser
            from ..visualizer import ASTVisualizer

            ast = CmdASTParser.from_source(input_text).parse()
            json_text = ASTVisualizer.render_json(ast)

            return FFIResult(
                text=json_text,
                length=len(json_text.encode("utf-8")),
                status=FFIStatusCode.OK,
                metrics=FFIMetrics(
                    elapsed_ns=time.perf_counter_ns() - start_ns,
                    ast_nodes_initial=len(input_text.splitlines()),
                    entropy_initial=compute_entropy(input_text),
                ),
            )
        except Exception as e:
            return FFIResult(
                text="{}",
                length=2,
                status=FFIStatusCode.ERR_EXECUTION_FAILED,
                error=str(e),
                metrics=FFIMetrics(
                    elapsed_ns=time.perf_counter_ns() - start_ns,
                ),
            )
