"""
Single-file deobfuscation worker for directory scanning.
Executes multi-encoding ingestion, AST parsing, transform pass pipelines,
normalization, file I/O (mirroring/in-place/backup), and telemetry collection.
"""

import os
import shutil
import time
from typing import List, Optional, Set, Tuple

from ..ast_nodes import ASTNode, ASTVisitor
from ..normalizer import ASTNormalizer
from ..parser import CmdASTParser
from ..transforms.base import PassManager
from ..benchmark.metrics import count_ast_nodes
from .models import (
    FileScanStatus,
    ScanConfig,
    ScanItem,
    compute_sha256,
    compute_shannon_entropy,
)


class ScannerWorker:
    """Handles end-to-end reading, deobfuscating, and persisting of a single file."""

    @staticmethod
    def read_file_multi_encoding(file_path: str, encodings: List[str]) -> Tuple[str, str, int]:
        """
        Reads a file attempting a fallback list of character encodings.
        Returns decoded text, encoding name used, and raw file size in bytes.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        for enc in encodings:
            try:
                decoded = raw_bytes.decode(enc)
                return decoded.lstrip("\ufeff"), enc, file_size
            except (UnicodeDecodeError, LookupError):
                continue

        # Ultimate fallback with character replacement
        return raw_bytes.decode("latin-1", errors="replace"), "latin-1", file_size

    @classmethod
    def process_file(
        cls,
        file_path: str,
        config: ScanConfig,
        shared_env: Optional[dict] = None
    ) -> ScanItem:
        """
        Deobfuscates a single batch file and records comprehensive metrics.
        Catches any syntax or parsing exceptions and logs safe error items.
        """
        start_time = time.perf_counter()
        base_dir = os.path.realpath(os.path.abspath(config.input_dir))
        real_file_path = os.path.realpath(os.path.abspath(file_path))
        rel_path = os.path.relpath(real_file_path, base_dir)

        # 1. Bounds check: file size cap
        try:
            raw_size = os.path.getsize(file_path)
        except OSError as e:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.FAILED,
                error_message=f"Cannot stat file: {e}",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        if raw_size > config.max_file_size:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.SKIPPED,
                file_size_bytes=raw_size,
                error_message=f"File exceeds maximum size threshold ({raw_size} > {config.max_file_size} bytes)",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        # 2. Multi-encoding ingestion
        try:
            source, encoding_used, file_size = cls.read_file_multi_encoding(file_path, config.encodings)
        except Exception as e:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.FAILED,
                error_message=f"Read error: {e}",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        sha_orig = compute_sha256(source)
        entropy_orig = compute_shannon_entropy(source)

        # 3. Parse and count original AST nodes
        try:
            parser = CmdASTParser.from_source(source)
            ast = parser.parse()
        except Exception as e:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.FAILED,
                file_size_bytes=file_size,
                encoding_used=encoding_used,
                sha256_original=sha_orig,
                entropy_before=entropy_orig,
                error_message=f"Parse error: {e}",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        nodes_before = count_ast_nodes(ast)

        # 4. Execute AST transform pass pipeline
        try:
            if config.enable_dce:
                pm = PassManager.optimization_pipeline(
                    env=shared_env,
                    preserve_vars=config.preserve_vars
                )
            else:
                pm = PassManager.default_pipeline(
                    env=shared_env,
                    preserve_vars=config.preserve_vars
                )
            transformed_ast = pm.run(ast, env=shared_env)
        except Exception as e:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.FAILED,
                file_size_bytes=file_size,
                encoding_used=encoding_used,
                sha256_original=sha_orig,
                entropy_before=entropy_orig,
                nodes_before=nodes_before,
                error_message=f"Transform error: {e}",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        # Record which passes modified the AST
        passes_modified = [p.name for p in pm.passes if p.modified]

        # 5. Normalization and serialization to source
        try:
            normalizer = ASTNormalizer(preserve_vars=config.preserve_vars)
            norm_ast = normalizer.normalize(transformed_ast)
            deobfuscated_code = normalizer.to_source(norm_ast)
        except Exception as e:
            return ScanItem(
                file_path=file_path,
                relative_path=rel_path,
                status=FileScanStatus.FAILED,
                file_size_bytes=file_size,
                encoding_used=encoding_used,
                sha256_original=sha_orig,
                entropy_before=entropy_orig,
                nodes_before=nodes_before,
                error_message=f"Normalize error: {e}",
                elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        nodes_after = count_ast_nodes(norm_ast)
        sha_deob = compute_sha256(deobfuscated_code)
        entropy_after = compute_shannon_entropy(deobfuscated_code)

        orig_len = len(source)
        deob_len = len(deobfuscated_code)
        reduction_ratio = (orig_len - deob_len) / orig_len if orig_len > 0 else 0.0

        canon_orig = source.strip().replace("\r\n", "\n")
        canon_deob = deobfuscated_code.strip().replace("\r\n", "\n")
        is_modified = bool(passes_modified) or (canon_orig != canon_deob)
        if not is_modified:
            sha_deob = sha_orig
            entropy_after = entropy_orig
            reduction_ratio = 0.0

        status = FileScanStatus.SUCCESS if is_modified else FileScanStatus.UNCHANGED

        # 6. Output writing (in-place or output_dir)
        output_path: Optional[str] = None
        if not config.dry_run:
            try:
                if config.in_place:
                    if is_modified:
                        if config.backup:
                            bak_path = f"{file_path}.bak"
                            shutil.copy2(file_path, bak_path)
                        with open(file_path, "w", encoding="utf-8") as f_out:
                            f_out.write(deobfuscated_code + "\n")
                    output_path = file_path
                elif config.output_dir:
                    out_base = os.path.abspath(config.output_dir)
                    target_out = os.path.join(out_base, rel_path)
                    os.makedirs(os.path.dirname(target_out), exist_ok=True)
                    with open(target_out, "w", encoding="utf-8") as f_out:
                        f_out.write(deobfuscated_code + "\n")
                    output_path = target_out
            except Exception as e:
                return ScanItem(
                    file_path=file_path,
                    relative_path=rel_path,
                    status=FileScanStatus.FAILED,
                    file_size_bytes=file_size,
                    encoding_used=encoding_used,
                    sha256_original=sha_orig,
                    sha256_deobfuscated=sha_deob,
                    entropy_before=entropy_orig,
                    entropy_after=entropy_after,
                    reduction_ratio=reduction_ratio,
                    nodes_before=nodes_before,
                    nodes_after=nodes_after,
                    error_message=f"Write error: {e}",
                    elapsed_ms=(time.perf_counter() - start_time) * 1000.0,
                )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ScanItem(
            file_path=file_path,
            relative_path=rel_path,
            status=status,
            file_size_bytes=file_size,
            encoding_used=encoding_used,
            sha256_original=sha_orig,
            sha256_deobfuscated=sha_deob,
            entropy_before=entropy_orig,
            entropy_after=entropy_after,
            reduction_ratio=reduction_ratio,
            nodes_before=nodes_before,
            nodes_after=nodes_after,
            elapsed_ms=elapsed_ms,
            output_path=output_path,
            passes_modified=passes_modified,
        )
