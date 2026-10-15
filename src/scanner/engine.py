"""
High-throughput directory scanner engine and parallel pipeline orchestrator.
Dispatches batch deobfuscation workers, aggregates telemetry metrics,
handles progress callbacks, and exports analysis reports.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time
from typing import Callable, List, Optional

from .collector import FileCollector
from .models import FileScanStatus, ScanConfig, ScanItem, ScanSummary
from .worker import ScannerWorker


ProgressCallback = Callable[[ScanItem, int, int], None]


class DirectoryScanner:
    """
    High-throughput batch file scanner and deobfuscation pipeline.
    Orchestrates multi-threaded processing across directories with real-time telemetry.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config

    def scan_and_deobfuscate(
        self,
        config: Optional[ScanConfig] = None,
        progress_callback: Optional[ProgressCallback] = None
    ) -> ScanSummary:
        """
        Executes parallel discovery, AST parsing, transform passes, and persistence
        across all target batch files found in the configured directory tree.
        """
        cfg = config or self.config
        if cfg is None:
            raise ValueError("ScanConfig must be provided to scan_and_deobfuscate().")
        cfg.validate()

        start_time = time.perf_counter()

        # 1. Discover target files
        file_paths = FileCollector.collect(cfg)
        total_discovered = len(file_paths)

        summary = ScanSummary(total_files_discovered=total_discovered)
        if total_discovered == 0:
            summary.total_elapsed_sec = time.perf_counter() - start_time
            summary.compute_aggregates()
            return summary

        # 2. Parallel deobfuscation execution
        processed_count = 0
        items: List[ScanItem] = []

        # Single worker optimization (avoids thread pool overhead for small batches or 1 worker)
        if cfg.workers <= 1 or total_discovered == 1:
            for fp in file_paths:
                item = ScannerWorker.process_file(fp, cfg)
                items.append(item)
                processed_count += 1
                if progress_callback:
                    progress_callback(item, processed_count, total_discovered)
                if cfg.fail_fast and item.status == FileScanStatus.FAILED:
                    break
        else:
            with ThreadPoolExecutor(max_workers=cfg.workers) as executor:
                future_to_path = {
                    executor.submit(ScannerWorker.process_file, fp, cfg): fp
                    for fp in file_paths
                }

                for future in as_completed(future_to_path):
                    try:
                        item = future.result()
                    except Exception as exc:
                        fp = future_to_path[future]
                        rel_p = os.path.relpath(fp, cfg.input_dir)
                        item = ScanItem(
                            file_path=fp,
                            relative_path=rel_p,
                            status=FileScanStatus.FAILED,
                            error_message=f"Worker exception: {exc}",
                        )

                    items.append(item)
                    processed_count += 1
                    if progress_callback:
                        progress_callback(item, processed_count, total_discovered)

                    if cfg.fail_fast and item.status == FileScanStatus.FAILED:
                        for pending in future_to_path:
                            pending.cancel()
                        break

        # Sort items deterministically by relative path
        items.sort(key=lambda it: it.relative_path)
        summary.items = items
        summary.total_elapsed_sec = time.perf_counter() - start_time
        summary.compute_aggregates()
        return summary

    @staticmethod
    def export_reports(
        summary: ScanSummary,
        json_path: Optional[str] = None,
        csv_path: Optional[str] = None,
        markdown_path: Optional[str] = None
    ) -> None:
        """Exports scan summary reports to designated file paths."""
        if json_path:
            os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(summary.to_json())

        if csv_path:
            os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(summary.to_csv())

        if markdown_path:
            os.makedirs(os.path.dirname(os.path.abspath(markdown_path)), exist_ok=True)
            with open(markdown_path, "w", encoding="utf-8") as f:
                f.write(summary.to_markdown())
