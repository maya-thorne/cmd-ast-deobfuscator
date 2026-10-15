"""
cmd-ast-deobfuscator: High-Throughput Batch File Directory Scanner & Pipeline.
"""

from .collector import FileCollector
from .engine import DirectoryScanner, ProgressCallback
from .models import (
    FileScanStatus,
    ScanConfig,
    ScanItem,
    ScanSummary,
    compute_sha256,
    compute_shannon_entropy,
)
from .worker import ScannerWorker, count_ast_nodes

__all__ = [
    "DirectoryScanner",
    "FileCollector",
    "ScannerWorker",
    "ScanConfig",
    "ScanItem",
    "ScanSummary",
    "FileScanStatus",
    "ProgressCallback",
    "count_ast_nodes",
    "compute_sha256",
    "compute_shannon_entropy",
]
