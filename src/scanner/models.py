"""
Data models, configurations, and summary telemetry structures for the
high-throughput batch file directory scanner and bulk deobfuscation engine.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
import os
from typing import Dict, List, Optional, Set, Any


class FileScanStatus(Enum):
    """Execution status for an individual file scan and deobfuscation task."""
    SUCCESS = "success"
    UNCHANGED = "unchanged"
    FAILED = "failed"
    SKIPPED = "skipped"


def compute_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy (bits per byte) of a given text string."""
    if not data:
        return 0.0
    byte_array = data.encode("utf-8", errors="replace")
    length = len(byte_array)
    if length == 0:
        return 0.0
    freq: Dict[int, int] = {}
    for b in byte_array:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_sha256(data: str) -> str:
    """Computes SHA-256 hex digest for a string."""
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class ScanConfig:
    """Configuration options for bulk directory scanning and batch deobfuscation."""
    input_dir: str
    output_dir: Optional[str] = None
    recursive: bool = True
    max_depth: Optional[int] = None
    file_patterns: List[str] = field(default_factory=lambda: ["*.bat", "*.cmd", "*.btm"])
    exclude_patterns: List[str] = field(
        default_factory=lambda: [".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"]
    )
    max_file_size: int = 10 * 1024 * 1024  # 10 MB per file cap
    workers: int = 4
    in_place: bool = False
    backup: bool = True
    dry_run: bool = False
    enable_dce: bool = False
    preserve_vars: Optional[Set[str]] = None
    encodings: List[str] = field(
        default_factory=lambda: ["utf-8-sig", "utf-8", "cp437", "cp1252", "cp949", "latin-1"]
    )
    fail_fast: bool = False
    timeout_per_file: float = 30.0

    def validate(self) -> None:
        """Validates configuration sanity and path integrity."""
        if not self.input_dir:
            raise ValueError("Input directory path must not be empty.")
        if not os.path.exists(self.input_dir):
            raise FileNotFoundError(f"Input directory does not exist: {self.input_dir}")
        if not os.path.isdir(self.input_dir):
            raise NotADirectoryError(f"Input path is not a directory: {self.input_dir}")
        if self.in_place and self.output_dir:
            raise ValueError("Cannot specify both --in-place and --output-dir simultaneously.")
        if self.workers < 1:
            self.workers = 1


@dataclass
class ScanItem:
    """Deobfuscation result and telemetry metadata for a single batch file."""
    file_path: str
    relative_path: str
    status: FileScanStatus
    file_size_bytes: int = 0
    encoding_used: str = "utf-8"
    sha256_original: str = ""
    sha256_deobfuscated: str = ""
    entropy_before: float = 0.0
    entropy_after: float = 0.0
    reduction_ratio: float = 0.0
    nodes_before: int = 0
    nodes_after: int = 0
    elapsed_ms: float = 0.0
    output_path: Optional[str] = None
    error_message: Optional[str] = None
    passes_modified: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes scan item result into a JSON-serializable dictionary."""
        return {
            "file_path": self.file_path,
            "relative_path": self.relative_path,
            "status": self.status.value,
            "file_size_bytes": self.file_size_bytes,
            "encoding_used": self.encoding_used,
            "sha256_original": self.sha256_original,
            "sha256_deobfuscated": self.sha256_deobfuscated,
            "entropy_before": self.entropy_before,
            "entropy_after": self.entropy_after,
            "reduction_ratio": round(self.reduction_ratio, 4),
            "nodes_before": self.nodes_before,
            "nodes_after": self.nodes_after,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "output_path": self.output_path,
            "error_message": self.error_message,
            "passes_modified": list(self.passes_modified),
        }

    def zeroize(self) -> None:
        """Zeroizes sensitive file paths, hashes, and error buffers from memory."""
        self.sha256_original = "0" * 64
        self.sha256_deobfuscated = "0" * 64
        if self.error_message:
            self.error_message = ""
        self.passes_modified.clear()


@dataclass
class ScanSummary:
    """Aggregated scan telemetry, batch throughput metrics, and execution summary."""
    total_files_discovered: int = 0
    total_files_processed: int = 0
    successful_count: int = 0
    unchanged_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    total_bytes_processed: int = 0
    total_elapsed_sec: float = 0.0
    throughput_files_sec: float = 0.0
    throughput_mb_sec: float = 0.0
    average_entropy_reduction: float = 0.0
    items: List[ScanItem] = field(default_factory=list)

    def compute_aggregates(self) -> None:
        """Calculates throughput, averages, and status tallies across all items."""
        self.total_files_processed = len(self.items)
        self.successful_count = sum(1 for it in self.items if it.status == FileScanStatus.SUCCESS)
        self.unchanged_count = sum(1 for it in self.items if it.status == FileScanStatus.UNCHANGED)
        self.failed_count = sum(1 for it in self.items if it.status == FileScanStatus.FAILED)
        self.skipped_count = sum(1 for it in self.items if it.status == FileScanStatus.SKIPPED)
        self.total_bytes_processed = sum(it.file_size_bytes for it in self.items)

        if self.total_elapsed_sec > 0:
            self.throughput_files_sec = round(self.total_files_processed / self.total_elapsed_sec, 2)
            self.throughput_mb_sec = round(
                (self.total_bytes_processed / (1024 * 1024)) / self.total_elapsed_sec, 3
            )
        else:
            self.throughput_files_sec = 0.0
            self.throughput_mb_sec = 0.0

        entropy_diffs = [
            (it.entropy_before - it.entropy_after)
            for it in self.items
            if it.status in (FileScanStatus.SUCCESS, FileScanStatus.UNCHANGED) and it.entropy_before > 0
        ]
        if entropy_diffs:
            self.average_entropy_reduction = round(sum(entropy_diffs) / len(entropy_diffs), 4)
        else:
            self.average_entropy_reduction = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes aggregate summary to dictionary."""
        return {
            "total_files_discovered": self.total_files_discovered,
            "total_files_processed": self.total_files_processed,
            "successful_count": self.successful_count,
            "unchanged_count": self.unchanged_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "total_bytes_processed": self.total_bytes_processed,
            "total_elapsed_sec": round(self.total_elapsed_sec, 3),
            "throughput_files_sec": self.throughput_files_sec,
            "throughput_mb_sec": self.throughput_mb_sec,
            "average_entropy_reduction": self.average_entropy_reduction,
            "items": [it.to_dict() for it in self.items],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes summary telemetry to formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        """Generates a CSV report of processed batch files."""
        lines = [
            "RelativePath,Status,SizeBytes,Encoding,EntropyBefore,EntropyAfter,ReductionRatio,NodesBefore,NodesAfter,ElapsedMs,Error"
        ]
        for it in self.items:
            err = (it.error_message or "").replace(",", ";").replace("\n", " ").replace('"', '""')
            lines.append(
                f'"{it.relative_path}",{it.status.value},{it.file_size_bytes},{it.encoding_used},'
                f'{it.entropy_before:.4f},{it.entropy_after:.4f},{it.reduction_ratio:.4f},'
                f'{it.nodes_before},{it.nodes_after},{it.elapsed_ms:.2f},"{err}"'
            )
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Generates a formatted Markdown summary table."""
        lines = [
            "# Batch Directory Deobfuscation Scan Report",
            "",
            "## Summary Metrics",
            f"- **Discovered Files**: {self.total_files_discovered}",
            f"- **Processed Files**: {self.total_files_processed}",
            f"- **Deobfuscated (Modified)**: {self.successful_count}",
            f"- **Unchanged (Already Clean)**: {self.unchanged_count}",
            f"- **Failed**: {self.failed_count}",
            f"- **Skipped**: {self.skipped_count}",
            f"- **Total Bytes**: {self.total_bytes_processed:,} bytes",
            f"- **Elapsed Time**: {self.total_elapsed_sec:.3f} s",
            f"- **Throughput**: {self.throughput_files_sec} files/s ({self.throughput_mb_sec} MB/s)",
            f"- **Average Entropy Reduction**: {self.average_entropy_reduction} bits/byte",
            "",
            "## Processed Files",
            "| Relative Path | Status | Size (B) | Entropy Delta | Node Delta | Time (ms) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: |",
        ]
        for it in self.items:
            entropy_delta = f"{it.entropy_before:.2f} -> {it.entropy_after:.2f}"
            node_delta = f"{it.nodes_before} -> {it.nodes_after}"
            lines.append(
                f"| `{it.relative_path}` | `{it.status.value}` | {it.file_size_bytes:,} | {entropy_delta} | {node_delta} | {it.elapsed_ms:.1f} |"
            )
        return "\n".join(lines)

    def zeroize(self) -> None:
        """Zeroizes all individual item records and clears in-memory structures."""
        for it in self.items:
            it.zeroize()
        self.items.clear()
