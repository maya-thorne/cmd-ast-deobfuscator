"""
File discovery engine and path traversal defense for directory scanning.
Handles recursive file traversal, exclusion filtering, pattern matching,
symlink cycle defenses, and boundary validation.
"""

import fnmatch
import os
from typing import List, Set

from .models import ScanConfig


class FileCollector:
    """Discovers target batch files according to ScanConfig rules."""

    @staticmethod
    def _is_excluded(path_part: str, exclude_patterns: List[str]) -> bool:
        """Checks if a directory or file matches any exclusion pattern."""
        lower = path_part.lower()
        for pat in exclude_patterns:
            if fnmatch.fnmatch(lower, pat.lower()):
                return True
        return False

    @staticmethod
    def _matches_pattern(filename: str, patterns: List[str]) -> bool:
        """Checks if a file matches any of the target extension patterns."""
        lower = filename.lower()
        for pat in patterns:
            if fnmatch.fnmatch(lower, pat.lower()):
                return True
        return False

    @classmethod
    def collect(cls, config: ScanConfig) -> List[str]:
        """
        Discovers and returns an ordered list of valid batch script paths.
        Enforces path traversal defenses, maximum depth, and exclusion filters.
        """
        config.validate()
        base_dir = os.path.realpath(os.path.abspath(config.input_dir))
        discovered: List[str] = []
        seen_realpaths: Set[str] = set()

        if not config.recursive:
            try:
                entries = os.scandir(base_dir)
            except (OSError, PermissionError):
                return []

            with entries as it:
                for entry in it:
                    if entry.is_file():
                        name = entry.name
                        if cls._is_excluded(name, config.exclude_patterns):
                            continue
                        if cls._matches_pattern(name, config.file_patterns):
                            real_p = os.path.realpath(entry.path)
                            if real_p not in seen_realpaths:
                                seen_realpaths.add(real_p)
                                discovered.append(entry.path)
            discovered.sort()
            return discovered

        for root, dirs, files in os.walk(base_dir, topdown=True, followlinks=False):
            # Safe path traversal guard: ensure root is inside base_dir
            real_root = os.path.realpath(root)
            try:
                common = os.path.commonpath([base_dir, real_root])
                if common != base_dir:
                    dirs[:] = []
                    continue
            except ValueError:
                dirs[:] = []
                continue

            # Symlink loop guard
            if real_root in seen_realpaths:
                dirs[:] = []
                continue
            seen_realpaths.add(real_root)

            # Max depth check
            rel_root = os.path.relpath(root, base_dir)
            depth = 0 if rel_root == "." else len(rel_root.split(os.sep))
            if config.max_depth is not None and depth >= config.max_depth:
                dirs[:] = []

            # Prune excluded subdirectories in-place
            dirs[:] = [
                d for d in dirs
                if not cls._is_excluded(d, config.exclude_patterns)
            ]

            # Check files in current directory
            for f in files:
                if cls._is_excluded(f, config.exclude_patterns):
                    continue
                if cls._matches_pattern(f, config.file_patterns):
                    full_p = os.path.join(root, f)
                    real_file = os.path.realpath(full_p)
                    # Verify file is within base_dir
                    try:
                        if os.path.commonpath([base_dir, real_file]) != base_dir:
                            continue
                    except ValueError:
                        continue
                    if real_file not in seen_realpaths:
                        seen_realpaths.add(real_file)
                        discovered.append(full_p)

        discovered.sort()
        return discovered
