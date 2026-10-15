"""
Data models, ANSI escape stylers, and telemetry metrics for the TUI Inspector.
Provides terminal styling primitives, color management, diff structures, and zeroization.
"""

from enum import Enum
from dataclasses import dataclass, field
import os
import re
import sys
from typing import List, Optional, Dict, Any


class DiffStyle(str, Enum):
    """Supported diff display formats."""
    UNIFIED = "unified"
    SIDE_BY_SIDE = "side_by_side"
    INLINE = "inline"


class ColorMode(str, Enum):
    """Terminal ANSI color activation policies."""
    AUTO = "auto"
    ALWAYS = "always"
    NEVER = "never"


class DiffLineType(str, Enum):
    """Classification for individual diff lines."""
    CONTEXT = "context"
    ADDITION = "addition"
    DELETION = "deletion"
    HEADER = "header"
    SEPARATOR = "separator"


class ANSI:
    """Standard ANSI VT100 styling escape codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"

    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_GRAY = "\033[100m"


_ANSI_REGEX = re.compile(r"\033\[[0-9;]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    """Removes all ANSI escape sequences from text for accurate column counting."""
    if not text:
        return ""
    return _ANSI_REGEX.sub("", text)


def ansi_len(text: str) -> int:
    """Returns the visual printable length of a string containing ANSI escape codes."""
    return len(strip_ansi(text))


def should_color(mode: ColorMode = ColorMode.AUTO, stream: Any = None) -> bool:
    """Determines whether ANSI escape codes should be emitted for the stream."""
    if mode == ColorMode.NEVER:
        return False
    if mode == ColorMode.ALWAYS:
        return True

    # Respect the NO_COLOR standard (https://no-color.org)
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"].strip() != "":
        return False

    target_stream = stream if stream is not None else sys.stdout
    if hasattr(target_stream, "isatty") and target_stream.isatty():
        return True

    # Check for Windows virtual terminal processing or TERM environment
    term = os.environ.get("TERM", "")
    if term in ("xterm", "xterm-256color", "vt100", "screen"):
        return True

    return False


@dataclass
class DiffLine:
    """Represents a single formatted line within a diff view."""
    line_type: DiffLineType
    text: str
    line_num_old: Optional[int] = None
    line_num_new: Optional[int] = None


@dataclass
class DiffMetrics:
    """Quantitative telemetry for code differences."""
    lines_before: int = 0
    lines_after: int = 0
    additions: int = 0
    deletions: int = 0
    modifications: int = 0
    similarity_ratio: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lines_before": self.lines_before,
            "lines_after": self.lines_after,
            "additions": self.additions,
            "deletions": self.deletions,
            "modifications": self.modifications,
            "similarity_ratio": round(self.similarity_ratio, 4),
        }

    def zeroize(self) -> None:
        """Securely resets metric values in memory."""
        self.lines_before = 0
        self.lines_after = 0
        self.additions = 0
        self.deletions = 0
        self.modifications = 0
        self.similarity_ratio = 1.0


@dataclass
class InspectorMetrics:
    """Telemetry capturing interactive AST inspector session activity."""
    steps_executed: int = 0
    passes_modified: int = 0
    nodes_inspected: int = 0
    diffs_rendered: int = 0
    breakpoints_hit: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps_executed": self.steps_executed,
            "passes_modified": self.passes_modified,
            "nodes_inspected": self.nodes_inspected,
            "diffs_rendered": self.diffs_rendered,
            "breakpoints_hit": self.breakpoints_hit,
        }

    def zeroize(self) -> None:
        """Securely resets telemetry counters."""
        self.steps_executed = 0
        self.passes_modified = 0
        self.nodes_inspected = 0
        self.diffs_rendered = 0
        self.breakpoints_hit = 0


@dataclass
class StepRecord:
    """Snapshot record of a pipeline step execution."""
    step_index: int
    pass_name: str
    modified: bool
    source_code: str
    env_snapshot: Dict[str, str] = field(default_factory=dict)
    ast_snapshot: Optional[Any] = None

    def zeroize(self) -> None:
        """Wipes source code buffer and snapshot dictionaries."""
        self.source_code = ""
        self.env_snapshot.clear()
        self.ast_snapshot = None
