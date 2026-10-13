"""
Data models and metrics for cmd.exe quote toggle boundary normalization.
Defines quote parsing states, token segments, and telemetry metrics.
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Tuple


class QuoteState(Enum):
    """Lexical state of quote toggle boundary."""
    OUTSIDE = auto()
    INSIDE = auto()
    ESCAPED = auto()


@dataclass
class QuoteSegment:
    """
    Segment of text categorized by quote state.
    """
    text: str
    is_quoted: bool
    is_escaped: bool = False
    span: Tuple[int, int] = (0, 0)

    def __len__(self) -> int:
        return len(self.text)


@dataclass
class QuoteNormalizerMetrics:
    """
    Telemetry and performance metrics for quote normalization operations.
    """
    total_tokens_processed: int = 0
    empty_pairs_collapsed: int = 0
    consecutive_quotes_reduced: int = 0
    targets_normalized: int = 0
    arguments_normalized: int = 0
    assignments_normalized: int = 0
    literals_normalized: int = 0

    def summary(self) -> str:
        """Returns formatted metrics summary."""
        lines = [
            f"  Tokens processed          : {self.total_tokens_processed}",
            f"  Empty quote pairs removed : {self.empty_pairs_collapsed}",
            f"  Consecutive quotes reduced: {self.consecutive_quotes_reduced}",
            f"  Command targets normalized: {self.targets_normalized}",
            f"  Arguments canonicalized   : {self.arguments_normalized}",
            f"  Assignments normalized    : {self.assignments_normalized}",
            f"  Literals normalized       : {self.literals_normalized}",
        ]
        return "\n".join(lines)
