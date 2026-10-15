"""
Interactive Terminal AST Inspector and Colored Diff Visualizer (TUI Debugger).
Provides unified and side-by-side colored diff rendering, colorized AST trees,
and interactive step-by-step pipeline debugging for cmd.exe scripts.
"""

from .models import (
    DiffStyle,
    ColorMode,
    DiffLineType,
    DiffLine,
    DiffMetrics,
    InspectorMetrics,
    StepRecord,
    ANSI,
    strip_ansi,
    ansi_len,
    should_color,
)
from .diff import ColoredDiffRenderer
from .tree_view import ColoredASTTreeRenderer
from .debugger import ASTPipelineDebugger

__all__ = [
    "DiffStyle",
    "ColorMode",
    "DiffLineType",
    "DiffLine",
    "DiffMetrics",
    "InspectorMetrics",
    "StepRecord",
    "ANSI",
    "strip_ansi",
    "ansi_len",
    "should_color",
    "ColoredDiffRenderer",
    "ColoredASTTreeRenderer",
    "ASTPipelineDebugger",
]
