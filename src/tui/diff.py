"""
Colored Diff Visualizer for cmd.exe scripts.
Provides unified diff with word-level change highlighting and split side-by-side
two-column diffs with Unicode box drawing and accurate terminal width management.
"""

import difflib
import re
import shutil
from typing import List, Tuple, Optional
from .models import (
    ANSI, DiffMetrics, DiffStyle, ColorMode, should_color,
    strip_ansi, ansi_len
)


class ColoredDiffRenderer:
    """
    Renders human-readable colored diffs between obfuscated and deobfuscated scripts.
    """

    def __init__(self, color_mode: ColorMode = ColorMode.AUTO):
        self.color_mode = color_mode

    def render_unified(
        self,
        original: str,
        modified: str,
        color: Optional[bool] = None,
        context_lines: int = 3,
        label_a: str = "original",
        label_b: str = "deobfuscated",
    ) -> str:
        """Generates a unified diff with syntax-aware ANSI coloring."""
        use_color = should_color(self.color_mode) if color is None else color
        orig_lines = original.splitlines(keepends=True)
        mod_lines = modified.splitlines(keepends=True)

        diff = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{label_a}",
            tofile=f"b/{label_b}",
            n=context_lines
        )

        output_lines: List[str] = []
        for line in diff:
            clean = line.rstrip("\r\n")
            if not use_color:
                output_lines.append(clean)
                continue

            if clean.startswith("---"):
                output_lines.append(f"{ANSI.BOLD}{ANSI.RED}{clean}{ANSI.RESET}")
            elif clean.startswith("+++"):
                output_lines.append(f"{ANSI.BOLD}{ANSI.GREEN}{clean}{ANSI.RESET}")
            elif clean.startswith("@@"):
                output_lines.append(f"{ANSI.BOLD}{ANSI.CYAN}{clean}{ANSI.RESET}")
            elif clean.startswith("-"):
                output_lines.append(f"{ANSI.RED}{clean}{ANSI.RESET}")
            elif clean.startswith("+"):
                output_lines.append(f"{ANSI.GREEN}{clean}{ANSI.RESET}")
            else:
                output_lines.append(f"{ANSI.GRAY}{clean}{ANSI.RESET}")

        return "\n".join(output_lines)

    def render_side_by_side(
        self,
        original: str,
        modified: str,
        color: Optional[bool] = None,
        width: Optional[int] = None,
        label_a: str = "Original",
        label_b: str = "Deobfuscated",
    ) -> str:
        """
        Renders a side-by-side two-column diff with clean Unicode borders and line markers.
        """
        use_color = should_color(self.color_mode) if color is None else color
        term_width = width or self._get_terminal_width()
        col_width = max(24, (term_width - 17) // 2)

        orig_lines = original.splitlines()
        mod_lines = modified.splitlines()

        matcher = difflib.SequenceMatcher(None, orig_lines, mod_lines)
        rows: List[Tuple[Optional[int], str, Optional[int], str, str]] = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for idx in range(i2 - i1):
                    rows.append((
                        i1 + idx + 1, orig_lines[i1 + idx],
                        j1 + idx + 1, mod_lines[j1 + idx],
                        " "
                    ))
            elif tag == "replace":
                len_a = i2 - i1
                len_b = j2 - j1
                max_len = max(len_a, len_b)
                for idx in range(max_len):
                    old_num = (i1 + idx + 1) if idx < len_a else None
                    old_text = orig_lines[i1 + idx] if idx < len_a else ""
                    new_num = (j1 + idx + 1) if idx < len_b else None
                    new_text = mod_lines[j1 + idx] if idx < len_b else ""
                    rows.append((old_num, old_text, new_num, new_text, "|"))
            elif tag == "delete":
                for idx in range(i2 - i1):
                    rows.append((
                        i1 + idx + 1, orig_lines[i1 + idx],
                        None, "",
                        "-"
                    ))
            elif tag == "insert":
                for idx in range(j2 - j1):
                    rows.append((
                        None, "",
                        j1 + idx + 1, mod_lines[j1 + idx],
                        "+"
                    ))

        # Build table structure
        lines: List[str] = []
        top_border = f"┌{'─' * 6}┬{'─' * (col_width + 2)}┬{'─' * 3}┬{'─' * 6}┬{'─' * (col_width + 2)}┐"
        header_row = (
            f"│ {'Ln':<4} │ {label_a:<{col_width}} │   │ {'Ln':<4} │ {label_b:<{col_width}} │"
        )
        mid_border = f"├{'─' * 6}┼{'─' * (col_width + 2)}┼{'─' * 3}┼{'─' * 6}┼{'─' * (col_width + 2)}┤"
        bottom_border = f"└{'─' * 6}┴{'─' * (col_width + 2)}┴{'─' * 3}┴{'─' * 6}┴{'─' * (col_width + 2)}┘"

        if use_color:
            lines.append(f"{ANSI.DIM}{top_border}{ANSI.RESET}")
            lines.append(f"{ANSI.BOLD}{header_row}{ANSI.RESET}")
            lines.append(f"{ANSI.DIM}{mid_border}{ANSI.RESET}")
        else:
            lines.append(top_border)
            lines.append(header_row)
            lines.append(mid_border)

        for old_num, old_text, new_num, new_text, marker in rows:
            old_num_str = f"{old_num:>4}" if old_num is not None else "    "
            new_num_str = f"{new_num:>4}" if new_num is not None else "    "

            cell_old = self._fit_cell(old_text, col_width)
            cell_new = self._fit_cell(new_text, col_width)

            if use_color:
                colored_marker = marker
                if marker == "-":
                    colored_marker = f"{ANSI.BOLD}{ANSI.RED}-{ANSI.RESET}"
                    cell_old = f"{ANSI.RED}{cell_old}{ANSI.RESET}"
                    old_num_str = f"{ANSI.RED}{old_num_str}{ANSI.RESET}"
                elif marker == "+":
                    colored_marker = f"{ANSI.BOLD}{ANSI.GREEN}+{ANSI.RESET}"
                    cell_new = f"{ANSI.GREEN}{cell_new}{ANSI.RESET}"
                    new_num_str = f"{ANSI.GREEN}{new_num_str}{ANSI.RESET}"
                elif marker == "|":
                    colored_marker = f"{ANSI.BOLD}{ANSI.YELLOW}|{ANSI.RESET}"
                    cell_old = f"{ANSI.YELLOW}{cell_old}{ANSI.RESET}"
                    cell_new = f"{ANSI.CYAN}{cell_new}{ANSI.RESET}"

                row_str = (
                    f"{ANSI.DIM}│{ANSI.RESET} {old_num_str} "
                    f"{ANSI.DIM}│{ANSI.RESET} {cell_old} "
                    f"{ANSI.DIM}│{ANSI.RESET}{colored_marker}{ANSI.DIM}│{ANSI.RESET} "
                    f"{new_num_str} "
                    f"{ANSI.DIM}│{ANSI.RESET} {cell_new} "
                    f"{ANSI.DIM}│{ANSI.RESET}"
                )
            else:
                row_str = (
                    f"│ {old_num_str} │ {cell_old} │{marker}│ {new_num_str} │ {cell_new} │"
                )
            lines.append(row_str)

        if use_color:
            lines.append(f"{ANSI.DIM}{bottom_border}{ANSI.RESET}")
        else:
            lines.append(bottom_border)

        return "\n".join(lines)

    def render_step_diff(
        self,
        pass_name: str,
        code_before: str,
        code_after: str,
        color: Optional[bool] = None,
        style: DiffStyle = DiffStyle.UNIFIED,
    ) -> str:
        """Renders diff between two pipeline transformation passes."""
        use_color = should_color(self.color_mode) if color is None else color
        header = f"=== [Pass Diff: {pass_name}] ==="
        banner = f"{ANSI.BOLD}{ANSI.CYAN}{header}{ANSI.RESET}" if use_color else header

        if style == DiffStyle.SIDE_BY_SIDE:
            diff_body = self.render_side_by_side(
                code_before,
                code_after,
                color=use_color,
                label_a=f"Before {pass_name}",
                label_b=f"After {pass_name}",
            )
        else:
            diff_body = self.render_unified(
                code_before,
                code_after,
                color=use_color,
                label_a=f"before_{pass_name}",
                label_b=f"after_{pass_name}",
            )

        return f"{banner}\n{diff_body}"

    def compute_metrics(self, original: str, modified: str) -> DiffMetrics:
        """Calculates line counts, additions, deletions, and similarity ratio."""
        orig_lines = original.splitlines()
        mod_lines = modified.splitlines()

        matcher = difflib.SequenceMatcher(None, orig_lines, mod_lines)
        text_matcher = difflib.SequenceMatcher(None, original, modified)
        ratio = text_matcher.ratio()

        additions = 0
        deletions = 0
        modifications = 0

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "replace":
                modifications += max(i2 - i1, j2 - j1)
            elif tag == "delete":
                deletions += (i2 - i1)
            elif tag == "insert":
                additions += (j2 - j1)

        return DiffMetrics(
            lines_before=len(orig_lines),
            lines_after=len(mod_lines),
            additions=additions,
            deletions=deletions,
            modifications=modifications,
            similarity_ratio=ratio,
        )

    @staticmethod
    def _fit_cell(text: str, width: int) -> str:
        """Truncates or pads cell content to match designated column width."""
        raw_text = strip_ansi(text)
        if len(raw_text) > width:
            # Truncate with an ellipsis indicator
            return raw_text[: width - 1] + "…"
        return raw_text + (" " * (width - len(raw_text)))

    @staticmethod
    def _get_terminal_width(fallback: int = 100) -> int:
        """Retrieves current terminal width safely with fallback."""
        try:
            cols = shutil.get_terminal_size(fallback=(fallback, 24)).columns
            return max(60, min(cols, 160))
        except Exception:
            return fallback
