"""
Interactive AST Pipeline Debugger and Step-by-Step TUI Inspector.
Enables step-by-step transform pass execution, state inspection, intermediate diffs,
and interactive terminal REPL debugging.
"""

from typing import List, Dict, Optional, Any, Callable
from ..ast_nodes import ASTNode
from ..parser import CmdASTParser
from ..normalizer import ASTNormalizer
from ..transforms.base import TransformPass, PassManager
from .models import (
    ANSI, ColorMode, DiffStyle, StepRecord, InspectorMetrics,
    should_color
)
from .diff import ColoredDiffRenderer
from .tree_view import ColoredASTTreeRenderer


class ASTPipelineDebugger:
    """
    Step-by-step transform debugger for cmd-ast-deobfuscator AST pipelines.
    """

    def __init__(
        self,
        source: str,
        passes: Optional[List[TransformPass]] = None,
        color_mode: ColorMode = ColorMode.AUTO,
    ):
        self.original_source = source
        self.color_mode = color_mode
        self.use_color = should_color(color_mode)

        self.diff_renderer = ColoredDiffRenderer(color_mode=color_mode)
        self.tree_renderer = ColoredASTTreeRenderer(color_mode=color_mode)

        # Parse initial AST
        ast_parser = CmdASTParser.from_source(source)
        self.initial_ast = ast_parser.parse()
        self.current_ast: ASTNode = self.initial_ast

        # Pipeline passes
        if passes is None:
            pm = PassManager.default_pipeline()
            self.passes: List[TransformPass] = pm.passes
        else:
            self.passes = list(passes)

        self.pass_index = 0
        self.iteration = 0
        self.max_iterations = 10

        self.history: List[StepRecord] = []
        self.metrics = InspectorMetrics()

        # Record initial baseline step 0
        init_record = StepRecord(
            step_index=0,
            pass_name="Initial Parse",
            modified=False,
            source_code=self._to_source(self.initial_ast),
            env_snapshot={},
            ast_snapshot=self.initial_ast,
        )
        self.history.append(init_record)

    def step(self) -> Optional[StepRecord]:
        """Executes the next single transform pass in the pipeline."""
        if self.is_complete():
            return None

        p = self.passes[self.pass_index]
        prev_code = self._to_source(self.current_ast)

        # Execute transformation pass
        self.current_ast = p.transform(self.current_ast)
        modified = p.modified
        new_code = self._to_source(self.current_ast)

        self.metrics.steps_executed += 1
        if modified:
            self.metrics.passes_modified += 1

        record = StepRecord(
            step_index=len(self.history),
            pass_name=p.name,
            modified=modified,
            source_code=new_code,
            env_snapshot=dict(p.env),
            ast_snapshot=self.current_ast,
        )
        self.history.append(record)

        # Advance cursor
        self.pass_index += 1
        if self.pass_index >= len(self.passes):
            self.pass_index = 0
            self.iteration += 1

        return record

    def run_until_modified(self) -> Optional[StepRecord]:
        """Executes passes until a pass modifies the AST, or the pipeline completes."""
        while not self.is_complete():
            rec = self.step()
            if rec and rec.modified:
                return rec
        return None

    def run_all(self) -> List[StepRecord]:
        """Runs all remaining passes until convergence or iteration limit."""
        results: List[StepRecord] = []
        consecutive_unmodified = 0
        total_passes = len(self.passes)

        while not self.is_complete():
            rec = self.step()
            if rec:
                results.append(rec)
                if rec.modified:
                    consecutive_unmodified = 0
                else:
                    consecutive_unmodified += 1
                if consecutive_unmodified >= total_passes:
                    break
        return results

    def is_complete(self) -> bool:
        """Checks if the debugger has reached the end of execution."""
        return self.iteration >= self.max_iterations

    def get_diff(
        self,
        style: DiffStyle = DiffStyle.UNIFIED,
        compare_with: str = "prev",
    ) -> str:
        """Returns colored diff comparing current state with previous step or original code."""
        self.metrics.diffs_rendered += 1
        current_code = self._to_source(self.current_ast)

        if compare_with == "orig":
            base_code = self.original_source
            label_a = "Original Obfuscated"
            label_b = f"Current (Step {len(self.history) - 1})"
        else:
            prev_idx = max(0, len(self.history) - 2)
            base_code = self.history[prev_idx].source_code
            prev_name = self.history[prev_idx].pass_name
            label_a = f"Before ({prev_name})"
            label_b = f"After ({self.history[-1].pass_name})"

        if style == DiffStyle.SIDE_BY_SIDE:
            return self.diff_renderer.render_side_by_side(
                base_code, current_code, color=self.use_color,
                label_a=label_a, label_b=label_b
            )
        return self.diff_renderer.render_unified(
            base_code, current_code, color=self.use_color,
            label_a=label_a, label_b=label_b
        )

    def get_tree(self, show_ids: bool = True, max_depth: Optional[int] = None) -> str:
        """Renders the current AST tree structure with colors and node IDs."""
        return self.tree_renderer.render(
            self.current_ast,
            color=self.use_color,
            show_ids=show_ids,
            max_depth=max_depth
        )

    def get_source(self) -> str:
        """Returns the current serialized batch source code."""
        return self._to_source(self.current_ast)

    def get_env(self) -> Dict[str, str]:
        """Returns the current environment symbol table."""
        if self.pass_index > 0 and self.pass_index <= len(self.passes):
            return dict(self.passes[self.pass_index - 1].env)
        return {}

    def get_passes_table(self) -> str:
        """Generates a formatted overview table of all pipeline passes and cursor status."""
        lines = []
        title = "=== Optimization Pipeline Passes ==="
        lines.append(f"{ANSI.BOLD}{ANSI.CYAN}{title}{ANSI.RESET}" if self.use_color else title)

        for i, p in enumerate(self.passes):
            marker = "►" if (i == self.pass_index and not self.is_complete()) else " "
            # Find if this pass has run and modified
            has_modified = any(r.pass_name == p.name and r.modified for r in self.history)
            has_run = any(r.pass_name == p.name for r in self.history)

            status = "PENDING"
            if has_modified:
                status = "MODIFIED"
            elif has_run:
                status = "CLEAN"

            if self.use_color:
                if status == "MODIFIED":
                    status_col = f"{ANSI.GREEN}{status:<8}{ANSI.RESET}"
                elif status == "CLEAN":
                    status_col = f"{ANSI.GRAY}{status:<8}{ANSI.RESET}"
                else:
                    status_col = f"{ANSI.YELLOW}{status:<8}{ANSI.RESET}"
                cur_marker = f"{ANSI.BOLD}{ANSI.CYAN}{marker}{ANSI.RESET}"
                lines.append(f"  {cur_marker} [{i + 1:>2}] {p.name:<28} : {status_col}")
            else:
                lines.append(f"  {marker} [{i + 1:>2}] {p.name:<28} : {status:<8}")

        iter_info = f"Iteration: {self.iteration + 1}/{self.max_iterations} (Step: {len(self.history) - 1})"
        lines.append(f"{ANSI.DIM}{iter_info}{ANSI.RESET}" if self.use_color else iter_info)
        return "\n".join(lines)

    def inspect_node(self, node_id: int) -> str:
        """Inspects attributes of a specific AST node by its identifier."""
        self.metrics.nodes_inspected += 1
        node = self.tree_renderer.get_node_by_id(node_id)
        if node is None:
            # Re-render tree to ensure cache is populated
            self.tree_renderer.render(self.current_ast, show_ids=True)
            node = self.tree_renderer.get_node_by_id(node_id)

        if node is None:
            return f"[-] Node ID #{node_id} not found in current AST."
        return self.tree_renderer.format_node_details(node, color=self.use_color)

    def reset(self) -> None:
        """Resets the AST and pipeline back to the initial parsed state."""
        self.current_ast = self.initial_ast
        self.pass_index = 0
        self.iteration = 0
        self.history = self.history[:1]
        for p in self.passes:
            p.modified = False

    def execute_command(self, cmd_line: str) -> str:
        """Executes a single inspector command and returns formatted output."""
        tokens = cmd_line.strip().split()
        if not tokens:
            return ""

        cmd = tokens[0].lower()
        args = tokens[1:]

        if cmd in ("step", "s"):
            rec = self.step()
            if rec is None:
                return "[*] Pipeline completed or converged. No further steps."
            mod_str = "MODIFIED" if rec.modified else "UNCHANGED"
            return f"[✓] Executed {rec.pass_name} -> {mod_str}"

        elif cmd in ("next", "n"):
            rec = self.run_until_modified()
            if rec is None:
                return "[*] Reached end of pipeline without modifications."
            return f"[✓] Advanced to modifying pass: {rec.pass_name}"

        elif cmd in ("run", "continue", "c"):
            recs = self.run_all()
            mod_count = sum(1 for r in recs if r.modified)
            return f"[✓] Ran {len(recs)} steps ({mod_count} modified). Pipeline finished."

        elif cmd in ("diff", "d"):
            style = DiffStyle.SIDE_BY_SIDE if ("--side" in args or "-s" in args) else DiffStyle.UNIFIED
            cmp_target = "orig" if ("--orig" in args or "-o" in args) else "prev"
            return self.get_diff(style=style, compare_with=cmp_target)

        elif cmd in ("tree", "t"):
            max_d = int(args[0]) if (args and args[0].isdigit()) else None
            return self.get_tree(max_depth=max_d)

        elif cmd in ("passes", "p"):
            return self.get_passes_table()

        elif cmd in ("source", "src", "code"):
            return self.get_source()

        elif cmd in ("env", "e"):
            env = self.get_env()
            if not env:
                return "[*] Environment symbol table is currently empty."
            lines = ["=== Current Environment Symbols ==="]
            for k in sorted(env.keys()):
                lines.append(f"  {k} = {env[k]}")
            return "\n".join(lines)

        elif cmd in ("node", "inspect", "i"):
            if not args or not args[0].isdigit():
                return "[-] Usage: node <node_id> (e.g., node 3)"
            return self.inspect_node(int(args[0]))

        elif cmd in ("reset", "r"):
            self.reset()
            return "[✓] Reset AST pipeline to initial state."

        elif cmd in ("stats",):
            d = self.metrics.to_dict()
            return "\n".join(f"  {k}: {v}" for k, v in d.items())

        elif cmd in ("help", "h", "?"):
            return self._help_text()

        elif cmd in ("quit", "q", "exit"):
            return "QUIT"

        return f"[-] Unknown command: {cmd!r}. Type 'help' for available commands."

    def repl(
        self,
        input_fn: Optional[Callable[[str], str]] = None,
        output_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Interactive REPL debugger loop."""
        in_fn = input_fn or input
        out_fn = output_fn or print

        banner = (
            f"\n{ANSI.BOLD}{ANSI.CYAN}=== cmd-ast-deobfuscator TUI Pipeline Debugger ==={ANSI.RESET}\n"
            f"Type {ANSI.YELLOW}'step'{ANSI.RESET} or {ANSI.YELLOW}'s'{ANSI.RESET} to advance, "
            f"{ANSI.YELLOW}'diff'{ANSI.RESET} to compare, {ANSI.YELLOW}'tree'{ANSI.RESET} for AST, "
            f"or {ANSI.YELLOW}'help'{ANSI.RESET} for commands.\n"
        )
        out_fn(banner if self.use_color else banner.replace(ANSI.RESET, ""))

        while True:
            try:
                prompt = f"{ANSI.BOLD}(cmd-dbg {self.pass_index + 1}/{len(self.passes)})>{ANSI.RESET} " if self.use_color else f"(cmd-dbg {self.pass_index + 1}/{len(self.passes)})> "
                cmd_line = in_fn(prompt)
                if not cmd_line or not cmd_line.strip():
                    continue
                result = self.execute_command(cmd_line)
                if result == "QUIT":
                    out_fn("[*] Exiting TUI Debugger.")
                    break
                if result:
                    out_fn(result)
            except (EOFError, KeyboardInterrupt):
                out_fn("\n[*] Debugger session terminated.")
                break

    def zeroize(self) -> None:
        """Securely clears buffers, history snapshots, and telemetry."""
        for rec in self.history:
            rec.zeroize()
        self.history.clear()
        self.original_source = ""
        self.metrics.zeroize()

    @staticmethod
    def _to_source(node: ASTNode) -> str:
        normalizer = ASTNormalizer()
        return normalizer.to_source(node)

    @staticmethod
    def _help_text() -> str:
        return (
            "=== Available Debugger Commands ===\n"
            "  step, s              : Execute next transform pass\n"
            "  next, n              : Run until a pass modifies the AST\n"
            "  run, c               : Run all passes until convergence\n"
            "  diff, d [--side]     : Show colored diff against previous step\n"
            "  diff --orig          : Show colored diff against original code\n"
            "  tree, t [depth]      : Print colored AST hierarchy with node IDs\n"
            "  node, inspect <id>   : Inspect properties of an AST node by ID\n"
            "  passes, p            : Show list of transform passes and status\n"
            "  source, src          : Display current deobfuscated source code\n"
            "  env, e               : Display current environment symbol table\n"
            "  reset, r             : Reset pipeline back to initial parse\n"
            "  stats                : Display inspector session telemetry\n"
            "  help, h, ?           : Display this help menu\n"
            "  quit, q, exit        : Exit the debugger session"
        )
