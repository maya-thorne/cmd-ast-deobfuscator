"""
Unit & Integration Test Suite for TUI Inspector and Colored Diff Visualizer (M16).
Tests ANSI stylers, unified/side-by-side diff rendering, colored AST trees,
step-by-step pipeline debugger, memory zeroization, and CLI flags.
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

from src.ast_nodes import CommandNode, LiteralNode, AssignmentNode
from src.parser import CmdASTParser
from src.tui import (
    DiffStyle, ColorMode, DiffMetrics, InspectorMetrics, StepRecord,
    ANSI, strip_ansi, ansi_len, should_color,
    ColoredDiffRenderer, ColoredASTTreeRenderer, ASTPipelineDebugger
)


class TestTUIModelsAndStyler(unittest.TestCase):
    """Tests for ANSI escape formatting, strip helpers, and telemetry models."""

    def test_strip_ansi_and_length(self):
        colored = f"{ANSI.BOLD}{ANSI.RED}hello{ANSI.RESET} {ANSI.GREEN}world{ANSI.RESET}"
        self.assertEqual(strip_ansi(colored), "hello world")
        self.assertEqual(ansi_len(colored), 11)
        self.assertEqual(strip_ansi(""), "")
        self.assertEqual(ansi_len(""), 0)

    def test_should_color_policies(self):
        self.assertTrue(should_color(ColorMode.ALWAYS))
        self.assertFalse(should_color(ColorMode.NEVER))

        # Test NO_COLOR environment variable compliance
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(should_color(ColorMode.AUTO))

        with patch.dict(os.environ, {}, clear=True):
            fake_tty = io.StringIO()
            fake_tty.isatty = lambda: True
            self.assertTrue(should_color(ColorMode.AUTO, stream=fake_tty))

            fake_non_tty = io.StringIO()
            fake_non_tty.isatty = lambda: False
            self.assertFalse(should_color(ColorMode.AUTO, stream=fake_non_tty))

    def test_diff_metrics_and_zeroize(self):
        metrics = DiffMetrics(
            lines_before=10,
            lines_after=8,
            additions=2,
            deletions=4,
            modifications=1,
            similarity_ratio=0.85432,
        )
        d = metrics.to_dict()
        self.assertEqual(d["lines_before"], 10)
        self.assertEqual(d["similarity_ratio"], 0.8543)

        metrics.zeroize()
        self.assertEqual(metrics.lines_before, 0)
        self.assertEqual(metrics.similarity_ratio, 1.0)

    def test_inspector_metrics_and_step_record_zeroize(self):
        insp = InspectorMetrics(steps_executed=5, passes_modified=3, nodes_inspected=12)
        d = insp.to_dict()
        self.assertEqual(d["steps_executed"], 5)
        self.assertEqual(d["passes_modified"], 3)
        insp.zeroize()
        self.assertEqual(insp.steps_executed, 0)

        record = StepRecord(
            step_index=1,
            pass_name="TestPass",
            modified=True,
            source_code="set a=1",
            env_snapshot={"a": "1"},
        )
        self.assertEqual(record.source_code, "set a=1")
        record.zeroize()
        self.assertEqual(record.source_code, "")
        self.assertEqual(len(record.env_snapshot), 0)


class TestColoredDiffRenderer(unittest.TestCase):
    """Tests for unified and side-by-side diff rendering."""

    def setUp(self):
        self.renderer = ColoredDiffRenderer(color_mode=ColorMode.ALWAYS)
        self.orig = "s^e^t VAR=c^a^l^c\n%VAR%\n"
        self.mod = "set VAR=calc\ncalc\n"

    def test_compute_metrics(self):
        metrics = self.renderer.compute_metrics(self.orig, self.mod)
        self.assertGreater(metrics.lines_before, 0)
        self.assertGreater(metrics.lines_after, 0)
        self.assertLess(metrics.similarity_ratio, 1.0)
        self.assertGreater(metrics.similarity_ratio, 0.0)

    def test_render_unified_diff_colored(self):
        diff_out = self.renderer.render_unified(self.orig, self.mod, color=True)
        self.assertIn("--- a/original", diff_out)
        self.assertIn("+++ b/deobfuscated", diff_out)
        self.assertIn(ANSI.RED, diff_out)
        self.assertIn(ANSI.GREEN, diff_out)

    def test_render_unified_diff_plain(self):
        diff_out = self.renderer.render_unified(self.orig, self.mod, color=False)
        self.assertIn("--- a/original", diff_out)
        self.assertIn("+++ b/deobfuscated", diff_out)
        self.assertNotIn("\033[", diff_out)

    def test_render_side_by_side_diff_structure(self):
        diff_out = self.renderer.render_side_by_side(
            self.orig, self.mod, color=True, width=100
        )
        self.assertIn("Original", diff_out)
        self.assertIn("Deobfuscated", diff_out)
        self.assertIn("│", diff_out)
        self.assertIn("┌", diff_out)
        self.assertIn("└", diff_out)

    def test_render_side_by_side_plain(self):
        diff_out = self.renderer.render_side_by_side(
            self.orig, self.mod, color=False, width=80
        )
        self.assertNotIn("\033[", diff_out)
        self.assertIn("Original", diff_out)
        self.assertIn("Deobfuscated", diff_out)

    def test_render_step_diff(self):
        step_unified = self.renderer.render_step_diff(
            "CaretNormalizer", self.orig, self.mod, color=False, style=DiffStyle.UNIFIED
        )
        self.assertIn("=== [Pass Diff: CaretNormalizer] ===", step_unified)
        self.assertIn("--- a/before_CaretNormalizer", step_unified)

        step_sbs = self.renderer.render_step_diff(
            "CaretNormalizer", self.orig, self.mod, color=False, style=DiffStyle.SIDE_BY_SIDE
        )
        self.assertIn("=== [Pass Diff: CaretNormalizer] ===", step_sbs)
        self.assertIn("Before CaretNormalizer", step_sbs)


class TestColoredASTTreeRenderer(unittest.TestCase):
    """Tests for AST tree visualization and node indexing."""

    def setUp(self):
        self.renderer = ColoredASTTreeRenderer(color_mode=ColorMode.ALWAYS)
        source = "set a=1 & c^a^l^c"
        parser = CmdASTParser.from_source(source)
        self.ast = parser.parse()

    def test_render_colored_tree(self):
        tree = self.renderer.render(self.ast, color=True, show_ids=True)
        self.assertIn("[#1]", tree)
        self.assertIn(ANSI.CYAN, tree)
        self.assertIn("CommandNode", tree)

    def test_render_plain_tree(self):
        tree = self.renderer.render(self.ast, color=False, show_ids=False)
        self.assertNotIn("\033[", tree)
        self.assertNotIn("[#1]", tree)
        self.assertIn("CommandNode", tree)

    def test_node_retrieval_and_details(self):
        tree = self.renderer.render(self.ast, color=False, show_ids=True)
        node_1 = self.renderer.get_node_by_id(1)
        self.assertIsNotNone(node_1)

        details = self.renderer.format_node_details(node_1, color=False)
        self.assertIn("Node Details:", details)

    def test_max_depth_clamping(self):
        tree = self.renderer.render(self.ast, color=False, max_depth=1)
        self.assertIn("(children truncated)", tree)


class TestASTPipelineDebugger(unittest.TestCase):
    """Tests for step-by-step transform debugging and commands."""

    def setUp(self):
        self.source = "s^e^t ^\"A=c^a^l^c^\"\n%A%\n"
        self.dbg = ASTPipelineDebugger(self.source, color_mode=ColorMode.NEVER)

    def test_initial_state_and_history(self):
        self.assertEqual(len(self.dbg.history), 1)
        self.assertEqual(self.dbg.history[0].pass_name, "Initial Parse")
        self.assertFalse(self.dbg.is_complete())

    def test_step_execution(self):
        rec = self.dbg.step()
        self.assertIsNotNone(rec)
        self.assertEqual(len(self.dbg.history), 2)
        self.assertIn("CaretNormalizerPass", rec.pass_name)

    def test_run_until_modified(self):
        rec = self.dbg.run_until_modified()
        self.assertIsNotNone(rec)
        self.assertTrue(rec.modified)

    def test_run_all(self):
        recs = self.dbg.run_all()
        self.assertGreater(len(recs), 0)
        final_src = self.dbg.get_source()
        self.assertIn("calc", final_src)

    def test_diff_generation(self):
        self.dbg.run_all()
        diff_prev = self.dbg.get_diff(compare_with="prev")
        diff_orig = self.dbg.get_diff(compare_with="orig")
        self.assertIsInstance(diff_prev, str)
        self.assertIsInstance(diff_orig, str)

    def test_debugger_commands(self):
        # Step command
        out = self.dbg.execute_command("step")
        self.assertIn("Executed", out)

        # Passes table
        passes_out = self.dbg.execute_command("passes")
        self.assertIn("Optimization Pipeline Passes", passes_out)

        # Source command
        src_out = self.dbg.execute_command("src")
        self.assertIsInstance(src_out, str)

        # Tree command
        tree_out = self.dbg.execute_command("tree")
        self.assertIn("ScriptNode", tree_out)

        # Node inspection
        node_out = self.dbg.execute_command("node 1")
        self.assertIn("Node Details", node_out)

        # Stats command
        stats_out = self.dbg.execute_command("stats")
        self.assertIn("steps_executed", stats_out)

        # Help command
        help_out = self.dbg.execute_command("help")
        self.assertIn("Available Debugger Commands", help_out)

        # Reset command
        reset_out = self.dbg.execute_command("reset")
        self.assertIn("Reset AST pipeline", reset_out)
        self.assertEqual(len(self.dbg.history), 1)

        # Quit command
        quit_out = self.dbg.execute_command("quit")
        self.assertEqual(quit_out, "QUIT")

    def test_repl_scripted_session(self):
        commands = iter(["step", "tree", "node 1", "quit"])
        output_buffer = []

        self.dbg.repl(
            input_fn=lambda prompt: next(commands),
            output_fn=lambda msg: output_buffer.append(msg),
        )

        full_output = "\n".join(output_buffer)
        self.assertIn("cmd-ast-deobfuscator TUI Pipeline Debugger", full_output)
        self.assertIn("Exiting TUI Debugger", full_output)

    def test_zeroize(self):
        self.dbg.run_all()
        self.assertGreater(len(self.dbg.history), 0)
        self.dbg.zeroize()
        self.assertEqual(len(self.dbg.history), 0)
        self.assertEqual(self.dbg.original_source, "")


class TestCLITUIIntegration(unittest.TestCase):
    """Tests CLI arguments integration for diff, side-by-side, and inspect."""

    def test_cli_diff_flag(self):
        from src.cli import main
        test_args = ["cli.py", "-c", "s^e^t a=1", "--diff", "--no-color"]
        with patch.object(sys, "argv", test_args):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                main()
                output = mock_stdout.getvalue()
                self.assertIn("DEOBFUSCATION DIFF", output)
                self.assertIn("--- a/original", output)

    def test_cli_side_by_side_flag(self):
        from src.cli import main
        test_args = ["cli.py", "-c", "s^e^t a=1", "--side-by-side", "--no-color"]
        with patch.object(sys, "argv", test_args):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                main()
                output = mock_stdout.getvalue()
                self.assertIn("DEOBFUSCATION DIFF", output)
                self.assertIn("Original", output)
                self.assertIn("Deobfuscated", output)

    def test_cli_step_diff_flag(self):
        from src.cli import main
        test_args = ["cli.py", "-c", "s^e^t a=c^a^l^c", "--step-diff", "--no-color"]
        with patch.object(sys, "argv", test_args):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 0)
                output = mock_stdout.getvalue()
                self.assertIn("STEP-BY-STEP TRANSFORM PIPELINE DIFF", output)

    def test_cli_diff_stats_flag(self):
        from src.cli import main
        test_args = ["cli.py", "-c", "s^e^t a=1", "--diff-stats", "--no-color"]
        with patch.object(sys, "argv", test_args):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                main()
                output = mock_stdout.getvalue()
                self.assertIn("DEOBFUSCATION DIFF STATS", output)
                self.assertIn("similarity_ratio", output)


if __name__ == "__main__":
    unittest.main()
