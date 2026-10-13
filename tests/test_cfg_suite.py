"""
Comprehensive Unit & Integration Test Suite for Control Flow Graph (CFG) Engine,
Dynamic CALL / GOTO Label Interpretation, Jump Table Tracking, and Visualizers.
"""

import unittest
from src.parser import CmdASTParser
from src.ast_nodes import LabelNode, GotoNode, CallNode, ExitNode, CommandNode, ScriptNode
from src.normalizer import ASTNormalizer
from src.transforms.base import PassManager
from src.cfg import (
    CFGBuilder, ControlFlowGraph, CFGNode, CFGEdgeType,
    JumpTableResolver, CFGVisualizer
)


class TestCFGSuite(unittest.TestCase):
    """Test suite covering AST nodes, CFG construction, jump table resolution, and graph analytics."""

    def test_parse_label_nodes(self):
        source = """:start
echo Hello
:EOF
"""
        ast = CmdASTParser.from_source(source).parse()
        self.assertEqual(len(ast.statements), 3)
        self.assertIsInstance(ast.statements[0], LabelNode)
        self.assertEqual(ast.statements[0].name, "start")
        self.assertFalse(ast.statements[0].is_eof)

        self.assertIsInstance(ast.statements[2], LabelNode)
        self.assertEqual(ast.statements[2].name, "EOF")
        self.assertTrue(ast.statements[2].is_eof)

    def test_parse_goto_static_and_dynamic(self):
        source = """goto :cleanup
goto %NEXT_STAGE%
goto !TARGET!
goto :EOF
"""
        ast = CmdASTParser.from_source(source).parse()
        self.assertEqual(len(ast.statements), 4)

        # Static goto
        self.assertIsInstance(ast.statements[0], GotoNode)
        self.assertEqual(ast.statements[0].target, "cleanup")
        self.assertFalse(ast.statements[0].is_dynamic)
        self.assertFalse(ast.statements[0].is_eof)

        # Dynamic percent goto
        self.assertIsInstance(ast.statements[1], GotoNode)
        self.assertEqual(ast.statements[1].target, "%NEXT_STAGE%")
        self.assertTrue(ast.statements[1].is_dynamic)

        # Dynamic delayed goto
        self.assertIsInstance(ast.statements[2], GotoNode)
        self.assertEqual(ast.statements[2].target, "!TARGET!")
        self.assertTrue(ast.statements[2].is_dynamic)

        # Return EOF goto
        self.assertIsInstance(ast.statements[3], GotoNode)
        self.assertEqual(ast.statements[3].target.lower(), "eof")
        self.assertTrue(ast.statements[3].is_eof)

    def test_parse_call_statements(self):
        source = """call :my_subroutine arg1 arg2
call script.bat param1
call :!DYNAMIC_SUB!
"""
        ast = CmdASTParser.from_source(source).parse()
        self.assertEqual(len(ast.statements), 3)

        # Subroutine call
        call_sub = ast.statements[0]
        self.assertIsInstance(call_sub, CallNode)
        self.assertEqual(call_sub.target, "my_subroutine")
        self.assertTrue(call_sub.is_subroutine)
        self.assertFalse(call_sub.is_dynamic)
        self.assertEqual(len(call_sub.arguments), 2)

        # External file call
        call_ext = ast.statements[1]
        self.assertIsInstance(call_ext, CallNode)
        self.assertEqual(call_ext.target, "script.bat")
        self.assertFalse(call_ext.is_subroutine)
        self.assertEqual(len(call_ext.arguments), 1)

        # Dynamic subroutine call
        call_dyn = ast.statements[2]
        self.assertIsInstance(call_dyn, CallNode)
        self.assertTrue(call_dyn.is_subroutine)
        self.assertTrue(call_dyn.is_dynamic)

    def test_parse_exit_statements(self):
        source = """exit /b 0
exit /b 1
exit 2
exit
"""
        ast = CmdASTParser.from_source(source).parse()
        self.assertEqual(len(ast.statements), 4)

        self.assertIsInstance(ast.statements[0], ExitNode)
        self.assertTrue(ast.statements[0].is_batch_return)
        self.assertEqual(ast.statements[0].exit_code, "0")

        self.assertIsInstance(ast.statements[1], ExitNode)
        self.assertTrue(ast.statements[1].is_batch_return)
        self.assertEqual(ast.statements[1].exit_code, "1")

        self.assertIsInstance(ast.statements[2], ExitNode)
        self.assertFalse(ast.statements[2].is_batch_return)
        self.assertEqual(ast.statements[2].exit_code, "2")

        self.assertIsInstance(ast.statements[3], ExitNode)
        self.assertFalse(ast.statements[3].is_batch_return)
        self.assertIsNone(ast.statements[3].exit_code)

    def test_cfg_straight_line_flow(self):
        source = """echo Step 1
set A=1
echo Step 2
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Should have entry, 1 basic block, and exit
        self.assertIn("entry", cfg.nodes)
        self.assertIn("exit", cfg.nodes)
        self.assertEqual(len(cfg.nodes), 3)

        # Entry -> block_0 -> exit
        entry_succs = cfg.get_successors("entry")
        self.assertEqual(len(entry_succs), 1)
        first_block = entry_succs[0][0]
        self.assertEqual(len(first_block.statements), 3)

        block_succs = cfg.get_successors(first_block.id)
        self.assertEqual(len(block_succs), 1)
        self.assertEqual(block_succs[0][0].id, "exit")

    def test_cfg_batch_label_fallthrough(self):
        """Verify cmd.exe behavior where control falls through into label without a jump."""
        source = """echo Before
:section
echo Inside Section
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Expected blocks: entry, block_0 (Before), label_section (Inside), exit
        self.assertIn("label_section", cfg.nodes)
        label_node = cfg.nodes["label_section"]
        self.assertEqual(label_node.label, "section")

        # Fallthrough edge from block_0 to label_section must exist!
        preds = cfg.get_predecessors("label_section")
        self.assertTrue(any(p[1].edge_type == CFGEdgeType.FALLTHROUGH for p in preds))

    def test_cfg_unconditional_goto(self):
        source = """echo Start
goto :target
echo Unreachable
:target
echo Reached
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Find jump edge
        jump_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.JUMP]
        self.assertEqual(len(jump_edges), 1)
        self.assertEqual(jump_edges[0].target, "label_target")

        # Reachability check: block containing 'echo Unreachable' must be dead!
        cfg.compute_reachability()
        unreachable = cfg.get_unreachable_nodes()
        self.assertEqual(len(unreachable), 1)
        self.assertIn("Unreachable", [getattr(s, 'value', '') for s in unreachable[0].statements[0].arguments])

    def test_cfg_subroutine_call_and_return(self):
        source = """call :my_proc
echo After Call
goto :EOF

:my_proc
echo Inside Proc
exit /b 0
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Call edge exists
        call_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.CALL]
        self.assertEqual(len(call_edges), 1)
        self.assertEqual(call_edges[0].target, "label_my_proc")

        # Return edge to continuation block
        return_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.RETURN]
        self.assertTrue(len(return_edges) >= 1)

        # Subroutines mapping
        subs = cfg.get_subroutines()
        self.assertIn("my_proc", subs)
        self.assertTrue(len(subs["my_proc"]) >= 1)

    def test_cfg_if_branching(self):
        source = """if "%1"=="clean" (
    echo Cleaning
) else (
    echo Building
)
echo Done
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        cond_true_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.COND_TRUE]
        cond_false_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.COND_FALSE]
        self.assertEqual(len(cond_true_edges), 1)
        self.assertEqual(len(cond_false_edges), 1)

        metrics = cfg.compute_metrics()
        self.assertTrue(metrics.cyclomatic_complexity >= 2)

    def test_cfg_for_loop_and_cycle(self):
        source = """for %%i in (1 2 3) do (
    echo %%i
)
echo After For
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Back edge detected for loop
        back_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.BACK_EDGE]
        self.assertEqual(len(back_edges), 1)

        # Cycle finding
        cycles = cfg.find_cycles()
        self.assertTrue(len(cycles) >= 1)

    def test_backward_goto_cycle_detection(self):
        source = """:loop
echo Iterating
goto :loop
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        cycles = cfg.find_cycles()
        self.assertEqual(len(cycles), 1)
        self.assertIn("label_loop", cycles[0])

    def test_jump_table_resolution_static(self):
        """Simulate dynamic jump where variable was assigned previously."""
        source = """set STAGE=payload
goto %STAGE%
:payload
echo Decrypted
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        # Before resolution, dynamic jump exists
        dyn_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.DYNAMIC_JUMP]
        self.assertEqual(len(dyn_edges), 1)

        resolver = JumpTableResolver()
        report = resolver.resolve(cfg)

        self.assertEqual(report.total_dynamic_jumps, 1)
        self.assertEqual(report.resolved_jumps, 1)
        self.assertEqual(report.unresolved_jumps, 0)

        # After resolution, dynamic jump should be converted to JUMP -> label_payload
        jump_edges = [e for e in cfg.edges if e.target == "label_payload"]
        self.assertTrue(len(jump_edges) >= 1)

    def test_jump_table_resolution_cff_dispatch(self):
        """Simulate a Control Flow Flattening (CFF) state machine dispatcher."""
        source = """:dispatch
if "%STATE%"=="1" goto :state_1
if "%STATE%"=="2" goto :state_2
if "%STATE%"=="3" goto :state_3
goto :exit_label

:state_1
set STATE=2
goto :dispatch

:state_2
set STATE=3
goto :dispatch

:state_3
set STATE=done
goto :dispatch

:exit_label
echo Finished
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        resolver = JumpTableResolver()
        report = resolver.resolve(cfg)

        # CFF dispatcher detection
        self.assertIn("label_dispatch", report.cff_dispatchers)

    def test_cfg_metrics(self):
        source = """echo A
if "%X%"=="1" (
    echo B
)
echo C
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        metrics = cfg.compute_metrics()
        self.assertTrue(metrics.block_count >= 4)
        self.assertTrue(metrics.edge_count >= 4)
        self.assertTrue(metrics.cyclomatic_complexity >= 2)
        self.assertEqual(metrics.dead_block_ratio, 0.0)

    def test_cfg_visualizer_mermaid(self):
        source = """:main
echo Start
goto :end
:end
echo Done
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        mermaid = CFGVisualizer.to_mermaid(cfg)
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("classDef entryClass", mermaid)
        self.assertIn("classDef exitClass", mermaid)
        self.assertIn("entry", mermaid)
        self.assertIn("exit", mermaid)

    def test_cfg_visualizer_dot(self):
        source = """echo Test"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        dot = CFGVisualizer.to_dot(cfg)
        self.assertIn("digraph ControlFlowGraph", dot)
        self.assertIn('rankdir=TB', dot)

    def test_cfg_visualizer_ascii(self):
        source = """echo A
echo B"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        ascii_summary = CFGVisualizer.to_ascii(cfg)
        self.assertIn("CONTROL FLOW GRAPH SUMMARY", ascii_summary)
        self.assertIn("Cyclomatic Complexity", ascii_summary)

    def test_normalizer_to_source_control_flow_nodes(self):
        source = """:init
goto :cleanup
call :subroutine p1 p2
exit /b 0
"""
        ast = CmdASTParser.from_source(source).parse()
        normalizer = ASTNormalizer()
        src = normalizer.to_source(ast)

        self.assertIn(":init", src)
        self.assertIn("goto :cleanup", src)
        self.assertIn("call :subroutine p1 p2", src)
        self.assertIn("exit /b 0", src)

    def test_pass_manager_transforms_on_call_and_goto(self):
        """Pass manager should deobfuscate targets inside Call and Goto nodes."""
        source = "call :s^u^b^r^o^u^t^i^n^e"
        ast = CmdASTParser.from_source(source).parse()
        pm = PassManager.default_pipeline()
        transformed = pm.run(ast)

        self.assertIsInstance(transformed.statements[0], CallNode)
        self.assertEqual(transformed.statements[0].target, "subroutine")

    def test_jump_table_prefix_pattern_matching(self):
        """Dynamic jump with variable matching prefix of multiple labels."""
        source = """goto :stage_%COUNT%
:stage_init
echo Init
goto :EOF
:stage_run
echo Run
goto :EOF
:stage_cleanup
echo Cleanup
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        resolver = JumpTableResolver()
        report = resolver.resolve(cfg)

        self.assertEqual(report.total_dynamic_jumps, 1)
        self.assertEqual(report.resolved_jumps, 1)
        # Should resolve to all 3 candidate stages
        resolved_nodes = [t[2] for t in report.resolved_transitions]
        self.assertIn("label_stage_init", resolved_nodes)
        self.assertIn("label_stage_run", resolved_nodes)
        self.assertIn("label_stage_cleanup", resolved_nodes)

    def test_subroutine_multiple_returns(self):
        """Subroutine with multiple exit points (exit /b and goto :eof)."""
        source = """call :worker
echo Resumed
goto :EOF

:worker
if "%1"=="fast" exit /b 0
echo Doing slow work
goto :EOF
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        subs = cfg.get_subroutines()
        self.assertIn("worker", subs)
        # Verify return edges back to continuation block
        worker_blocks = subs["worker"]
        return_count = sum(1 for b in worker_blocks if b.has_return)
        self.assertTrue(return_count >= 1)

    def test_process_exit_node_semantics(self):
        """Plain exit terminates entire script with TERMINATE edge."""
        source = """echo Starting
exit 1
echo Unreachable
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        term_edges = [e for e in cfg.edges if e.edge_type == CFGEdgeType.TERMINATE]
        self.assertEqual(len(term_edges), 1)
        self.assertEqual(term_edges[0].target, "exit")

        cfg.compute_reachability()
        unreachable = cfg.get_unreachable_nodes()
        self.assertTrue(len(unreachable) >= 1)

    def test_cfg_to_dict_json_serialization(self):
        """Verify graph serialization produces expected dictionary structure."""
        source = """:entry_point
echo Running
goto :EOF
"""
        ast = CmdASTParser.from_source(source).parse()
        builder = CFGBuilder()
        cfg = builder.build(ast)

        d = cfg.to_dict()
        self.assertIn("entry_id", d)
        self.assertIn("exit_id", d)
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("metrics", d)
        self.assertIn("cyclomatic_complexity", d["metrics"])

    def test_cli_cfg_integration(self):
        """Verify CLI invocations with --cfg, --cfg-mermaid, --cfg-dot."""
        from src.cli import main
        import sys
        import io

        old_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            sys.argv = ["cmd-ast-deobfuscator", "-c", "echo Test & goto :EOF", "--cfg", "--cfg-mermaid", "--cfg-dot"]
            main()
            output = sys.stdout.getvalue()
            self.assertIn("CONTROL FLOW GRAPH SUMMARY", output)
            self.assertIn("flowchart TD", output)
            self.assertIn("digraph ControlFlowGraph", output)
        finally:
            sys.stdout = old_stdout


if __name__ == "__main__":
    unittest.main()

