"""
Unit and Integration Test Suite for Control Flow Flattening (CFF) Loop Unrolling and Structuring (M22).
Tests linear switch dispatcher unrolling, bounded deterministic loop full unrolling,
data-dependent while-loop recovery, multi-state cycles, dead state pruning,
fallthrough state updates, DoS limits, memory zeroization, and CLI flags.
"""
import unittest
import io
import sys
from unittest.mock import patch
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    ScriptNode, CommandNode, LiteralNode, AssignmentNode,
    IfNode, BlockNode, GotoNode, LabelNode, ExitNode
)
from src.cff import (
    CFFPatternType, CFFLoopType, UnrollMode, CFFTransition, CFFBlockInfo,
    CFFStateMachine, CFFLoopInfo, CFFUnrollConfig, DeflatMetrics, DeflatResult,
    CFFAnalyzer, CFFLoopDetector, CFFDispatcherUnroller, CFFLinearizer, CFFDecompiler
)
from src.transforms.deflat_pass import DeflatPass
from src.transforms.base import PassManager
class TestCFFUnrollerSuite(unittest.TestCase):
    """Exhaustive test suite for CFF loop detection, unrolling, and structuring."""
    def setUp(self):
        self.analyzer = CFFAnalyzer()
        self.detector = CFFLoopDetector()
        self.unroller = CFFDispatcherUnroller()
        self.linearizer = CFFLinearizer()
        self.decompiler = CFFDecompiler()
        self.normalizer = ASTNormalizer()
    # 1. Linear Switch Dispatcher Unrolling Tests
    def test_linear_switch_dispatcher_full_unroll(self):
        code = (
            "set state=s1\n"
            ":dispatch\n"
            "if \"%state%\"==\"s1\" goto :b1\n"
            "if \"%state%\"==\"s2\" goto :b2\n"
            "if \"%state%\"==\"s3\" goto :b3\n"
            "goto :dispatch\n"
            ":b1\n"
            "echo Step 1\n"
            "set state=s2\n"
            "goto :dispatch\n"
            ":b2\n"
            "echo Step 2\n"
            "set state=s3\n"
            "goto :dispatch\n"
            ":b3\n"
            "echo Step 3\n"
            "exit /b 0\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.states_unrolled, 3)
        self.assertEqual(res.metrics.blocks_linearized, 3)
        self.assertEqual(res.metrics.dead_jumps_pruned, 2)
        out = self.normalizer.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertIn("Step 1", out)
        self.assertIn("Step 2", out)
        self.assertIn("Step 3", out)
        self.assertNotIn("goto :dispatch", out)
        self.assertNotIn("set state=", out)
    # 2. Bounded Deterministic Loop Full Unrolling (3 and 5 iterations)
    def test_bounded_deterministic_loop_3_iterations(self):
        code = (
            "set state=0\n"
            "set i=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_loop\n"
            "if \"%state%\"==\"1\" goto :b_exit\n"
            "goto :dispatch\n"
            ":b_loop\n"
            "echo Iteration Item\n"
            "set /a i+=1\n"
            "if %i% equ 3 (set state=1) else (set state=0)\n"
            "goto :dispatch\n"
            ":b_exit\n"
            "echo Finished Loop\n"
            "exit /b 0\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        loops, dead = self.detector.detect(sm, CFFUnrollConfig())
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].header_state, "0")
        self.assertEqual(loops[0].loop_type, CFFLoopType.DETERMINISTIC_UNROLLED)
        self.assertEqual(loops[0].iteration_count, 3)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.loops_fully_unrolled, 1)
        out = self.normalizer.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertEqual(out.count("Iteration Item"), 3)
        self.assertIn("Finished Loop", out)
        self.assertNotIn("loop_0", out)
    def test_bounded_deterministic_loop_5_iterations(self):
        code = (
            "set state=0\n"
            "set i=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_body\n"
            "if \"%state%\"==\"1\" goto :b_done\n"
            "goto :dispatch\n"
            ":b_body\n"
            "echo Running Payload Pass\n"
            "set /a i+=1\n"
            "if %i% equ 5 (set state=1) else (set state=0)\n"
            "goto :dispatch\n"
            ":b_done\n"
            "echo Completed Five Iterations\n"
            "exit /b 0\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        loops, dead = self.detector.detect(sm, CFFUnrollConfig())
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].iteration_count, 5)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.loops_fully_unrolled, 1)
        out = self.normalizer.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertEqual(out.count("Running Payload Pass"), 5)
        self.assertIn("Completed Five Iterations", out)
    # 3. Data-dependent While Loop Structured Reconstruction
    def test_data_dependent_while_loop_structured_reconstruction(self):
        code = (
            "set state=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_head\n"
            "if \"%state%\"==\"1\" goto :b_exit\n"
            "goto :dispatch\n"
            ":b_head\n"
            "echo Waiting for dynamic input\n"
            "if \"%user_input%\"==\"quit\" (set state=1) else (set state=0)\n"
            "goto :dispatch\n"
            ":b_exit\n"
            "echo Exited Loop Cleanly\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        loops, dead = self.detector.detect(sm, CFFUnrollConfig())
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].loop_type, CFFLoopType.STRUCTURED_WHILE)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.loops_reconstructed, 1)
        out = self.normalizer.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertIn(":loop_0", out)
        self.assertIn("Waiting for dynamic input", out)
        self.assertIn("goto :loop_0", out)
        self.assertIn(":loop_exit_0", out)
        self.assertIn("Exited Loop Cleanly", out)
        self.assertNotIn("goto :dispatch", out)
    # 4. Multi-State Cycles & Nested Loops
    def test_multi_state_cycle_detection(self):
        code = (
            "set state=A\n"
            ":dispatch\n"
            "if \"%state%\"==\"A\" goto :node_a\n"
            "if \"%state%\"==\"B\" goto :node_b\n"
            "if \"%state%\"==\"C\" goto :node_c\n"
            "if \"%state%\"==\"exit\" goto :node_end\n"
            "goto :dispatch\n"
            ":node_a\n"
            "echo In Node A\n"
            "set state=B\n"
            "goto :dispatch\n"
            ":node_b\n"
            "echo In Node B\n"
            "set state=C\n"
            "goto :dispatch\n"
            ":node_c\n"
            "echo In Node C\n"
            "if \"%input%\"==\"stop\" (set state=exit) else (set state=A)\n"
            "goto :dispatch\n"
            ":node_end\n"
            "echo Done\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        loops, dead = self.detector.detect(sm, CFFUnrollConfig())
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].header_state, "A")
        self.assertEqual(loops[0].body_states, {"A", "B", "C"})
        self.assertIn("C", loops[0].latch_states)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.loops_reconstructed, 1)
    # 5. Conditional Branching Inside Loop Body
    def test_conditional_branching_within_cff(self):
        code = (
            "set state=chk\n"
            ":dispatch\n"
            "if \"%state%\"==\"chk\" goto :b_chk\n"
            "if \"%state%\"==\"t_act\" goto :b_then\n"
            "if \"%state%\"==\"e_act\" goto :b_else\n"
            "goto :dispatch\n"
            ":b_chk\n"
            "if /i \"%perm%\" equ \"admin\" (set state=t_act) else (set state=e_act)\n"
            "goto :dispatch\n"
            ":b_then\n"
            "echo Admin Mode Activated\n"
            "exit\n"
            ":b_else\n"
            "echo User Mode Limited\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.conditional_branches_recovered, 1)
        out = self.normalizer.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertIn("Admin Mode Activated", out)
        self.assertIn("User Mode Limited", out)
    # 6. Dead State Pruning
    def test_dead_state_pruning(self):
        code = (
            "set state=start\n"
            ":dispatch\n"
            "if \"%state%\"==\"start\" goto :b_start\n"
            "if \"%state%\"==\"end\" goto :b_end\n"
            "if \"%state%\"==\"dead_1\" goto :b_dead1\n"
            "if \"%state%\"==\"dead_2\" goto :b_dead2\n"
            "goto :dispatch\n"
            ":b_start\n"
            "echo Start Job\n"
            "set state=end\n"
            "goto :dispatch\n"
            ":b_end\n"
            "echo End Job\n"
            "exit\n"
            ":b_dead1\n"
            "echo Dead 1\n"
            "goto :dispatch\n"
            ":b_dead2\n"
            "echo Dead 2\n"
            "goto :dispatch\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        cfg = CFFUnrollConfig(prune_dead_states=True)
        loops, dead = self.detector.detect(sm, cfg)
        self.assertIn("dead_1", dead)
        self.assertIn("dead_2", dead)
        self.assertEqual(len(dead), 2)
        res = self.linearizer.linearize(sm, config=cfg)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.dead_states_pruned, 2)
        self.assertNotIn("dead_1", sm.blocks)
        self.assertNotIn("dead_2", sm.blocks)
    # 7. Fallthrough State Updates
    def test_fallthrough_state_update_detection(self):
        code = (
            "set state=chk\n"
            ":dispatch\n"
            "if \"%state%\"==\"chk\" goto :b_chk\n"
            "if \"%state%\"==\"target_a\" goto :b_a\n"
            "if \"%state%\"==\"target_b\" goto :b_b\n"
            "goto :dispatch\n"
            ":b_chk\n"
            "if \"%flag%\"==\"1\" set state=target_a\n"
            "set state=target_b\n"
            "goto :dispatch\n"
            ":b_a\n"
            "echo Target A\n"
            "exit\n"
            ":b_b\n"
            "echo Target B\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        chk_block = sm.blocks["chk"]
        self.assertEqual(len(chk_block.conditional_transitions), 2)
        self.assertEqual(chk_block.conditional_transitions[0][1], "target_a")
        self.assertEqual(chk_block.conditional_transitions[1][1], "target_b")
        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.conditional_branches_recovered, 1)
    # 8. DoS and Max Unroll Limit Enforcement
    def test_dos_max_unroll_limit_enforcement(self):
        code = (
            "set state=0\n"
            "set i=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_loop\n"
            "goto :dispatch\n"
            ":b_loop\n"
            "echo Endless Loop\n"
            "set /a i+=1\n"
            "set state=0\n"
            "goto :dispatch\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)
        cfg = CFFUnrollConfig(max_unroll_iterations=5, max_unroll_steps=20)
        loops, dead = self.detector.detect(sm, cfg)
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].loop_type, CFFLoopType.STRUCTURED_WHILE)
        res = self.linearizer.linearize(sm, config=cfg)
        self.assertTrue(res.success)
        self.assertLessEqual(res.metrics.states_unrolled, 25)
    # 9. Memory Zeroization & Telemetry Integrity
    def test_models_zeroization(self):
        loop = CFFLoopInfo(
            header_state="0", latch_states={"0"}, body_states={"0"},
            exit_states={"0"}, back_edges=[("0", "0")],
            loop_type=CFFLoopType.DETERMINISTIC_UNROLLED, iteration_count=5,
            exit_conditions=["cond1"], continue_conditions=["cond2"]
        )
        self.assertEqual(loop.to_dict()["iteration_count"], 5)
        loop.zeroize()
        self.assertEqual(loop.header_state, "")
        self.assertEqual(len(loop.latch_states), 0)
        self.assertIsNone(loop.iteration_count)
        cfg = CFFUnrollConfig(max_unroll_iterations=100, max_unroll_steps=999)
        self.assertEqual(cfg.to_dict()["max_unroll_iterations"], 100)
        cfg.zeroize()
        self.assertEqual(cfg.max_unroll_iterations, 0)
        self.assertFalse(cfg.detect_loops)
        metrics = DeflatMetrics(
            dispatchers_detected=2, states_unrolled=10, blocks_linearized=8,
            dead_jumps_pruned=6, conditional_branches_recovered=3,
            loops_reconstructed=1, loops_detected=4, loops_fully_unrolled=2,
            dead_states_pruned=5
        )
        self.assertEqual(metrics.to_dict()["loops_fully_unrolled"], 2)
        metrics.zeroize()
        self.assertEqual(metrics.loops_fully_unrolled, 0)
        self.assertEqual(metrics.dead_states_pruned, 0)
        res = DeflatResult(success=True, loops=[loop], metrics=metrics)
        res.zeroize()
        self.assertEqual(len(res.loops), 0)
        self.assertIsNone(res.state_machine)
        # Zeroize detector and unroller
        self.detector.zeroize()
        self.unroller.zeroize()
        self.linearizer.zeroize()
        self.decompiler.zeroize()
    # 10. CLI Integration Flags
    def test_cli_integration_cff_flags(self):
        from src.cli import main
        code = (
            "@echo off\n"
            "set state=0\n"
            "set i=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_loop\n"
            "if \"%state%\"==\"1\" goto :b_exit\n"
            "goto :dispatch\n"
            ":b_loop\n"
            "echo CLI Loop Item\n"
            "set /a i+=1\n"
            "if %i% equ 3 (set state=1) else (set state=0)\n"
            "goto :dispatch\n"
            ":b_exit\n"
            "echo CLI Loop Exit\n"
            "exit /b 0\n"
        )
        test_args = ["cmd-ast-deobfuscator", "-c", code, "--cff-unroll", "--cff-report"]
        buf = io.StringIO()
        with patch.object(sys, "argv", test_args):
            with patch("sys.stdout", buf):
                main()
        out = buf.getvalue()
        self.assertIn("CLI Loop Item", out)
        self.assertIn("CONTROL FLOW DE-FLATTENING & CFF REPORT", out)
        self.assertIn("loops_fully_unrolled", out)
if __name__ == "__main__":
    unittest.main()
