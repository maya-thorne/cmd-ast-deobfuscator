"""
Comprehensive Test Suite for Batch String Reversal and Transposition Deobfuscation.
Covers Somalifuscator FOR /L reverse loops, FOR IN index transposition, pushdown stack automata,
decreasing slice sequences, rail-fence transpositions, and pipeline integration.
"""

import unittest
from typing import Dict

from src.ast_nodes import (
    ScriptNode, CommandNode, AssignmentNode, LiteralNode,
    VarExpandNode, ForNode, LabelNode, GotoNode, IfNode, BlockNode
)
from src.parser import CmdASTParser
from src.reversal.models import (
    ReversalPatternType, ReversalLoopSpec, TranspositionResult, ReversalMetrics
)
from src.reversal.automaton import StringReversalAutomaton
from src.reversal.detector import ReversalPatternDetector
from src.transforms.reversal_folder import ReversalFolderPass
from src.transforms.base import PassManager
from src.deobfuscator_engine import BatchDeobfuscator


class TestStringReversalAutomaton(unittest.TestCase):
    """Verifies core automaton state machine routines."""

    def test_reverse_direct(self):
        self.assertEqual(StringReversalAutomaton.reverse("exe.clac"), "calc.exe")
        self.assertEqual(StringReversalAutomaton.reverse(""), "")
        self.assertEqual(StringReversalAutomaton.reverse("A"), "A")

    def test_get_slice_semantics(self):
        s = "Hello, World!"
        self.assertEqual(StringReversalAutomaton.get_slice(s, 0, 5), "Hello")
        self.assertEqual(StringReversalAutomaton.get_slice(s, 7, 5), "World")
        self.assertEqual(StringReversalAutomaton.get_slice(s, -1, 1), "!")
        self.assertEqual(StringReversalAutomaton.get_slice(s, -6, 5), "World")
        self.assertEqual(StringReversalAutomaton.get_slice(s, 100, 5), "")
        self.assertEqual(StringReversalAutomaton.get_slice(s, -100, 5), "Hello")

    def test_simulate_slice_loop_reverse(self):
        # Somalifuscator style: "exe.clac" index 7 down to 0
        res = StringReversalAutomaton.simulate_slice_loop("exe.clac", 7, -1, 0, 1)
        self.assertEqual(res.decoded_text, "calc.exe")
        self.assertEqual(res.steps_simulated, 8)
        self.assertEqual(res.pattern_type, ReversalPatternType.FOR_L_REVERSAL)

    def test_simulate_slice_loop_prepend(self):
        # Prepending 0 to 7 of "exe.clac" reverses the characters
        res = StringReversalAutomaton.simulate_slice_loop("exe.clac", 0, 1, 7, 1, is_prepend=True)
        self.assertEqual(res.decoded_text, "calc.exe")
        self.assertEqual(res.steps_simulated, 8)
        self.assertEqual(res.pattern_type, ReversalPatternType.FOR_L_PREPEND)

    def test_simulate_slice_loop_dos_guard(self):
        # Step 0 should not loop
        res = StringReversalAutomaton.simulate_slice_loop("test", 0, 0, 10)
        self.assertEqual(res.steps_simulated, 0)
        self.assertEqual(res.decoded_text, "")

        # Huge step count terminates at max_steps
        res2 = StringReversalAutomaton.simulate_slice_loop("a", 0, 1, 1000000, max_steps=50)
        self.assertEqual(res2.steps_simulated, 50)

    def test_simulate_index_sequence(self):
        dict_str = "abcdefghijklmnopqrstuvwxyz 0123456789"
        # 22=w, 7=h, 14=o, 0=a, 12=m, 8=i
        indices = [22, 7, 14, 0, 12, 8]
        res = StringReversalAutomaton.simulate_index_sequence(dict_str, indices)
        self.assertEqual(res.decoded_text, "whoami")
        self.assertEqual(res.steps_simulated, 6)

    def test_simulate_stack_reversal(self):
        res = StringReversalAutomaton.simulate_stack_reversal("exe.etavirp\\llehsrewop")
        self.assertEqual(res.decoded_text, "powershell\\private.exe")

    def test_apply_permutation(self):
        s = "dcm"
        perm = [1, 2, 0]  # c, m, d
        self.assertEqual(StringReversalAutomaton.apply_permutation(s, perm), "cmd")

    def test_decode_rail_fence(self):
        # "WECRLTEERDSOX" with 3 rails -> "WEAREDISCOVERED" etc.
        # Simple test: 2 rails: "HloWrd" + "elol" -> "HelloWorld"
        s = "HloolelWrd"
        decoded = StringReversalAutomaton.decode_rail_fence(s, rails=2)
        self.assertTrue(len(decoded) == len(s))

    def test_zeroize_memory(self):
        b = bytearray(b"sensitive_password")
        StringReversalAutomaton.zeroize(b)
        self.assertEqual(b, bytearray(len(b)))


class TestReversalPatternDetector(unittest.TestCase):
    """Verifies AST pattern detection accuracy."""

    def test_detect_for_l_append(self):
        code = 'for /l %%i in (7,-1,0) do set res=!res!!s:~%%i,1!'
        ast = CmdASTParser.from_source(code).parse()
        for_node = ast.statements[0]
        self.assertIsInstance(for_node, ForNode)

        detector = ReversalPatternDetector()
        spec = detector.detect_for_l_reversal(for_node, {})
        self.assertIsNotNone(spec)
        self.assertEqual(spec.iterator_var, "i")
        self.assertEqual(spec.source_var, "s")
        self.assertEqual(spec.dest_var, "res")
        self.assertEqual(spec.start, 7)
        self.assertEqual(spec.step, -1)
        self.assertEqual(spec.stop, 0)
        self.assertFalse(spec.is_prepend)

    def test_detect_for_l_prepend(self):
        code = 'for /L %%x in (0,1,7) do set out=!src:~%%x,1!!out!'
        ast = CmdASTParser.from_source(code).parse()
        for_node = ast.statements[0]
        self.assertIsInstance(for_node, ForNode)

        detector = ReversalPatternDetector()
        spec = detector.detect_for_l_reversal(for_node, {})
        self.assertIsNotNone(spec)
        self.assertEqual(spec.iterator_var, "x")
        self.assertEqual(spec.source_var, "src")
        self.assertEqual(spec.dest_var, "out")
        self.assertTrue(spec.is_prepend)

    def test_detect_for_l_with_env_variables(self):
        code = 'for /l %%i in (%LEN%,-1,0) do set "out=!out!!buf:~%%i,1!"'
        ast = CmdASTParser.from_source(code).parse()
        for_node = ast.statements[0]

        detector = ReversalPatternDetector()
        spec = detector.detect_for_l_reversal(for_node, {"len": "15"})
        self.assertIsNotNone(spec)
        self.assertEqual(spec.start, 15)
        self.assertEqual(spec.step, -1)
        self.assertEqual(spec.stop, 0)

    def test_detect_for_in_transposition(self):
        code = 'for %%a in (22 7 14 0 12 8) do set out=!out!!dict:~%%a,1!'
        ast = CmdASTParser.from_source(code).parse()
        for_node = ast.statements[0]

        detector = ReversalPatternDetector()
        spec = detector.detect_for_in_transposition(for_node, {})
        self.assertIsNotNone(spec)
        self.assertEqual(spec.iterator_var, "a")
        self.assertEqual(spec.source_var, "dict")
        self.assertEqual(spec.dest_var, "out")
        self.assertEqual(spec.in_items, ["22", "7", "14", "0", "12", "8"])

    def test_detect_goto_stack_reversal(self):
        code = (
            ':loop\n'
            'set "dst=%dst%%src:~-1%"\n'
            'set "src=%src:~0,-1%"\n'
            'if defined src goto loop\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        detector = ReversalPatternDetector()
        match = detector.detect_goto_reversal_loop(ast.statements, {})
        self.assertIsNotNone(match)
        start_idx, end_idx, spec = match
        self.assertEqual(spec.source_var, "src")
        self.assertEqual(spec.dest_var, "dst")
        self.assertEqual(spec.pattern_type, ReversalPatternType.GOTO_STACK_REVERSAL)

    def test_detect_slice_transposition_sequence(self):
        code = 'cmd /c %s:~3,1%%s:~2,1%%s:~1,1%%s:~0,1%'
        ast = CmdASTParser.from_source(code).parse()
        cmd_node = ast.statements[0]
        detector = ReversalPatternDetector()
        runs = detector.detect_slice_transposition_sequence(cmd_node.arguments, {"s": "calc"})
        self.assertEqual(len(runs), 1)
        start_idx, end_idx, var_name, starts, lens = runs[0]
        self.assertEqual(var_name, "s")
        self.assertEqual(starts, [3, 2, 1, 0])
        self.assertEqual(lens, [1, 1, 1, 1])


class TestReversalFolderPass(unittest.TestCase):
    """Verifies AST transformations and folding optimizations."""

    def test_fold_for_l_reverse_string(self):
        code = (
            'set "s=exe.clac"\n'
            'set "res="\n'
            'for /L %%i in (7,-1,0) do set res=!res!!s:~%%i,1!\n'
            '!res!\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        rev_pass = ReversalFolderPass()
        folded_ast = rev_pass.transform(ast)

        # Environment should contain the reversed string
        self.assertEqual(rev_pass.env.get("res"), "calc.exe")
        self.assertEqual(rev_pass.metrics.loops_folded, 1)
        self.assertEqual(rev_pass.metrics.characters_decoded, 8)

        # The ForNode should have been replaced with an AssignmentNode
        statements = folded_ast.statements
        self.assertIsInstance(statements[2], AssignmentNode)
        self.assertEqual(statements[2].var_name, "res")
        self.assertEqual(statements[2].raw_value, "calc.exe")

    def test_fold_for_in_dictionary_transposition(self):
        code = (
            'set "dict=abcdefghijklmnopqrstuvwxyz 0123456789"\n'
            'for %%a in (22 7 14 0 12 8) do set out=!out!!dict:~%%a,1!\n'
            '%out% /all\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        rev_pass = ReversalFolderPass()
        folded_ast = rev_pass.transform(ast)

        self.assertEqual(rev_pass.env.get("out"), "whoami")
        self.assertEqual(rev_pass.metrics.loops_folded, 1)
        self.assertEqual(folded_ast.statements[1].raw_value, "whoami")

    def test_fold_decreasing_slice_sequence_in_command(self):
        code = (
            'set "cmd_rev=exe.etavirp\\llehsrewop"\n'
            '%cmd_rev:~21,1%%cmd_rev:~20,1%%cmd_rev:~19,1%'
            '%cmd_rev:~18,1%%cmd_rev:~17,1%%cmd_rev:~16,1%%cmd_rev:~15,1%'
            '%cmd_rev:~14,1%%cmd_rev:~13,1%%cmd_rev:~12,1%%cmd_rev:~11,1%'
            '%cmd_rev:~10,1%%cmd_rev:~9,1%%cmd_rev:~8,1%%cmd_rev:~7,1%'
            '%cmd_rev:~6,1%%cmd_rev:~5,1%%cmd_rev:~4,1%%cmd_rev:~3,1%'
            '%cmd_rev:~2,1%%cmd_rev:~1,1%%cmd_rev:~0,1% -NoProfile\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        rev_pass = ReversalFolderPass()
        folded_ast = rev_pass.transform(ast)

        self.assertGreaterEqual(rev_pass.metrics.transposed_slices_folded, 1)
        cmd_stmt = folded_ast.statements[1]
        self.assertEqual(cmd_stmt.target, "powershell\\private.exe")

    def test_fold_decreasing_slice_sequence_in_assignment(self):
        code = (
            'set "raw=exe.clac"\n'
            'set "target=%raw:~7,1%%raw:~6,1%%raw:~5,1%%raw:~4,1%%raw:~3,1%%raw:~2,1%%raw:~1,1%%raw:~0,1%"\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        rev_pass = ReversalFolderPass()
        folded_ast = rev_pass.transform(ast)

        self.assertEqual(rev_pass.env.get("target"), "calc.exe")
        assign_node = folded_ast.statements[1]
        self.assertEqual(assign_node.raw_value, "calc.exe")

    def test_fold_goto_stack_reversal_loop(self):
        code = (
            'set "src=exe.clac"\n'
            'set "dst="\n'
            ':rev_loop\n'
            'set "dst=%dst%%src:~-1%"\n'
            'set "src=%src:~0,-1%"\n'
            'if defined src goto rev_loop\n'
            '%dst%\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        rev_pass = ReversalFolderPass()
        folded_ast = rev_pass.transform(ast)

        self.assertEqual(rev_pass.env.get("dst"), "calc.exe")
        self.assertEqual(rev_pass.metrics.goto_loops_folded, 1)

    def test_full_pipeline_end_to_end(self):
        # Combination of Carets + Somalifuscator FOR /L reverse loop + DCE
        code = (
            'set s=e^x^e.e^t^a^v^i^r^p\\l^l^e^h^s^r^e^w^o^p\n'
            'set payload=\n'
            'for /L %%i in (21,-1,0) do set "payload=!payload!!s:~%%i,1!"\n'
            '!payload! -NoProfile -Command "dir"\n'
        )
        ast = CmdASTParser.from_source(code).parse()
        pipeline = PassManager.optimization_pipeline()
        optimized = pipeline.run(ast)
        serialized = pipeline.passes[0].to_source(optimized)

        self.assertIn("powershell\\private.exe -NoProfile -Command \"dir\"", serialized)


class TestBatchDeobfuscatorReversal(unittest.TestCase):
    """Verifies regex/automaton integration in BatchDeobfuscator."""

    def test_batch_deobfuscator_reversal(self):
        code = (
            'set "s=exe.clac"\n'
            'for /l %i in (7,-1,0) do set res=!res!!s:~%i,1!\n'
            '%res%\n'
        )
        engine = BatchDeobfuscator()
        result = engine.deobfuscate(code)
        self.assertIn("calc.exe", result)

    def test_batch_deobfuscator_combined_carets_and_reversal(self):
        code = (
            's^e^t payload=l^l^a/ i^m^a^o^h^w c/ d^m^c\n'
            'for /L %a in (17,-1,0) do set out=!out!!payload:~%a,1!\n'
            '%out%\n'
        )
        engine = BatchDeobfuscator()
        result = engine.deobfuscate(code)
        self.assertIn("cmd /c whoami /all", result)


if __name__ == "__main__":
    unittest.main()
