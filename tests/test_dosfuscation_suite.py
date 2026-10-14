#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Unit & Integration Test Suite for Invoke-DOSfuscation Concatenation Engine
Validates:
1. Garbage / empty variable interleaving elimination
2. Scrambled delimiter normalization outside quotes & variable slices
3. Fine-grained variable fragment chaining
4. FOR token accumulator loop folding
5. CALL execution trampoline unwrapping
6. Heuristic detection & scoring
7. AST DosfuscationPass integration
8. Memory zeroization and security bounds
9. CLI flag verification
"""

import unittest
from typing import Dict, List

from src.ast_nodes import (
    CommandNode, AssignmentNode, LiteralNode, VarExpandNode,
    ForNode, CallNode, ScriptNode, ChainNode
)
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.transforms.base import PassManager
from src.transforms.dosfuscation_pass import DosfuscationPass
from src.dosfuscation.models import (
    ConcatenationType, ConcatenationPattern, DosfuscationMetrics, DosfuscationResult
)
from src.dosfuscation.concatenation import DosfuscationConcatenationDecoder
from src.dosfuscation.detector import DosfuscationDetector
from src.deobfuscator_engine import BatchDeobfuscator
from src.cli import main as cli_main


class TestDosfuscationConcatenationDecoder(unittest.TestCase):
    """Unit tests for DosfuscationConcatenationDecoder heuristic methods."""

    def setUp(self):
        self.decoder = DosfuscationConcatenationDecoder()

    def test_junk_variable_interleaving_empty_slice(self):
        text = "%PUBLIC:~0,0%c%PUBLIC:~0,0%m%PUBLIC:~0,0%d"
        clean, count = self.decoder.strip_junk_variables(text)
        self.assertEqual(clean, "cmd")
        self.assertEqual(count, 3)

    def test_junk_variable_interleaving_defined_empty(self):
        env = {"dummy": "", "noise": ""}
        text = "%dummy%w%dummy%h%noise%o%dummy%a%noise%m%dummy%i"
        clean, count = self.decoder.strip_junk_variables(text, local_env=env)
        self.assertEqual(clean, "whoami")
        self.assertEqual(count, 6)

    def test_delimiter_scrambling_basic(self):
        text = "cmd,;,/c,;,whoami"
        clean, count = self.decoder.normalize_delimiters(text)
        self.assertEqual(clean.strip(), "cmd /c whoami")
        self.assertGreaterEqual(count, 1)

    def test_delimiter_scrambling_preserves_quoted_commas(self):
        text = 'cmd,;,/c,;,"C:\\Users,Admin;Folder\\script.bat"'
        clean, count = self.decoder.normalize_delimiters(text)
        self.assertIn('"C:\\Users,Admin;Folder\\script.bat"', clean)
        self.assertTrue(clean.startswith("cmd /c"))

    def test_delimiter_scrambling_preserves_slice_commas(self):
        text = "%COMSPEC:~-7,3% /c dir"
        clean, count = self.decoder.normalize_delimiters(text)
        self.assertIn("%COMSPEC:~-7,3%", clean)

    def test_delimiter_scrambling_leading_and_trailing(self):
        text = ",;;cmd.exe,,/c,,whoami;;"
        clean, count = self.decoder.normalize_delimiters(text)
        self.assertEqual(clean.strip(), "cmd.exe /c whoami")

    def test_variable_fragment_chaining(self):
        env = {"a": "p", "b": "o", "c": "w", "d": "ershell"}
        text = "%a%%b%%c%%d% -NoProfile"
        fused, count = self.decoder.fuse_variable_chains(text, local_env=env)
        self.assertEqual(fused, "powershell -NoProfile")
        self.assertEqual(count, 4)

    def test_nested_variable_chaining(self):
        env = {"v1": "cm", "v2": "d", "full": "%v1%%v2%"}
        text = "%full% /c dir"
        fused, count = self.decoder.fuse_variable_chains(text, local_env=env)
        self.assertEqual(fused, "cmd /c dir")

    def test_for_token_accumulation_loop_append(self):
        env = {"out": ""}
        script = "for %x in (c a l c) do set out=!out!%x"
        resolved, count = self.decoder.resolve_token_accumulation_loops(script, local_env=env)
        self.assertEqual(resolved, 'set "out=calc"')
        self.assertEqual(count, 1)
        self.assertEqual(env["out"], "calc")

    def test_for_token_accumulation_loop_commas(self):
        env = {"out": ""}
        script = "for %x in (p,o,w,e,r,s,h,e,l,l) do set out=%out%%x"
        resolved, count = self.decoder.resolve_token_accumulation_loops(script, local_env=env)
        self.assertEqual(resolved, 'set "out=powershell"')
        self.assertEqual(count, 1)
        self.assertEqual(env["out"], "powershell")

    def test_for_token_accumulation_loop_prepend(self):
        env = {"out": "world"}
        script = "for %x in (hello_) do set out=%x!out!"
        resolved, count = self.decoder.resolve_token_accumulation_loops(script, local_env=env)
        self.assertEqual(resolved, 'set "out=hello_world"')
        self.assertEqual(count, 1)
        self.assertEqual(env["out"], "hello_world")

    def test_call_trampoline_unrolling_powershell(self):
        env = {"c": "powershell.exe"}
        text = "call %c% -NoProfile -Command dir"
        unrolled, count = self.decoder.unroll_call_trampolines(text, local_env=env)
        self.assertEqual(unrolled.strip(), "powershell.exe -NoProfile -Command dir")
        self.assertEqual(count, 1)

    def test_call_trampoline_preserves_subroutine_label(self):
        env = {"c": "my_subroutine"}
        text = "call :my_subroutine arg1 arg2"
        unrolled, count = self.decoder.unroll_call_trampolines(text, local_env=env)
        self.assertEqual(unrolled.strip(), "call :my_subroutine arg1 arg2")
        self.assertEqual(count, 0)

    def test_extract_symbol_definitions_compound_line(self):
        env = {}
        line = "set a=c&& set b=m&& set c=d"
        self.decoder.extract_symbol_definitions(line, local_env=env)
        self.assertEqual(env.get("a"), "c")
        self.assertEqual(env.get("b"), "m")
        self.assertEqual(env.get("c"), "d")

    def test_decode_full_staged_concatenation(self):
        script = (
            'set p1=po\n'
            'set p2=wer\n'
            'set p3=shell\n'
            '%p1%%p2%%p3% -NoProfile -Command "Write-Host OK"'
        )
        res = self.decoder.decode(script)
        self.assertIn('powershell -NoProfile -Command "Write-Host OK"', res.decoded_text)
        self.assertGreater(res.metrics.var_chains_fused, 0)
        self.assertGreater(res.concatenation_score, 0.0)


class TestDosfuscationDetector(unittest.TestCase):
    """Unit tests for DosfuscationDetector heuristic evaluation."""

    def setUp(self):
        self.detector = DosfuscationDetector()

    def test_plain_script_not_dosfuscated(self):
        script = "@echo off\necho Hello World\ndir /b\npause"
        analysis = self.detector.analyze_script(script)
        self.assertFalse(analysis["is_dosfuscated"])
        self.assertLess(analysis["dosfuscation_score"], 0.20)

    def test_dosfuscated_script_detection(self):
        script = (
            "set a1=p& set a2=o& set a3=w& set a4=ershell\n"
            "call %a1%%a2%%a3%%a4%,;,/c,;,-NoProfile"
        )
        analysis = self.detector.analyze_script(script)
        self.assertTrue(analysis["is_dosfuscated"])
        self.assertGreaterEqual(len(analysis["detected_levels"]), 1)
        self.assertGreater(analysis["dosfuscation_score"], 0.30)

    def test_entropy_computation(self):
        e1 = self.detector.calculate_entropy("aaaaaa")
        e2 = self.detector.calculate_entropy("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*")
        self.assertEqual(e1, 0.0)
        self.assertGreater(e2, 4.0)


class TestDosfuscationPass(unittest.TestCase):
    """Integration tests for AST-level DosfuscationPass."""

    def test_ast_command_node_target_normalization(self):
        env = {"x": "calc", "y": ".exe"}
        cmd = CommandNode(target="%x%%y%", arguments=[])
        dosf_pass = DosfuscationPass(env=env)
        norm_node = dosf_pass.transform(cmd)
        self.assertIsInstance(norm_node, CommandNode)
        self.assertEqual(norm_node.target, "calc.exe")

    def test_ast_chain_node_propagation(self):
        script = 'set a=who& set b=ami& %a%%b% /all'
        parser = CmdASTParser.from_source(script)
        ast = parser.parse()

        dosf_pass = DosfuscationPass()
        opt_ast = dosf_pass.transform(ast)

        normalizer = ASTNormalizer()
        res = normalizer.to_source(opt_ast)
        self.assertIn("whoami /all", res)

    def test_ast_for_loop_accumulator_folded(self):
        script = 'for %i in (c a l c) do set out=!out!%i'
        parser = CmdASTParser.from_source(script)
        ast = parser.parse()

        dosf_pass = DosfuscationPass()
        opt_ast = dosf_pass.transform(ast)

        # Body was folded into AssignmentNode
        normalizer = ASTNormalizer()
        res = normalizer.to_source(opt_ast)
        self.assertIn("calc", res)

    def test_pipeline_integration(self):
        script = (
            'set a=c&& set b=m&& set c=d\n'
            '%a%%b%%c%,;,/c,;,dir'
        )
        parser = CmdASTParser.from_source(script)
        ast = parser.parse()

        pm = PassManager.default_pipeline()
        clean_ast = pm.run(ast)

        normalizer = ASTNormalizer()
        res = normalizer.to_source(clean_ast)
        self.assertIn("cmd /c dir", res)


class TestDosfuscationSecurityAndZeroize(unittest.TestCase):
    """Security audit checks: memory wiping, zeroize, and boundary defense."""

    def test_zeroize_metrics(self):
        metrics = DosfuscationMetrics(
            total_patterns_detected=10,
            var_chains_fused=5,
            junk_vars_stripped=4,
            delimiters_normalized=3,
            bytes_before=100,
            bytes_after=50
        )
        metrics.zeroize()
        self.assertTrue(metrics.is_zeroized)
        self.assertEqual(metrics.total_patterns_detected, 0)
        self.assertEqual(metrics.var_chains_fused, 0)
        self.assertEqual(metrics.bytes_before, 0)

    def test_zeroize_pattern(self):
        pat = ConcatenationPattern(
            pattern_type=ConcatenationType.VAR_FRAGMENT_CHAIN,
            confidence=0.9,
            raw_snippet="%secret%",
            normalized_snippet="clean"
        )
        pat.zeroize()
        self.assertEqual(pat.raw_snippet, "\x00" * 8)
        self.assertEqual(pat.normalized_snippet, "\x00" * 5)

    def test_zeroize_result(self):
        res = DosfuscationResult(
            original_text="secret_payload",
            decoded_text="deobfuscated_payload",
            patterns=[ConcatenationPattern(ConcatenationType.JUNK_VAR_INTERLEAVE, 0.9, "raw", "clean")],
            metrics=DosfuscationMetrics()
        )
        res.zeroize()
        self.assertTrue(all(c == "\x00" for c in res.original_text))
        self.assertTrue(all(c == "\x00" for c in res.decoded_text))
        self.assertEqual(len(res.patterns), 0)
        self.assertTrue(res.metrics.is_zeroized)


class TestCLIIntegration(unittest.TestCase):
    """Test CLI execution with --dosfuscation and --dosf-stats flags."""

    def test_cli_dosfuscation_inline(self):
        import sys
        from io import StringIO

        saved_stdout = sys.stdout
        saved_argv = sys.argv
        try:
            sys.stdout = StringIO()
            sys.argv = [
                "cli.py",
                "-c", "set a=c&& set b=m&& set c=d&& %a%%b%%c%,;,/c,;,dir",
                "--dosfuscation",
                "--dosf-stats"
            ]
            cli_main()
            output = sys.stdout.getvalue()
            self.assertIn("cmd /c dir", output)
            self.assertIn("INVOKE-DOSFUSCATION CONCATENATION STATS", output)
            self.assertIn("Variable chains fused", output)
        finally:
            sys.stdout = saved_stdout
            sys.argv = saved_argv


if __name__ == "__main__":
    unittest.main()
