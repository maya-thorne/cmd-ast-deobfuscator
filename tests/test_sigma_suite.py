"""
Comprehensive Test Suite for Enterprise SIEM & Sigma Obfuscation Primitive Detector (M23).
"""

import io
import json
import os
import sys
import tempfile
import unittest

from src.ast_nodes import CommandNode, LiteralNode, ScriptNode, VarExpandNode
from src.parser import CmdASTParser
from src.sigma import (
    ObfuscationPrimitive,
    ObfuscationPrimitiveDetector,
    ObfuscationPrimitiveType,
    ObfuscationScore,
    PrimitiveSeverity,
    SIEMTarget,
    SIEMTranspiler,
    SigmaAnalysisResult,
    SigmaRule,
    SigmaRuleGenerator,
    SigmaTransformPass,
    analyze_sigma_primitives,
)


class TestSigmaModelsAndZeroize(unittest.TestCase):
    """Verifies data model serialization, scoring math, and memory zeroization."""

    def test_primitive_serialization_and_zeroize(self):
        p = ObfuscationPrimitive(
            primitive_type=ObfuscationPrimitiveType.CARET_INSERTION,
            severity=PrimitiveSeverity.HIGH,
            confidence=0.95,
            description="Caret escape inside token",
            line_number=3,
            matched_token="c^m^d",
            ast_node_type="LiteralNode",
            weight=3.0,
            metadata={"source": "test"},
        )
        d = p.to_dict()
        self.assertEqual(d["primitive_type"], "caret_insertion")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["confidence"], 0.95)
        self.assertEqual(d["line_number"], 3)
        self.assertEqual(d["matched_token"], "c^m^d")

        p.zeroize()
        self.assertEqual(p.confidence, 0.0)
        self.assertEqual(len(p.metadata), 0)
        self.assertTrue(all(c == "\x00" for c in p.matched_token))

    def test_score_calculation(self):
        # Empty primitives -> CLEAN (0.0)
        score_clean = ObfuscationScore.calculate([])
        self.assertEqual(score_clean.score, 0.0)
        self.assertEqual(score_clean.level, "CLEAN")

        # Few low severity primitives -> LOW_SUSPICION
        p_low = [
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.IO_STEALTH_REDIRECTION,
                severity=PrimitiveSeverity.LOW,
                confidence=0.8,
                description="test",
                line_number=1,
                matched_token=">nul",
                weight=1.0,
            )
        ]
        score_low = ObfuscationScore.calculate(p_low, entropy=3.0)
        self.assertLess(score_low.score, 35.0)

        # High severity obfuscation -> HIGHLY_OBFUSCATED or MALICIOUS
        p_heavy = [
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.CARET_INSERTION,
                severity=PrimitiveSeverity.HIGH,
                confidence=0.95,
                description="carets",
                line_number=1,
                matched_token="c^m^d",
                weight=3.0,
            ),
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.ENV_CONCATENATION,
                severity=PrimitiveSeverity.HIGH,
                confidence=0.95,
                description="concat",
                line_number=2,
                matched_token="%a%%b%%c%",
                weight=3.5,
            ),
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING,
                severity=PrimitiveSeverity.CRITICAL,
                confidence=0.99,
                description="encoded powershell",
                line_number=3,
                matched_token="powershell -enc AAAA",
                weight=5.0,
            ),
        ]
        score_heavy = ObfuscationScore.calculate(p_heavy, entropy=5.8)
        self.assertGreaterEqual(score_heavy.score, 65.0)
        self.assertIn(score_heavy.level, ("HIGHLY_OBFUSCATED", "MALICIOUS"))

    def test_sigma_rule_and_result_zeroize(self):
        rule = SigmaRule(
            title="Suspicious Command Line Obfuscation",
            description="Sensitive detection rule description",
            references=["https://example.com/ref"],
            tags=["attack.t1027"],
            detection={"selection": {"CommandLine|contains": ["test"]}},
        )
        self.assertIn("CommandLine|contains", rule.detection["selection"])
        rule.zeroize()
        self.assertEqual(len(rule.references), 0)
        self.assertEqual(len(rule.tags), 0)
        self.assertEqual(len(rule.detection), 0)

        res = SigmaAnalysisResult(
            primitives=[
                ObfuscationPrimitive(
                    primitive_type=ObfuscationPrimitiveType.CARET_INSERTION,
                    severity=PrimitiveSeverity.HIGH,
                    confidence=0.9,
                    description="desc",
                    line_number=1,
                    matched_token="tok",
                )
            ],
            score=ObfuscationScore(50.0, "MODERATELY_OBFUSCATED"),
            rules=[rule],
            source_file="sample.bat",
        )
        res.zeroize()
        self.assertEqual(len(res.primitives), 0)
        self.assertEqual(len(res.rules), 0)
        self.assertIsNone(res.source_file)


class TestObfuscationPrimitiveDetector(unittest.TestCase):
    """Verifies precision detection of specific obfuscation primitives."""

    def setUp(self):
        self.detector = ObfuscationPrimitiveDetector(min_confidence=0.5)

    def test_detect_caret_insertion(self):
        script = "c^m^d^.^e^x^e /c whoami\n"
        res = self.detector.detect(source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.CARET_INSERTION, p_types)
        caret_p = [p for p in res.primitives if p.primitive_type == ObfuscationPrimitiveType.CARET_INSERTION][0]
        self.assertEqual(caret_p.severity, PrimitiveSeverity.HIGH)
        self.assertEqual(caret_p.mitre_attack.technique_id, "T1027.010")

    def test_detect_quote_interleaving(self):
        script = '"c"m"d" /c "w"h"o"a"m"i\n'
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.QUOTE_INTERLEAVING, p_types)

    def test_detect_substring_slicing(self):
        script = "set x=%COMSPEC:~0,1%\nset y=%PATH:~10,2%\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.SUBSTRING_SLICING, p_types)

    def test_detect_reverse_slicing(self):
        script = "set last=%VAR:~-1%\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.REVERSE_SLICING, p_types)

    def test_detect_env_concatenation(self):
        script = "set a=c\nset b=m\nset c=d\n%a%%b%%c% /c whoami\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.ENV_CONCATENATION, p_types)

    def test_detect_delimiter_scrambling(self):
        script = "cmd.exe,/,c,whoami\n"
        res = self.detector.detect(source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.DELIMITER_SCRAMBLING, p_types)

    def test_detect_arithmetic_encoding(self):
        script = "set /a val=97^5\nset /a a=1,b=2,c=3\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.ARITHMETIC_ENCODING, p_types)

    def test_detect_for_reversal_loop(self):
        script = "for /l %i in (10,-1,0) do @echo %i\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.STRING_REVERSAL, p_types)

    def test_detect_dynamic_call_trampoline(self):
        script = "call :%dispatch_label%\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.DYNAMIC_CALL_TRAMPOLINE, p_types)

    def test_detect_io_stealth_redirection(self):
        script = "whoami >nul 2>&1\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.IO_STEALTH_REDIRECTION, p_types)

    def test_detect_script_droppers(self):
        script = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=\n"
        ast = CmdASTParser.from_source(script).parse()
        res = self.detector.detect(ast_root=ast, source_text=script)
        p_types = [p.primitive_type for p in res.primitives]
        self.assertIn(ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING, p_types)
        stub_p = [p for p in res.primitives if p.primitive_type == ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING][0]
        self.assertEqual(stub_p.severity, PrimitiveSeverity.CRITICAL)

    def test_clean_script_baseline(self):
        clean_script = "@echo off\necho Hello World\npause\n"
        ast = CmdASTParser.from_source(clean_script).parse()
        res = self.detector.detect(ast_root=ast, source_text=clean_script)
        self.assertEqual(res.score.level, "CLEAN")
        self.assertLess(res.score.score, 15.0)


class TestSigmaRuleGeneratorAndTranspiler(unittest.TestCase):
    """Verifies Sigma v2.0 rule synthesis and multi-target SIEM transpilation."""

    def setUp(self):
        self.generator = SigmaRuleGenerator(author="Security Team")
        self.transpiler = SIEMTranspiler()

    def test_rule_generation_and_yaml(self):
        primitives = [
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.CARET_INSERTION,
                severity=PrimitiveSeverity.HIGH,
                confidence=0.95,
                description="Caret escape inside token",
                line_number=1,
                matched_token="c^m^d",
                weight=3.0,
            ),
            ObfuscationPrimitive(
                primitive_type=ObfuscationPrimitiveType.DELIMITER_SCRAMBLING,
                severity=PrimitiveSeverity.MEDIUM,
                confidence=0.85,
                description="Delimiters",
                line_number=2,
                matched_token="cmd.exe,/,c",
                weight=2.5,
            ),
        ]
        res = SigmaAnalysisResult(primitives=primitives, score=ObfuscationScore.calculate(primitives))
        rules = self.generator.generate_rules(res, custom_title="Custom Obfuscated Batch Rule")

        self.assertGreaterEqual(len(rules), 1)
        b_rule = rules[0]
        self.assertEqual(b_rule.title, "Custom Obfuscated Batch Rule")
        self.assertEqual(b_rule.author, "Security Team")
        self.assertEqual(b_rule.logsource["category"], "process_creation")

        yaml_text = b_rule.to_yaml()
        self.assertIn("Custom Obfuscated Batch Rule", yaml_text)
        self.assertIn("logsource:", yaml_text)
        self.assertIn("category: process_creation", yaml_text)
        self.assertIn("detection:", yaml_text)
        self.assertIn("selection_carets:", yaml_text)
        self.assertIn("selection_delimiters:", yaml_text)

    def test_transpile_splunk_spl(self):
        rule = SigmaRule(
            title="Splunk Test Rule",
            detection={
                "selection_carets": {"CommandLine|contains": ["^c^", "^m^"]},
                "condition": "selection_carets",
            },
        )
        spl = self.transpiler.transpile(rule, target=SIEMTarget.SPLUNK)
        self.assertIn("index=* sourcetype=WinEventLog:Security EventCode=4688", spl)
        self.assertIn('CommandLine="*^c^*"', spl)
        self.assertIn('CommandLine="*^m^*"', spl)

    def test_transpile_elastic_eql(self):
        rule = SigmaRule(
            title="Elastic Test Rule",
            detection={
                "selection": {"CommandLine|contains": ["-enc", "-EncodedCommand"]},
                "condition": "selection",
            },
        )
        eql = self.transpiler.transpile(rule, target=SIEMTarget.ELASTIC)
        self.assertIn("process where", eql)
        self.assertIn('process.command_line in ("-enc", "-EncodedCommand")', eql)

    def test_transpile_sentinel_kql(self):
        rule = SigmaRule(
            title="Sentinel Test Rule",
            detection={
                "selection": {"CommandLine|contains": ["c^m^d", "whoami"]},
                "condition": "selection",
            },
        )
        kql = self.transpiler.transpile(rule, target=SIEMTarget.SENTINEL)
        self.assertIn("DeviceProcessEvents", kql)
        self.assertIn('ProcessCommandLine has_any ("c^m^d", "whoami")', kql)

    def test_transpile_qradar_aql(self):
        rule = SigmaRule(
            title="QRadar Test Rule",
            detection={
                "selection": {"CommandLine|contains": ["c^m^d"]},
                "condition": "selection",
            },
        )
        aql = self.transpiler.transpile(rule, target=SIEMTarget.QRADAR)
        self.assertIn("SELECT UTF8(payload) AS RawPayload", aql)
        self.assertIn('"Process CommandLine" ILIKE \'%c^m^d%\'', aql)

    def test_transpile_json(self):
        rule = SigmaRule(
            title="JSON Test Rule",
            detection={"selection": {"CommandLine|contains": ["cmd"]}},
        )
        json_str = self.transpiler.transpile(rule, target=SIEMTarget.JSON)
        data = json.loads(json_str)
        self.assertEqual(data["title"], "JSON Test Rule")
        self.assertIn("CommandLine|contains", data["detection"]["selection"])


class TestSigmaTransformPassAndCLI(unittest.TestCase):
    """Verifies AST transform pass integration and CLI flag routing."""

    def test_sigma_transform_pass(self):
        script = "c^m^d /c whoami >nul 2>&1\n"
        ast = CmdASTParser.from_source(script).parse()
        pass_instance = SigmaTransformPass()
        ast_out = pass_instance.transform(ast)

        self.assertIsNotNone(pass_instance.analysis_result)
        self.assertGreater(len(pass_instance.analysis_result.primitives), 0)
        self.assertGreater(len(pass_instance.analysis_result.rules), 0)

    def test_analyze_sigma_primitives_helper(self):
        script = "%COMSPEC:~0,1% /c whoami\n"
        res = analyze_sigma_primitives(script)
        self.assertIsInstance(res, SigmaAnalysisResult)
        self.assertGreater(len(res.primitives), 0)
        self.assertIn("## Detected Obfuscation Primitives", res.to_markdown())

    def test_cli_flags_invocation(self):
        from src.cli import main
        # Run --sigma-detect and --sigma-score on an inline script
        test_args = [
            "cli.py",
            "-c",
            "c^m^d /c whoami >nul 2>&1",
            "--sigma-detect",
            "--sigma-score",
        ]
        old_argv = sys.argv
        sys.argv = test_args
        captured_out = io.StringIO()
        try:
            old_stdout = sys.stdout
            sys.stdout = captured_out
            main()
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv

        output = captured_out.getvalue()
        self.assertIn("=== [BATCH OBFUSCATION RISK SCORE] ===", output)
        self.assertIn("Detected Obfuscation Primitives", output)


if __name__ == "__main__":
    unittest.main()
