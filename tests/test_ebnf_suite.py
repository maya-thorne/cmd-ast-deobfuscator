"""
Unit and integration test suite for cmd.exe EBNF grammar models, conformance validator,
canonical test corpus, and CLI telemetry integration.
"""

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

from src.ebnf import (
    GrammarRuleType,
    GrammarRule,
    GrammarSpecification,
    ValidationStatus,
    RuleValidationResult,
    SyntaxViolation,
    ConformanceReport,
    CMD_EBNF_SPEC,
    build_cmd_ebnf_rules,
    get_default_grammar,
    export_ebnf_specification,
    CorpusSample,
    CANONICAL_CORPUS,
    get_canonical_corpus,
    get_corpus_by_category,
    get_corpus_by_rule,
    EBNFConformanceValidator,
    validate_source,
    audit_ebnf_suite,
    handle_ebnf_cli,
)
from src.parser import CmdASTParser


class TestEBNFModels(unittest.TestCase):
    """Tests for EBNF grammar models, telemetry dataclasses, and serialization."""

    def test_grammar_rule_creation_and_dict(self):
        rule = GrammarRule(
            name="TestRule",
            rule_type=GrammarRuleType.SYNTACTIC,
            ebnf_expression="TestRule = Atom , { Atom } ;",
            description="A test grammar rule",
            category="testing",
            ast_node_types=["CommandNode"],
            is_terminal=False,
            examples=["test example"],
        )
        self.assertEqual(rule.name, "TestRule")
        self.assertEqual(rule.rule_type, GrammarRuleType.SYNTACTIC)
        data = rule.to_dict()
        self.assertEqual(data["name"], "TestRule")
        self.assertEqual(data["rule_type"], "syntactic")
        self.assertEqual(data["ast_node_types"], ["CommandNode"])

    def test_rule_validation_result_and_violation(self):
        res = RuleValidationResult(
            rule_name="Command",
            status=ValidationStatus.PASS,
            matched=True,
            occurrences=3,
            message="Passed 3 times",
            ast_node_types=["CommandNode"],
            matched_samples=["echo a", "echo b"],
        )
        self.assertEqual(res.status, ValidationStatus.PASS)
        d = res.to_dict()
        self.assertEqual(d["rule_name"], "Command")
        self.assertEqual(d["occurrences"], 3)

        v = SyntaxViolation(
            rule_name="CommandTarget",
            message="Missing target",
            line_number=5,
            snippet="&& echo",
            severity="ERROR",
        )
        self.assertEqual(v.severity, "ERROR")
        vd = v.to_dict()
        self.assertEqual(vd["line_number"], 5)

    def test_conformance_report_serialization(self):
        report = ConformanceReport(
            total_rules=10,
            tested_rules=8,
            covered_rules=8,
            passed_rules=8,
            failed_rules=0,
            grammar_coverage_pct=80.0,
            conformance_pct=100.0,
            results=[],
            violations=[],
            source_lines=15,
            ast_node_count=22,
            elapsed_ms=1.25,
            is_conformant=True,
        )
        summary = report.summary()
        self.assertIn("[PASS]", summary)
        self.assertIn("80.0%", summary)

        md = report.to_markdown()
        self.assertIn("cmd.exe EBNF Grammar Conformance Report", md)
        self.assertIn("80.0%", md)

        js = report.to_json()
        self.assertIn('"grammar_coverage_pct": 80.0', js)

    def test_grammar_specification_methods(self):
        spec = GrammarSpecification(title="Custom Spec", version="1.0.0")
        rule = GrammarRule(
            name="R1",
            rule_type=GrammarRuleType.LEXICAL,
            ebnf_expression="R1 = 'a' ;",
            description="Letter a",
            category="lexical",
        )
        spec.add_rule(rule)
        self.assertEqual(spec.get_rule("R1"), rule)
        self.assertIn("R1", spec.rule_names)
        self.assertEqual(len(spec.list_rules(rule_type=GrammarRuleType.LEXICAL)), 1)
        self.assertEqual(len(spec.list_rules(category="nonexistent")), 0)
        ebnf_text = spec.to_ebnf_text()
        self.assertIn("Custom Spec", ebnf_text)
        self.assertIn("R1 = 'a' ;", ebnf_text)


class TestEBNFGrammar(unittest.TestCase):
    """Tests for cmd.exe formal grammar specification and rule coverage."""

    def test_default_grammar_completeness(self):
        spec = get_default_grammar()
        self.assertGreaterEqual(len(spec.rules), 45)
        self.assertEqual(spec.version, "0.20.0")

        expected_rules = [
            "Character", "Newline", "Whitespace", "Digit", "Letter", "SpecialChar",
            "CaretEscape", "EmptyQuotePair", "DoubleQuote", "QuotedString", "LiteralText",
            "SeqOp", "AndOp", "OrOp", "PipeOp", "AssignOp", "RedirOut", "RedirAppend",
            "RedirIn", "RedirDup", "VarName", "SliceStart", "SliceLen", "PercentVar",
            "PercentSlice", "PercentSubst", "DelayedVar", "DelayedSlice", "ParamExpand",
            "Script", "Line", "Statement", "ChainOperator", "Pipeline", "CommandOrBlock",
            "Block", "Assignment", "Command", "CommandTarget", "Argument", "Redirection",
            "Atom", "IfStatement", "ForLoop", "LabelDef", "GotoStatement", "CallStatement",
            "ExitStatement", "Comment",
        ]
        for r_name in expected_rules:
            self.assertIsNotNone(spec.get_rule(r_name), f"Missing formal rule: {r_name}")

    def test_export_ebnf_specification(self):
        text = export_ebnf_specification()
        self.assertIn("Formal cmd.exe EBNF Grammar Specification", text)
        self.assertIn("Script = { Line } , [ EOF ] ;", text)
        self.assertIn("CaretEscape", text)


class TestCanonicalCorpus(unittest.TestCase):
    """Tests for canonical cmd.exe test corpus."""

    def test_canonical_corpus_structure(self):
        corpus = get_canonical_corpus()
        self.assertEqual(len(corpus), 25)

        ids = set()
        for sample in corpus:
            self.assertTrue(sample.id.startswith("CORPUS-"))
            self.assertNotIn(sample.id, ids)
            ids.add(sample.id)
            self.assertTrue(len(sample.code) > 0)
            self.assertTrue(len(sample.targeted_rules) > 0)
            self.assertEqual(sample.expected_status, "PASS")

    def test_corpus_filtering(self):
        statements = get_corpus_by_category("statements")
        self.assertGreaterEqual(len(statements), 4)
        self.assertEqual(get_corpus_by_category(None), [])
        self.assertEqual(get_corpus_by_rule(None), [])
        pipe_samples = get_corpus_by_rule("PipeOp")
        self.assertGreaterEqual(len(pipe_samples), 1)
        self.assertEqual(pipe_samples[0].id, "CORPUS-005")


class TestEBNFConformanceValidator(unittest.TestCase):
    """Tests for EBNFConformanceValidator against diverse batch constructs."""

    def setUp(self):
        self.validator = EBNFConformanceValidator()

    def test_validate_simple_command(self):
        report = self.validator.validate_source("echo hello world\n")
        self.assertTrue(report.is_conformant)
        self.assertEqual(report.failed_rules, 0)
        covered_names = {r.rule_name for r in report.results if r.matched}
        self.assertIn("Script", covered_names)
        self.assertIn("Command", covered_names)
        self.assertIn("CommandTarget", covered_names)
        self.assertIn("Argument", covered_names)
        self.assertIn("LiteralText", covered_names)

    def test_validate_chaining_and_operators(self):
        code = "echo 1 & echo 2 && echo 3 || echo 4\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("Statement", covered)
        self.assertIn("ChainOperator", covered)
        self.assertIn("SeqOp", covered)
        self.assertIn("AndOp", covered)
        self.assertIn("OrOp", covered)

    def test_validate_pipeline(self):
        code = "type test.txt | findstr /i pattern\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("Pipeline", covered)
        self.assertIn("PipeOp", covered)

    def test_validate_assignments(self):
        code = "set NAME=val\nset /a NUM=42+8\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("Assignment", covered)
        self.assertIn("VarName", covered)
        self.assertIn("AssignOp", covered)

    def test_validate_expansions_and_slices(self):
        code = "echo %VAR% !DELAY! %PATH:~0,5% !LINE:~-2! %TEXT:old=new% %~dp0\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("PercentVar", covered)
        self.assertIn("DelayedVar", covered)
        self.assertIn("PercentSlice", covered)
        self.assertIn("DelayedSlice", covered)
        self.assertIn("PercentSubst", covered)
        self.assertIn("ParamExpand", covered)

    def test_validate_control_flow(self):
        code = (
            ":START\n"
            "if exist file.txt ( echo yes ) else ( echo no )\n"
            "for %%i in (*.txt) do echo %%i\n"
            "call :subroutine arg1\n"
            "goto :START\n"
            "exit /b 0\n"
            "rem comment\n"
        )
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("LabelDef", covered)
        self.assertIn("IfStatement", covered)
        self.assertIn("ForLoop", covered)
        self.assertIn("CallStatement", covered)
        self.assertIn("GotoStatement", covered)
        self.assertIn("ExitStatement", covered)
        self.assertIn("Comment", covered)
        self.assertIn("Block", covered)

    def test_validate_redirections(self):
        code = "dir > out.txt & type log >> all.txt & sort < in.txt & cmd 2>&1\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("Redirection", covered)
        self.assertIn("RedirOut", covered)
        self.assertIn("RedirAppend", covered)
        self.assertIn("RedirIn", covered)
        self.assertIn("RedirDup", covered)

    def test_validate_carets_and_quotes(self):
        code = 'c^m^d.e^x^e "quoted argument with &" ""\n'
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("CaretEscape", covered)
        self.assertIn("QuotedString", covered)
        self.assertIn("EmptyQuotePair", covered)
        self.assertIn("DoubleQuote", covered)

    def test_validate_direct_ast(self):
        ast = CmdASTParser.from_source("dir & echo ok").parse()
        report = self.validator.validate_ast(ast)
        self.assertTrue(report.is_conformant)
        self.assertGreaterEqual(report.covered_rules, 4)

    def test_validate_ast_caret_and_empty_quote(self):
        ast = CmdASTParser.from_source('c^m^d "quoted" ""\n').parse()
        report = self.validator.validate_ast(ast)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("CaretEscape", covered)
        self.assertIn("EmptyQuotePair", covered)
        self.assertIn("QuotedString", covered)
        self.assertIn("DoubleQuote", covered)

    def test_dynamic_slice_expressions(self):
        code = "echo %VAR:~%OFFSET%,%LEN%% & echo !NAME:~%START%,%LEN%!\n"
        report = self.validator.validate_source(code)
        self.assertTrue(report.is_conformant)
        covered = {r.rule_name for r in report.results if r.matched}
        self.assertIn("PercentSlice", covered)
        self.assertIn("DelayedSlice", covered)
        self.assertIn("SliceStart", covered)
        self.assertIn("SliceLen", covered)

    def test_syntax_violations_detection(self):
        rep1 = self.validator.validate_source("()\n")
        self.assertFalse(rep1.is_conformant)
        self.assertTrue(any(v.rule_name == "Block" for v in rep1.violations))

        rep2 = self.validator.validate_source("if exist file.txt\n")
        self.assertFalse(rep2.is_conformant)
        self.assertTrue(any(v.rule_name == "IfStatement" for v in rep2.violations))

        rep3 = self.validator.validate_source("for %%i in (*.txt)\n")
        self.assertFalse(rep3.is_conformant)
        self.assertTrue(any(v.rule_name == "ForLoop" for v in rep3.violations))

    def test_deeply_nested_blocks(self):
        nested = "(" * 55 + "echo nested" + ")" * 55 + "\n"
        report = self.validator.validate_source(nested)
        self.assertTrue(report.is_conformant)
        self.assertEqual(len(report.violations), 0)

    def test_parser_failure_graceful_handling(self):
        malformed = "\x00\x01\x02"
        report = self.validator.validate_source(malformed)
        self.assertIsNotNone(report)
        none_rep = self.validator.validate_source(None)
        self.assertTrue(none_rep.is_conformant)

    def test_unicode_and_crlf(self):
        code = "echo 한글 테스트 🚀\r\nrem 한글 주석\r\nset 한글변수=값\r\necho %한글변수%\r\n"
        rep = self.validator.validate_source(code)
        self.assertTrue(rep.is_conformant)
        covered = {r.rule_name for r in rep.results if r.matched}
        self.assertIn("Newline", covered)
        self.assertIn("Comment", covered)
        self.assertIn("VarName", covered)
        self.assertIn("PercentVar", covered)

    def test_non_standard_redirections(self):
        for pattern, expected_rule in [
            ("cmd <&0\n", "RedirDup"),
            ("cmd >&2\n", "RedirDup"),
            ("cmd 3>&1\n", "RedirDup"),
            ("cmd 3>out.txt\n", "RedirOut"),
            ("cmd 2>>err.log\n", "RedirAppend"),
        ]:
            rep = self.validator.validate_source(pattern)
            self.assertTrue(rep.is_conformant, f"Failed on {pattern}")
            covered = {r.rule_name for r in rep.results if r.matched}
            self.assertIn(expected_rule, covered, f"{expected_rule} missing in {pattern}")

    def test_incomplete_statements_failure_rules(self):
        for stmt, rule in [
            ("for %%i in (*.txt)\n", "ForLoop"),
            ("if exist file.txt\n", "IfStatement"),
            ("goto\n", "GotoStatement"),
            ("call\n", "CallStatement"),
        ]:
            rep = self.validator.validate_source(stmt)
            self.assertFalse(rep.is_conformant)
            self.assertGreaterEqual(rep.failed_rules, 1)
            matching_result = next((r for r in rep.results if r.rule_name == rule), None)
            self.assertIsNotNone(matching_result)
            self.assertEqual(matching_result.status, ValidationStatus.FAIL)

    def test_label_and_ast_reconstruction(self):
        from src.ast_nodes import CommentNode, LabelNode, GotoNode, CallNode, ScriptNode
        ast = ScriptNode(statements=[CommentNode(text="rem note"), LabelNode(name="START"), GotoNode(target="START"), CallNode(target="sub")])
        rep = self.validator.validate_ast(ast)
        covered = {r.rule_name for r in rep.results if r.matched}
        self.assertIn("CommandOrBlock", covered)
        self.assertIn("LabelDef", covered)
        self.assertIn("Letter", covered)


class TestAuditSuite(unittest.TestCase):
    """Tests for canonical corpus audit suite execution and aggregate telemetry."""

    def test_audit_suite_execution(self):
        report = audit_ebnf_suite()
        self.assertTrue(report.is_conformant)
        self.assertEqual(report.failed_rules, 0)
        self.assertEqual(len(report.violations), 0)
        self.assertEqual(report.grammar_coverage_pct, 100.0)
        self.assertEqual(report.conformance_pct, 100.0)
        self.assertIsNotNone(report.corpus_results)
        self.assertEqual(len(report.corpus_results), 25)

        for s in report.corpus_results:
            self.assertEqual(s["status"], "PASS")

    def test_markdown_and_json_exports(self):
        report = audit_ebnf_suite()
        self.assertIn("cmd.exe EBNF Grammar Conformance Report", report.to_markdown())
        self.assertIn('"conformance_pct": 100.0', report.to_json())
        empty_rep = EBNFConformanceValidator().audit_suite(corpus=[])
        self.assertEqual(empty_rep.tested_rules, 0)
        self.assertTrue(empty_rep.is_conformant)


class TestCLIIntegration(unittest.TestCase):
    """Tests for CLI integration with EBNF flags."""

    def test_handle_ebnf_cli_audit_suite(self):
        args = SimpleNamespace(
            ebnf_audit_suite=True,
            ebnf_validate=False,
            ebnf_report=False,
            ebnf_json=None,
            ebnf_md=None,
        )
        code = handle_ebnf_cli(args)
        self.assertEqual(code, 0)

    def test_handle_ebnf_cli_validate(self):
        args = SimpleNamespace(
            ebnf_audit_suite=False,
            ebnf_validate=True,
            ebnf_report=False,
            ebnf_json=None,
            ebnf_md=None,
        )
        code = handle_ebnf_cli(args, source="echo test & dir")
        self.assertEqual(code, 0)

    def test_handle_ebnf_cli_validate_missing_source(self):
        args = SimpleNamespace(
            ebnf_audit_suite=False,
            ebnf_validate=True,
            ebnf_report=False,
            ebnf_json=None,
            ebnf_md=None,
        )
        code = handle_ebnf_cli(args, source=None)
        self.assertEqual(code, 1)

    def test_handle_ebnf_cli_export_json_and_md(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_file = os.path.join(tmp_dir, "report.json")
            md_file = os.path.join(tmp_dir, "report.md")

            args = SimpleNamespace(
                ebnf_audit_suite=False,
                ebnf_validate=False,
                ebnf_report=True,
                ebnf_json=json_file,
                ebnf_md=md_file,
            )
            code = handle_ebnf_cli(args, source="echo export test")
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(json_file))
            self.assertTrue(os.path.isfile(md_file))

    def test_cli_missing_input_file(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, "-m", "src.cli", "-i", "nonexistent_file_xyz.bat", "--ebnf-validate"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("File not found", proc.stderr)

    def test_cli_empty_batch_file(self):
        with tempfile.NamedTemporaryFile(suffix=".bat", delete=False) as f:
            f.write(b"")
            fpath = f.name
        try:
            import subprocess
            proc = subprocess.run([sys.executable, "-m", "src.cli", "-i", fpath, "--ebnf-validate"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("[PASS]", proc.stdout)
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)


if __name__ == "__main__":
    unittest.main()
