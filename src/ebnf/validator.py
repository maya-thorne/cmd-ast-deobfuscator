"""
cmd-ast-deobfuscator: EBNF Conformance Validator and Grammar Audit Engine.
Validates batch scripts and ASTs against formal EBNF specifications, tracks rule
coverage matrices, detects syntax/semantic violations, and evaluates test suites.
"""

import sys
import time
from typing import List, Dict, Set, Optional, Any
from ..parser import CmdASTParser
from ..lexer import CmdLexer, CmdToken, CmdTokenType
from ..ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, ParamExpandNode, ForNode, IfNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from .models import (
    GrammarRule, GrammarRuleType, GrammarSpecification,
    ValidationStatus, RuleValidationResult, SyntaxViolation, ConformanceReport
)
from .grammar import CMD_EBNF_SPEC
from .corpus import CorpusSample, get_canonical_corpus


def _safe_print(text: str, file: Optional[Any] = None) -> None:
    target = file or sys.stdout
    try:
        print(text, file=target)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"), file=target)


class EBNFConformanceValidator:
    """Formal validator verifying batch code and AST trees against cmd.exe EBNF grammar rules."""

    def __init__(self, grammar: Optional[GrammarSpecification] = None):
        self.grammar = grammar or CMD_EBNF_SPEC

    def validate_source(self, source: Optional[str], filename: Optional[str] = None) -> ConformanceReport:
        """Parses batch source and validates conformance against the EBNF grammar."""
        start_time = time.perf_counter()
        src = "" if source is None else source
        try:
            lexer = CmdLexer(src)
            tokens = lexer.tokenize()
            parser = CmdASTParser(tokens)
            ast = parser.parse()
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            violations = [SyntaxViolation("Script", f"Parser failure: {str(exc)}", 1, src[:60], "FATAL")]
            return ConformanceReport(
                total_rules=len(self.grammar.rules), tested_rules=1, covered_rules=0,
                passed_rules=0, failed_rules=1, grammar_coverage_pct=0.0, conformance_pct=0.0,
                results=[], violations=violations, source_lines=len(src.splitlines()) if src else 0,
                ast_node_count=0, elapsed_ms=elapsed_ms, is_conformant=False
            )
        return self.validate_ast(ast, source=src, tokens=tokens, start_time=start_time)

    def validate_ast(
        self, ast: ScriptNode, source: str = "", tokens: Optional[List[CmdToken]] = None,
        start_time: Optional[float] = None
    ) -> ConformanceReport:
        """Validates an existing AST hierarchy against EBNF grammar production rules."""
        if start_time is None:
            start_time = time.perf_counter()

        collected_nodes: List[ASTNode] = []
        self._collect_all_nodes(ast, collected_nodes)
        rule_matches: Dict[str, List[ASTNode]] = {name: [] for name in self.grammar.rules}
        violations: List[SyntaxViolation] = []

        if not source and collected_nodes:
            text_frags = []
            for n in collected_nodes:
                if isinstance(n, LiteralNode):
                    text_frags.append(n.value)
                elif isinstance(n, CommandNode) and n.target:
                    text_frags.append(n.target)
                elif isinstance(n, AssignmentNode):
                    text_frags.extend([n.var_name, n.raw_value])
                elif isinstance(n, VarExpandNode) and n.name:
                    text_frags.append(n.name)
                elif isinstance(n, CommentNode) and n.text:
                    text_frags.append(n.text)
                elif isinstance(n, LabelNode) and n.name:
                    text_frags.append(n.name)
                elif isinstance(n, (GotoNode, CallNode)) and n.target:
                    text_frags.append(n.target)
                elif isinstance(n, IfNode) and n.condition:
                    text_frags.append(n.condition)
                elif isinstance(n, ForNode):
                    text_frags.extend([n.iterator, n.in_clause])
                elif isinstance(n, ExitNode) and n.exit_code:
                    text_frags.append(n.exit_code)
                elif isinstance(n, RedirectNode):
                    text_frags.extend([n.stream, n.destination])
            source = " ".join(f for f in text_frags if f)

        for node in collected_nodes:
            self._map_node_to_rules(node, rule_matches, violations)
        self._map_tokens_to_rules(source, tokens, rule_matches)

        results: List[RuleValidationResult] = []
        covered_count = 0
        passed_count = 0
        failed_count = 0

        for rule_name, rule in self.grammar.rules.items():
            matched_items = rule_matches.get(rule_name, [])
            occurrences = len(matched_items)
            rule_violations = [v for v in violations if v.rule_name == rule_name]
            if occurrences > 0 or rule_violations:
                covered_count += 1
                if rule_violations:
                    failed_count += 1
                    status = ValidationStatus.FAIL
                    msg = f"Failed ({len(rule_violations)} violation(s))"
                else:
                    passed_count += 1
                    status = ValidationStatus.PASS
                    msg = f"Passed ({occurrences} occurrence(s))"
                results.append(RuleValidationResult(
                    rule_name=rule_name, status=status, matched=True, occurrences=occurrences,
                    message=msg, ast_node_types=rule.ast_node_types,
                    matched_samples=[str(item)[:40] for item in matched_items[:3]]
                ))
            else:
                results.append(RuleValidationResult(
                    rule_name=rule_name, status=ValidationStatus.SKIPPED, matched=False,
                    occurrences=0, message="Not exercised in this script", ast_node_types=rule.ast_node_types
                ))

        total_rules = len(self.grammar.rules)
        cov_pct = (covered_count / total_rules * 100.0) if total_rules > 0 else 0.0
        conf_pct = (passed_count / covered_count * 100.0) if covered_count > 0 else 100.0
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        lines = len(source.splitlines()) if source else 1

        return ConformanceReport(
            total_rules=total_rules, tested_rules=covered_count, covered_rules=covered_count,
            passed_rules=passed_count, failed_rules=failed_count, grammar_coverage_pct=cov_pct,
            conformance_pct=conf_pct, results=results, violations=violations, source_lines=lines,
            ast_node_count=len(collected_nodes), elapsed_ms=elapsed_ms,
            is_conformant=(failed_count == 0 and len(violations) == 0)
        )

    def _collect_all_nodes(self, node: ASTNode, acc: List[ASTNode]) -> None:
        """Recursively gathers all AST nodes in the tree."""
        if node is None:
            return
        acc.append(node)
        if isinstance(node, ScriptNode):
            for stmt in node.statements:
                self._collect_all_nodes(stmt, acc)
        elif isinstance(node, CommandNode):
            if not node.target_nodes and node.target:
                acc.append(LiteralNode(value=node.target, is_quoted=False))
            for tn in node.target_nodes:
                self._collect_all_nodes(tn, acc)
            for arg in node.arguments:
                self._collect_all_nodes(arg, acc)
        elif isinstance(node, (ChainNode, PipeNode)):
            self._collect_all_nodes(node.left, acc)
            self._collect_all_nodes(node.right, acc)
        elif isinstance(node, BlockNode):
            for stmt in node.statements:
                self._collect_all_nodes(stmt, acc)
        elif isinstance(node, IfNode):
            self._collect_all_nodes(node.then_block, acc)
            if node.else_block:
                self._collect_all_nodes(node.else_block, acc)
        elif isinstance(node, ForNode):
            self._collect_all_nodes(node.body, acc)
        elif isinstance(node, AssignmentNode):
            for val in node.value_nodes:
                self._collect_all_nodes(val, acc)
        elif isinstance(node, RedirectNode):
            self._collect_all_nodes(node.command, acc)
        elif isinstance(node, (GotoNode, CallNode)):
            if not node.target_nodes and node.target:
                acc.append(LiteralNode(value=node.target, is_quoted=False))
            for tn in node.target_nodes:
                self._collect_all_nodes(tn, acc)
            if isinstance(node, CallNode):
                for arg in node.arguments:
                    self._collect_all_nodes(arg, acc)

    def _map_node_to_rules(
        self, node: ASTNode, matches: Dict[str, List[ASTNode]], violations: List[SyntaxViolation]
    ) -> None:
        """Inspects an AST node and maps it to matching EBNF production rules."""
        if isinstance(node, ScriptNode):
            matches["Script"].append(node)
            matches["Line"].append(node)
        elif isinstance(node, CommandNode):
            matches["Command"].append(node)
            matches["CommandOrBlock"].append(node)
            t_str = node.target.strip().lower() if node.target else ""
            if t_str in ("if", "for"):
                r_name = "IfStatement" if t_str == "if" else "ForLoop"
                violations.append(SyntaxViolation(r_name, f"Malformed {t_str.upper()} statement syntax", snippet=t_str, severity="ERROR"))
            elif t_str in ("goto", "call") and not node.arguments:
                r_name = "GotoStatement" if t_str == "goto" else "CallStatement"
                violations.append(SyntaxViolation(r_name, f"{t_str.upper()} statement missing target", snippet=t_str, severity="ERROR"))
            elif node.target or node.target_nodes:
                matches["CommandTarget"].append(node)
            else:
                violations.append(SyntaxViolation("CommandTarget", "Empty command target", snippet="<empty>", severity="ERROR"))
            if node.arguments:
                matches["Argument"].extend(node.arguments)
        elif isinstance(node, ChainNode):
            matches["Statement"].append(node)
            matches["ChainOperator"].append(node)
            if node.operator == "&":
                matches["SeqOp"].append(node)
            elif node.operator == "&&":
                matches["AndOp"].append(node)
            elif node.operator == "||":
                matches["OrOp"].append(node)
            else:
                violations.append(SyntaxViolation("ChainOperator", f"Invalid chain operator: {node.operator}", snippet=str(node.operator)))
            if node.left is None or node.right is None:
                violations.append(SyntaxViolation("Statement", "Incomplete chained statement missing operand", snippet=str(node.operator)))
        elif isinstance(node, PipeNode):
            matches["Pipeline"].append(node)
            matches["PipeOp"].append(node)
            if node.left is None or node.right is None:
                violations.append(SyntaxViolation("Pipeline", "Pipeline missing left or right command", snippet="|"))
        elif isinstance(node, BlockNode):
            matches["Block"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.statements:
                violations.append(SyntaxViolation("Block", "Empty compound block expression", snippet="()"))
        elif isinstance(node, AssignmentNode):
            matches["Assignment"].append(node)
            matches["CommandOrBlock"].append(node)
            matches["AssignOp"].append(node)
            if node.var_name:
                matches["VarName"].append(node)
            else:
                violations.append(SyntaxViolation("Assignment", "Assignment missing variable name", snippet=node.raw_value or "="))
        elif isinstance(node, IfNode):
            matches["IfStatement"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.condition:
                violations.append(SyntaxViolation("IfStatement", "IF statement missing condition", snippet="if"))
        elif isinstance(node, ForNode):
            matches["ForLoop"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.iterator:
                violations.append(SyntaxViolation("ForLoop", "FOR loop missing iterator variable", snippet="for"))
        elif isinstance(node, LabelNode):
            matches["LabelDef"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.name:
                violations.append(SyntaxViolation("LabelDef", "Label missing identifier", snippet=":"))
        elif isinstance(node, GotoNode):
            matches["GotoStatement"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.target and not node.target_nodes:
                violations.append(SyntaxViolation("GotoStatement", "GOTO missing target label", snippet="goto"))
        elif isinstance(node, CallNode):
            matches["CallStatement"].append(node)
            matches["CommandOrBlock"].append(node)
            if not node.target and not node.target_nodes:
                violations.append(SyntaxViolation("CallStatement", "CALL missing target", snippet="call"))
        elif isinstance(node, ExitNode):
            matches["ExitStatement"].append(node)
            matches["CommandOrBlock"].append(node)
        elif isinstance(node, CommentNode):
            matches["Comment"].append(node)
            matches["CommandOrBlock"].append(node)
        elif isinstance(node, RedirectNode):
            matches["Redirection"].append(node)
            stream = node.stream or ""
            if ">>" in stream:
                matches["RedirAppend"].append(node)
            elif ">&" in stream or "<&" in stream or node.is_dup:
                matches["RedirDup"].append(node)
            elif ">" in stream:
                matches["RedirOut"].append(node)
            elif "<" in stream:
                matches["RedirIn"].append(node)
            if not node.destination and not node.target_fd and not node.is_dup:
                violations.append(SyntaxViolation("Redirection", "Redirection missing destination target", snippet=stream or ">"))
        elif isinstance(node, VarExpandNode):
            matches["Atom"].append(node)
            if node.name:
                matches["VarName"].append(node)
            else:
                violations.append(SyntaxViolation("VarName", "Variable expansion missing variable identifier", snippet="%%"))
            is_slice = (node.slice_start is not None or node.slice_start_expr is not None)
            has_len = (node.slice_len is not None or node.slice_len_expr is not None)
            if node.is_delayed:
                if is_slice:
                    matches["DelayedSlice"].append(node)
                    matches["SliceStart"].append(node)
                    if has_len:
                        matches["SliceLen"].append(node)
                elif node.sub_search is not None:
                    matches["PercentSubst"].append(node)
                    matches["DelayedVar"].append(node)
                else:
                    matches["DelayedVar"].append(node)
            else:
                if is_slice:
                    matches["PercentSlice"].append(node)
                    matches["SliceStart"].append(node)
                    if has_len:
                        matches["SliceLen"].append(node)
                elif node.sub_search is not None:
                    matches["PercentSubst"].append(node)
                else:
                    matches["PercentVar"].append(node)
        elif isinstance(node, ParamExpandNode):
            matches["Atom"].append(node)
            matches["ParamExpand"].append(node)
        elif isinstance(node, LiteralNode):
            matches["Atom"].append(node)
            if node.is_quoted:
                matches["QuotedString"].append(node)
                matches["DoubleQuote"].append(node)
                if node.value == "":
                    matches["EmptyQuotePair"].append(node)
            elif (node.value in ('', '""') or (node.span and node.span[1] - node.span[0] == 2 and node.value == '')) and not node.is_quoted:
                matches["EmptyQuotePair"].append(node)
            elif "^" in node.value or (node.span and not node.is_quoted and (node.span[1] - node.span[0] > len(node.value))):
                matches["CaretEscape"].append(node)
            else:
                matches["LiteralText"].append(node)

    def _map_tokens_to_rules(
        self, source: str, tokens: Optional[List[CmdToken]], matches: Dict[str, List[Any]]
    ) -> None:
        """Scans tokens and source patterns for lexical and terminal rules."""
        if not source:
            return
        matches["Character"].append(source[0])
        if any(c.isspace() for c in source):
            matches["Whitespace"].append(" ")
        if "\n" in source or "\r" in source:
            matches["Newline"].append("\n")
        if any(c.isdigit() for c in source):
            matches["Digit"].append("0")
        if any(c.isalpha() for c in source):
            matches["Letter"].append("a")
        if any(c in '^"%!&|<>=' for c in source):
            matches["SpecialChar"].append("^")
        if '^' in source and not matches["CaretEscape"]:
            matches["CaretEscape"].append("^")
        if '""' in source and not matches["EmptyQuotePair"]:
            matches["EmptyQuotePair"].append('""')
        if '"' in source and not matches["DoubleQuote"]:
            matches["DoubleQuote"].append('"')

        if tokens:
            for tok in tokens:
                if tok.type == CmdTokenType.AMP and not matches["SeqOp"]:
                    matches["SeqOp"].append(tok)
                elif tok.type == CmdTokenType.DOUBLE_AMP and not matches["AndOp"]:
                    matches["AndOp"].append(tok)
                elif tok.type == CmdTokenType.DOUBLE_PIPE and not matches["OrOp"]:
                    matches["OrOp"].append(tok)
                elif tok.type == CmdTokenType.PIPE and not matches["PipeOp"]:
                    matches["PipeOp"].append(tok)
                elif tok.type == CmdTokenType.EQUALS and not matches["AssignOp"]:
                    matches["AssignOp"].append(tok)

    def audit_suite(self, corpus: Optional[List[CorpusSample]] = None) -> ConformanceReport:
        """Runs the entire canonical test corpus and computes aggregate grammar coverage."""
        suite = corpus if corpus is not None else get_canonical_corpus()
        start_time = time.perf_counter()
        per_sample_results: List[Dict[str, Any]] = []
        overall_covered: Set[str] = set()
        overall_failed: Set[str] = set()
        rule_occ: Dict[str, int] = {name: 0 for name in self.grammar.rules}
        all_violations: List[SyntaxViolation] = []
        total_lines = 0
        total_nodes = 0

        for sample in suite:
            rep = self.validate_source(sample.code)
            total_lines += rep.source_lines
            total_nodes += rep.ast_node_count
            all_violations.extend(rep.violations)
            sample_covered = [r.rule_name for r in rep.results if r.matched]
            sample_failed = [r.rule_name for r in rep.results if r.status == ValidationStatus.FAIL]
            for r in rep.results:
                if r.matched:
                    overall_covered.add(r.rule_name)
                    rule_occ[r.rule_name] += r.occurrences
                if r.status == ValidationStatus.FAIL:
                    overall_failed.add(r.rule_name)
            per_sample_results.append({
                "id": sample.id, "name": sample.name, "category": sample.category,
                "status": "PASS" if (len(sample_failed) == 0 and rep.is_conformant) else "FAIL",
                "covered_rules": sample_covered, "failed_rules": sample_failed,
                "elapsed_ms": rep.elapsed_ms,
            })

        results: List[RuleValidationResult] = []
        for name, rule in self.grammar.rules.items():
            occ = rule_occ.get(name, 0)
            if name in overall_failed:
                status, msg = ValidationStatus.FAIL, f"Failed in suite ({occ} occurrences)"
            elif name in overall_covered:
                status, msg = ValidationStatus.PASS, f"Passed across suite ({occ} occurrences)"
            else:
                status, msg = ValidationStatus.SKIPPED, "Not exercised in suite"
            results.append(RuleValidationResult(
                rule_name=name, status=status, matched=(name in overall_covered),
                occurrences=occ, message=msg, ast_node_types=rule.ast_node_types
            ))

        total_rules = len(self.grammar.rules)
        cov_count = len(overall_covered)
        passed_count = len(overall_covered - overall_failed)
        cov_pct = (cov_count / total_rules * 100.0) if total_rules > 0 else 0.0
        conf_pct = (passed_count / cov_count * 100.0) if cov_count > 0 else 100.0
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ConformanceReport(
            total_rules=total_rules, tested_rules=cov_count, covered_rules=cov_count,
            passed_rules=passed_count, failed_rules=len(overall_failed), grammar_coverage_pct=cov_pct,
            conformance_pct=conf_pct, results=results, violations=all_violations,
            corpus_results=per_sample_results, source_lines=total_lines,
            ast_node_count=total_nodes, elapsed_ms=elapsed_ms,
            is_conformant=(len(overall_failed) == 0 and len(all_violations) == 0)
        )


def validate_source(source: str) -> ConformanceReport:
    """Convenience function to validate batch source against cmd.exe EBNF grammar."""
    return EBNFConformanceValidator().validate_source(source)


def audit_ebnf_suite() -> ConformanceReport:
    """Convenience function to audit the canonical corpus against cmd.exe EBNF grammar."""
    return EBNFConformanceValidator().audit_suite()


def handle_ebnf_cli(args: Any, source: Optional[str] = None) -> int:
    """Dispatches EBNF CLI commands (--ebnf-validate, --ebnf-report, --ebnf-audit-suite)."""
    validator = EBNFConformanceValidator()
    if getattr(args, "ebnf_audit_suite", False):
        report = validator.audit_suite()
    elif getattr(args, "ebnf_report", False):
        report = validator.validate_source(source) if source is not None else validator.audit_suite()
    elif getattr(args, "ebnf_validate", False):
        if source is None:
            _safe_print("[!] Error: --ebnf-validate requires an input script (-c or -i).", file=sys.stderr)
            return 1
        report = validator.validate_source(source)
    else:
        return 0

    import os
    if getattr(args, "ebnf_json", None):
        out_dir = os.path.dirname(args.ebnf_json)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.ebnf_json, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        _safe_print(f"[+] EBNF report exported to JSON: {args.ebnf_json}")

    if getattr(args, "ebnf_md", None):
        out_dir = os.path.dirname(args.ebnf_md)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.ebnf_md, "w", encoding="utf-8") as f:
            f.write(report.to_markdown())
        _safe_print(f"[+] EBNF report exported to Markdown: {args.ebnf_md}")

    if getattr(args, "ebnf_report", False) or getattr(args, "ebnf_audit_suite", False):
        _safe_print("\n" + report.to_markdown())
    else:
        _safe_print("\n" + report.summary())
        for v in report.violations:
            _safe_print(f"  [!] {v.rule_name} ({v.severity}): {v.message}")

    return 0 if report.is_conformant else 1
