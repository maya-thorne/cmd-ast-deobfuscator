"""
Comprehensive Unit & Integration Test Suite for Quote Toggle Boundary & Nested Quote Normalization (M11).
Validates QuoteToggleAutomaton, QuoteNormalizer, QuoteNormalizerPass, CLI flags,
empty quote reduction, argument canonicalization, and zeroize memory wiping.
"""

import unittest
from src.quotes import (
    QuoteState,
    QuoteSegment,
    QuoteNormalizerMetrics,
    QuoteToggleAutomaton,
    QuoteNormalizer,
    normalize_quotes,
    collapse_empty_quotes,
)
from src.transforms import QuoteNormalizerPass, PassManager
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    CommandNode, AssignmentNode, LiteralNode, ChainNode,
    BlockNode, IfNode, ForNode, ScriptNode
)


class TestQuoteNormalizerSuite(unittest.TestCase):

    def setUp(self):
        self.automaton = QuoteToggleAutomaton()
        self.normalizer = QuoteNormalizer()
        self.pass_instance = QuoteNormalizerPass()

    # -------------------------------------------------------------------------
    # 1. Quote State Machine Transitions & Boundary Detection
    # -------------------------------------------------------------------------

    def test_quote_state_machine_basic_segments(self):
        text = 'hello "quoted text" world'
        segments = self.automaton.tokenize_segments(text)
        self.assertEqual(len(segments), 3)
        self.assertEqual(segments[0].text, 'hello ')
        self.assertFalse(segments[0].is_quoted)
        self.assertEqual(segments[1].text, 'quoted text')
        self.assertTrue(segments[1].is_quoted)
        self.assertEqual(segments[2].text, ' world')
        self.assertFalse(segments[2].is_quoted)

    def test_quote_state_machine_escaped_quote(self):
        text = 'before ^"literal quote^" after'
        segments = self.automaton.tokenize_segments(text)
        # ^" outside quotes emits an escaped quote with is_quoted=False
        escaped_segs = [s for s in segments if s.is_escaped]
        self.assertEqual(len(escaped_segs), 2)
        for s in escaped_segs:
            self.assertEqual(s.text, '"')
            self.assertFalse(s.is_quoted)

    def test_quote_state_machine_unclosed_quote(self):
        text = 'echo "unclosed string goes to end'
        segments = self.automaton.tokenize_segments(text)
        self.assertEqual(len(segments), 2)
        self.assertEqual(segments[0].text, 'echo ')
        self.assertFalse(segments[0].is_quoted)
        self.assertEqual(segments[1].text, 'unclosed string goes to end')
        self.assertTrue(segments[1].is_quoted)

    def test_quote_state_machine_empty_string(self):
        segments = self.automaton.tokenize_segments('')
        self.assertEqual(len(segments), 0)

    # -------------------------------------------------------------------------
    # 2. Empty Quote Pair Collapsing ("" -> reduction)
    # -------------------------------------------------------------------------

    def test_collapse_embedded_empty_quotes(self):
        self.assertEqual(self.automaton.collapse_empty_quotes('w""h""o""a""m""i'), 'whoami')
        self.assertEqual(self.automaton.collapse_empty_quotes('c""m""d'), 'cmd')
        self.assertEqual(self.automaton.collapse_empty_quotes('p""o""w""e""r""s""h""e""l""l'), 'powershell')

    def test_collapse_consecutive_multi_quotes(self):
        self.assertEqual(self.automaton.collapse_empty_quotes('""""'), '""')
        self.assertEqual(self.automaton.collapse_empty_quotes('""""""'), '""')
        self.assertEqual(self.automaton.collapse_empty_quotes('calc""""'), 'calc')

    def test_collapse_standalone_empty_string(self):
        # A standalone empty string argument must be preserved
        self.assertEqual(self.automaton.collapse_empty_quotes('""'), '""')

    def test_collapse_mixed_quotes_and_carets(self):
        self.assertEqual(collapse_empty_quotes('c""m""d /c w""h""o'), 'cmd /c who')

    # -------------------------------------------------------------------------
    # 3. Command Target Normalization
    # -------------------------------------------------------------------------

    def test_normalize_target_stripped_quotes(self):
        self.assertEqual(self.automaton.normalize_target('"c"m"d"'), 'cmd')
        self.assertEqual(self.automaton.normalize_target('c""m""d'), 'cmd')
        self.assertEqual(self.automaton.normalize_target('""powershell""'), 'powershell')
        self.assertEqual(self.automaton.normalize_target('"whoami"'), 'whoami')

    def test_normalize_target_with_carets(self):
        self.assertEqual(self.automaton.normalize_target('w^"h^"o^"a^"m^"i'), 'whoami')
        self.assertEqual(self.automaton.normalize_target('^c^a^l^c'), 'calc')
        self.assertEqual(self.automaton.normalize_target('"^c^a^l^c"'), 'calc')

    def test_normalize_target_path(self):
        self.assertEqual(
            self.automaton.normalize_target(r'"C:\Windows\System32\cmd.exe"'),
            r'C:\Windows\System32\cmd.exe'
        )

    # -------------------------------------------------------------------------
    # 4. Command Argument Normalization
    # -------------------------------------------------------------------------

    def test_normalize_argument_safe_tokens(self):
        self.assertEqual(self.automaton.normalize_argument('""calc.exe""'), 'calc.exe')
        self.assertEqual(self.automaton.normalize_argument('""/c""'), '/c')
        self.assertEqual(self.automaton.normalize_argument('c""a""l""c'), 'calc')
        self.assertEqual(self.automaton.normalize_argument('"""calc.exe"""'), 'calc.exe')
        self.assertEqual(self.automaton.normalize_argument(r'""C:\test.bat""'), r'C:\test.bat')
        # Clean canonical quoted string preserved
        self.assertEqual(self.automaton.normalize_argument('"dir"'), '"dir"')

    def test_normalize_argument_standalone_empty(self):
        self.assertEqual(self.automaton.normalize_argument('""'), '""')
        self.assertEqual(self.automaton.normalize_argument('  ""  '.strip()), '""')

    def test_normalize_argument_with_spaces(self):
        self.assertEqual(self.automaton.normalize_argument('"hello world"'), '"hello world"')
        # Fragmented quotes with spaces canonicalized to single outer pair
        self.assertEqual(self.automaton.normalize_argument('"hello" "world"'), '"hello world"')

    def test_normalize_argument_with_metacharacters(self):
        self.assertEqual(self.automaton.normalize_argument('"foo&bar"'), '"foo&bar"')
        self.assertEqual(self.automaton.normalize_argument('"a|b"'), '"a|b"')
        self.assertEqual(self.automaton.normalize_argument('"x>y"'), '"x>y"')

    def test_normalize_argument_embedded_empty_quotes(self):
        self.assertEqual(self.automaton.normalize_argument('arg""val'), 'argval')

    # -------------------------------------------------------------------------
    # 5. Variable Assignment Normalization
    # -------------------------------------------------------------------------

    def test_normalize_assignment_enclosed_quotes(self):
        var, val, is_enc = self.normalizer.normalize_assignment('VAR', '"hello"')
        self.assertEqual(var, 'VAR')
        self.assertEqual(val, 'hello')
        self.assertTrue(is_enc)

    def test_normalize_assignment_quoted_var_name(self):
        var, val, _ = self.normalizer.normalize_assignment('"MY_VAR"', 'test')
        self.assertEqual(var, 'MY_VAR')
        self.assertEqual(val, 'test')

    def test_normalize_assignment_redundant_quotes(self):
        var, val, _ = self.normalizer.normalize_assignment('""KEY""', '""val""')
        self.assertEqual(var, 'KEY')
        self.assertEqual(val, 'val')

    def test_normalize_assignment_embedded_empty_in_value(self):
        var, val, _ = self.normalizer.normalize_assignment('VAR', 'p""a""t""h')
        self.assertEqual(var, 'VAR')
        self.assertEqual(val, 'path')

    # -------------------------------------------------------------------------
    # 6. AST Pass Transformation (QuoteNormalizerPass)
    # -------------------------------------------------------------------------

    def test_pass_transforms_command_node(self):
        cmd = CommandNode(
            target='"c"m"d"',
            arguments=[LiteralNode(value='""'), LiteralNode(value='""calc.exe""')]
        )
        norm_cmd = self.pass_instance.visit_CommandNode(cmd)
        self.assertTrue(self.pass_instance.modified)
        self.assertEqual(norm_cmd.target, 'cmd')
        self.assertEqual(norm_cmd.arguments[0].value, '""')
        self.assertEqual(norm_cmd.arguments[1].value, 'calc.exe')

    def test_pass_transforms_assignment_node(self):
        assign = AssignmentNode(var_name='""VAR""', raw_value='""secret""')
        norm_assign = self.pass_instance.visit_AssignmentNode(assign)
        self.assertTrue(self.pass_instance.modified)
        self.assertEqual(norm_assign.var_name, 'VAR')
        self.assertEqual(norm_assign.raw_value, 'secret')

    def test_pass_transforms_literal_node(self):
        lit = LiteralNode(value='w""h""o')
        norm_lit = self.pass_instance.visit_LiteralNode(lit)
        self.assertTrue(self.pass_instance.modified)
        self.assertEqual(norm_lit.value, 'who')

    def test_pass_transforms_chain_and_block(self):
        block = BlockNode(statements=[
            CommandNode(target='""whoami""', arguments=[]),
            CommandNode(target='c""m""d', arguments=[LiteralNode(value='""/c""')])
        ])
        norm_block = self.pass_instance.visit_BlockNode(block)
        self.assertEqual(norm_block.statements[0].target, 'whoami')
        self.assertEqual(norm_block.statements[1].target, 'cmd')
        self.assertEqual(norm_block.statements[1].arguments[0].value, '/c')

    # -------------------------------------------------------------------------
    # 7. PassManager Pipeline Integration & Full End-to-End AST Parsing
    # -------------------------------------------------------------------------

    def test_pass_manager_pipeline_execution(self):
        source = 'set ""TARGET""=""calc"" & ""c""m""d /c %TARGET%'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        pm = PassManager.default_pipeline()
        transformed = pm.run(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(transformed)
        self.assertIn('set TARGET=calc', output)
        self.assertIn('cmd /c calc', output)

    # -------------------------------------------------------------------------
    # 8. Memory Zeroize and Telemetry Metrics
    # -------------------------------------------------------------------------

    def test_telemetry_metrics_tracking(self):
        automaton = QuoteToggleAutomaton()
        automaton.normalize_target('c""m""d')
        automaton.normalize_argument('""calc.exe""')
        automaton.normalize_assignment_value('""test""')

        self.assertGreater(automaton.metrics.total_tokens_processed, 0)
        self.assertGreater(automaton.metrics.targets_normalized, 0)
        self.assertGreater(automaton.metrics.arguments_normalized, 0)
        summary = automaton.metrics.summary()
        self.assertIn('Tokens processed', summary)

    def test_zeroize_memory_clearing(self):
        automaton = QuoteToggleAutomaton()
        automaton.normalize_target('c""m""d')
        self.assertGreater(automaton.metrics.total_tokens_processed, 0)

        automaton.zeroize()
        self.assertEqual(automaton.metrics.total_tokens_processed, 0)
        self.assertEqual(automaton.metrics.targets_normalized, 0)


if __name__ == '__main__':
    unittest.main()
