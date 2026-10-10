"""
Comprehensive Unit Test Suite for cmd-ast-deobfuscator Compiler & AST Pipeline.
Validates Lexer, Automaton, Parser, Normalizer, and Visualizer.
"""

import unittest
from src.lexer import CmdLexer, CmdTokenType
from src.automaton import PushdownAutomaton, AutomatonState
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.visualizer import ASTVisualizer
from src.ast_nodes import ScriptNode, CommandNode, AssignmentNode, ChainNode, PipeNode, LiteralNode


class TestCmdASTCompilerSuite(unittest.TestCase):

    def test_lexer_caret_and_quote_tokenization(self):
        source = 'c^a^l^c^.^e^x^e "quoted ^caret" ""'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        # Check tokens
        token_types = [t.type for t in tokens]
        self.assertIn(CmdTokenType.CARET, token_types)
        self.assertIn(CmdTokenType.QUOTE, token_types)
        self.assertEqual(tokens[-1].type, CmdTokenType.EOF)

    def test_lexer_percent_variable_detection(self):
        source = '%COMSPEC:~19,1% %VAR:old=new%'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        percent_tokens = [t for t in tokens if t.type == CmdTokenType.PERCENT_VAR]
        self.assertEqual(len(percent_tokens), 2)
        self.assertEqual(percent_tokens[0].value, '%COMSPEC:~19,1%')
        self.assertEqual(percent_tokens[1].value, '%VAR:old=new%')

    def test_automaton_state_transitions(self):
        pda = PushdownAutomaton()
        source = 'set FOO=bar & calc.exe'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        for t in tokens:
            pda.transition(t)

        self.assertEqual(pda.depth(), 0)
        self.assertEqual(pda.current_state(), AutomatonState.TERMINAL)

    def test_parser_command_chaining(self):
        source = 'set X=calc & %X% && echo success'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        self.assertIsInstance(ast, ScriptNode)
        self.assertTrue(len(ast.statements) > 0)

    def test_parser_parenthesized_block(self):
        source = '( echo one & echo two ) | more'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        self.assertIsInstance(ast, ScriptNode)
        first_stmt = ast.statements[0]
        self.assertIsInstance(first_stmt, PipeNode)

    def test_normalizer_caret_stripping(self):
        source = 'c^a^l^c^.^e^x^e'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertEqual(output.strip(), 'calc.exe')

    def test_normalizer_environment_slicing(self):
        source = '%COMSPEC:~20,1%%COMSPEC:~21,1%%COMSPEC:~22,1%'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        # COMSPEC is C:\Windows\system32\cmd.exe
        # Index 20 is 'c', 21 is 'm', 22 is 'd'
        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertEqual(output.strip(), 'cmd')

        # Negative slicing test
        p2 = CmdASTParser.from_source('%COMSPEC:~-7,3%')
        ast2 = normalizer.normalize(p2.parse())
        self.assertEqual(normalizer.to_source(ast2).strip(), 'cmd')

    def test_normalizer_symbol_table_propagation(self):
        source = 'set TARGET=calc.exe\n%TARGET%'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('calc.exe', output)

    def test_visualizer_ascii_tree(self):
        source = 'set A=1 & calc.exe'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        ascii_tree = ASTVisualizer.render_ascii_tree(ast)
        self.assertIn('ScriptNode', ascii_tree)
        self.assertIn('ChainNode', ascii_tree)

    def test_visualizer_mermaid_and_json(self):
        source = 'echo test'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        mermaid = ASTVisualizer.render_mermaid(ast)
        self.assertIn('flowchart TD', mermaid)

        json_dump = ASTVisualizer.render_json(ast)
        self.assertIn('"node_type": "ScriptNode"', json_dump)


if __name__ == '__main__':
    unittest.main()
