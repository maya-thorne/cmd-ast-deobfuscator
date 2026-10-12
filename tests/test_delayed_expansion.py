"""
Comprehensive Unit Test Suite for Delayed Expansion (!VAR!) AST Tokenizer, Parser, and Normalizer.
Verifies Lexer tokens, AST VarExpandNode construction, slicing calculations, substitutions, caret escaping, and visualizer rendering.
"""

import unittest
from src.lexer import CmdLexer, CmdTokenType
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.visualizer import ASTVisualizer
from src.ast_nodes import VarExpandNode, LiteralNode, CommandNode, ScriptNode


class TestDelayedExpansionAST(unittest.TestCase):

    def test_lexer_delayed_expansion_basic(self):
        source = '!VAR! !ANOTHER_VAR!'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 2)
        self.assertEqual(exclam_tokens[0].value, '!VAR!')
        self.assertEqual(exclam_tokens[1].value, '!ANOTHER_VAR!')

    def test_lexer_delayed_expansion_slicing(self):
        source = '!VAR:~0,5! !VAR:~-3! !VAR:~-7,3! !VAR:~0,-2! !VAR:~-5,-2!'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 5)
        self.assertEqual(exclam_tokens[0].value, '!VAR:~0,5!')
        self.assertEqual(exclam_tokens[1].value, '!VAR:~-3!')
        self.assertEqual(exclam_tokens[2].value, '!VAR:~-7,3!')
        self.assertEqual(exclam_tokens[3].value, '!VAR:~0,-2!')
        self.assertEqual(exclam_tokens[4].value, '!VAR:~-5,-2!')

    def test_lexer_delayed_expansion_substitution(self):
        source = '!VAR:old=new! !VAR:foo=! !VAR: =_! !VAR:hello=world string!'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 4)
        self.assertEqual(exclam_tokens[0].value, '!VAR:old=new!')
        self.assertEqual(exclam_tokens[1].value, '!VAR:foo=!')
        self.assertEqual(exclam_tokens[2].value, '!VAR: =_!')
        self.assertEqual(exclam_tokens[3].value, '!VAR:hello=world string!')

    def test_lexer_escaped_caret_exclamation(self):
        # ^! should be tokenized as CARET token and NOT start delayed expansion
        source = 'echo ^!VAR! "^!"'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        caret_tokens = [t for t in tokens if t.type == CmdTokenType.CARET]
        self.assertEqual(len(caret_tokens), 2)
        self.assertEqual(caret_tokens[0].value, '^!')
        self.assertFalse(caret_tokens[0].in_quote)
        self.assertEqual(caret_tokens[1].value, '^!')
        self.assertTrue(caret_tokens[1].in_quote)

        # Ensure no EXCLAM_VAR was produced for ^!VAR!
        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 0)

    def test_lexer_caret_inside_delayed_expansion(self):
        source = '!VAR:old=^!!'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 1)
        self.assertEqual(exclam_tokens[0].value, '!VAR:old=^!!')

    def test_lexer_unclosed_exclamation(self):
        source = 'echo Hello! world'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 0)
        # The single exclamation should be preserved as literal '!'
        lit_exclam = [t for t in tokens if t.type == CmdTokenType.LITERAL and t.value == '!']
        self.assertEqual(len(lit_exclam), 1)

    def test_lexer_delayed_expansion_inside_quotes(self):
        source = '"!VAR!" "!VAR:~0,4!"'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 2)
        self.assertTrue(exclam_tokens[0].in_quote)
        self.assertEqual(exclam_tokens[0].value, '!VAR!')
        self.assertTrue(exclam_tokens[1].in_quote)
        self.assertEqual(exclam_tokens[1].value, '!VAR:~0,4!')

    def test_parser_delayed_expansion_node(self):
        source = 'echo !FOO!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        self.assertIsInstance(ast, ScriptNode)
        cmd_node = ast.statements[0]
        self.assertIsInstance(cmd_node, CommandNode)
        self.assertEqual(len(cmd_node.arguments), 1)

        arg = cmd_node.arguments[0]
        self.assertIsInstance(arg, VarExpandNode)
        self.assertEqual(arg.name, 'FOO')
        self.assertTrue(arg.is_delayed)
        self.assertIsNone(arg.slice_start)
        self.assertIsNone(arg.sub_search)

    def test_parser_delayed_expansion_slicing(self):
        source = 'echo !VAR:~2,4! !VAR:~-7,3! !VAR:~-3!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        cmd = ast.statements[0]
        args = cmd.arguments
        self.assertEqual(len(args), 3)

        self.assertTrue(args[0].is_delayed)
        self.assertEqual(args[0].name, 'VAR')
        self.assertEqual(args[0].slice_start, 2)
        self.assertEqual(args[0].slice_len, 4)

        self.assertTrue(args[1].is_delayed)
        self.assertEqual(args[1].name, 'VAR')
        self.assertEqual(args[1].slice_start, -7)
        self.assertEqual(args[1].slice_len, 3)

        self.assertTrue(args[2].is_delayed)
        self.assertEqual(args[2].name, 'VAR')
        self.assertEqual(args[2].slice_start, -3)
        self.assertIsNone(args[2].slice_len)

    def test_parser_delayed_expansion_substitution(self):
        source = 'echo !VAR:find=replace! !VAR:empty=!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        cmd = ast.statements[0]
        args = cmd.arguments
        self.assertEqual(len(args), 2)

        self.assertTrue(args[0].is_delayed)
        self.assertEqual(args[0].name, 'VAR')
        self.assertEqual(args[0].sub_search, 'find')
        self.assertEqual(args[0].sub_replace, 'replace')

        self.assertTrue(args[1].is_delayed)
        self.assertEqual(args[1].name, 'VAR')
        self.assertEqual(args[1].sub_search, 'empty')
        self.assertEqual(args[1].sub_replace, '')

    def test_parser_delayed_expansion_command_target(self):
        source = '!TARGET_CMD! /v /s'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        cmd = ast.statements[0]
        self.assertIsInstance(cmd, CommandNode)
        self.assertEqual(cmd.target, '!TARGET_CMD!')
        self.assertEqual(len(cmd.target_nodes), 1)
        self.assertIsInstance(cmd.target_nodes[0], VarExpandNode)
        self.assertTrue(cmd.target_nodes[0].is_delayed)
        self.assertEqual(cmd.target_nodes[0].name, 'TARGET_CMD')

    def test_parser_caret_escaped_exclamation_literal(self):
        source = 'echo ^!hello'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        cmd = ast.statements[0]
        # Should NOT contain VarExpandNode
        var_nodes = [a for a in cmd.arguments if isinstance(a, VarExpandNode)]
        self.assertEqual(len(var_nodes), 0)
        # Arguments should contain LiteralNode with unmasked '!'
        lit_nodes = [a for a in cmd.arguments if isinstance(a, LiteralNode)]
        self.assertTrue(any(a.value == '!' for a in lit_nodes))

    def test_normalizer_delayed_expansion_resolution(self):
        source = 'set MY_VAR=HelloDelayed\necho !MY_VAR!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo HelloDelayed', output)

    def test_normalizer_delayed_expansion_slicing_positive(self):
        source = 'set NUMS=0123456789\necho !NUMS:~3,4!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo 3456', output)

    def test_normalizer_delayed_expansion_slicing_negative_offset(self):
        source = '!COMSPEC:~-7,3!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertEqual(output.strip(), 'cmd')

    def test_normalizer_delayed_expansion_slicing_negative_length(self):
        source = 'set STR=0123456789\necho !STR:~0,-2!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo 01234567', output)

    def test_normalizer_delayed_expansion_slicing_both_negative(self):
        source = 'set STR=0123456789\necho !STR:~-5,-2!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo 567', output)

    def test_normalizer_delayed_expansion_substitution(self):
        source = 'set PHRASE=the quick brown fox\necho !PHRASE:quick=slow!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo the slow brown fox', output)

    def test_normalizer_delayed_expansion_wildcard_substitution(self):
        source = 'set FILEPATH=C:\\Windows\\System32\\calc.exe\necho !FILEPATH:*System32\\=!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo calc.exe', output)

    def test_normalizer_unresolved_delayed_expansion_serialization(self):
        # Unresolved delayed variables must serialize with !...! delimiters
        source = 'echo !UNRESOLVED! !UNRESOLVED:~0,3! !UNRESOLVED:foo=bar!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('!UNRESOLVED!', output)
        self.assertIn('!UNRESOLVED:~0,3!', output)
        self.assertIn('!UNRESOLVED:foo=bar!', output)
        # Verify it did NOT convert to %...%
        self.assertNotIn('%UNRESOLVED%', output)

    def test_normalizer_chained_assignment_delayed(self):
        source = 'set A=calc\nset B=!A!.exe\n!B!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('calc.exe', output)

    def test_visualizer_delayed_expansion_representation(self):
        source = 'echo !DELAYED_VAR:~1,2!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        tree_str = ASTVisualizer.render_ascii_tree(ast)
        self.assertIn('delayed=True', tree_str)
        self.assertIn("name='DELAYED_VAR'", tree_str)

        mermaid_str = ASTVisualizer.render_mermaid(ast)
        self.assertIn('delayed=True', mermaid_str)

        json_str = ASTVisualizer.render_json(ast)
        self.assertIn('"is_delayed": true', json_str)

    def test_lexer_unclosed_exclamation_inside_quotes_does_not_swallow(self):
        source = '"hello!world" and !VAR!'
        lexer = CmdLexer(source)
        tokens = lexer.tokenize()

        exclam_tokens = [t for t in tokens if t.type == CmdTokenType.EXCLAM_VAR]
        self.assertEqual(len(exclam_tokens), 1)
        self.assertEqual(exclam_tokens[0].value, '!VAR!')

        lit_exclam = [t for t in tokens if t.type == CmdTokenType.LITERAL and t.value == '!']
        self.assertEqual(len(lit_exclam), 1)
        self.assertTrue(lit_exclam[0].in_quote)

    def test_normalizer_chained_assignment_delayed_slicing(self):
        source = 'set A=HelloWorld\nset B=!A:~0,5!\necho !B!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo Hello', output)

    def test_normalizer_chained_assignment_delayed_substitution(self):
        source = 'set A=cat.exe\nset B=!A:cat=calc!\n!B!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('calc.exe', output)

    def test_normalizer_invalid_substitution_patterns_untouched(self):
        source = 'set VAR=abc\necho !VAR:=new!\necho !VAR:*=new!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('!VAR:=new!', output)
        self.assertIn('!VAR:*=new!', output)

    def test_normalizer_delayed_expansion_nested_percent_slicing(self):
        source = 'set OFFSET=2\nset STR=0123456789\necho !STR:~%OFFSET%,3!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo 234', output)

    def test_normalizer_delayed_expansion_dynamic_variable_name(self):
        source = 'set DYN=MYVAR\nset MYVAR=success\necho !%DYN%!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo success', output)

    def test_parser_and_normalizer_slicing_trailing_comma_zero_length(self):
        source = 'set A=0123456789\necho [!A:~1,!] [!A:~,!] [!A:~-2,!] [!A:~0,!] [!A:~!] [!A:~,4!]'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo [  ] [  ] [  ] [  ] [ 0123456789 ] [ 0123 ]', output)

    def test_normalizer_chained_assignment_nested_percent_slicing(self):
        source = 'set OFFSET=2\nset STR=0123456789\nset SUB=!STR:~%OFFSET%,3!\necho !SUB!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo 234', output)
        self.assertIn('set SUB=234', output)

    def test_normalizer_chained_assignment_dynamic_variable(self):
        source = 'set DYN=MYVAR\nset MYVAR=success\nset TARGET=!%DYN%!\necho !TARGET!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo success', output)
        self.assertIn('set TARGET=success', output)

    def test_normalizer_chained_assignment_nested_percent_substitution(self):
        source = 'set STR=apple pie\nset OLD=apple\nset NEW=orange\nset RES=!STR:%OLD%=%NEW%!\necho !RES!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo orange pie', output)
        self.assertIn('set RES=orange pie', output)

    def test_normalizer_unresolved_variable_with_resolved_nested_substitution_patterns(self):
        source = 'set OLD=apple\nset NEW=orange\necho !STR:%OLD%=%NEW%!'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        normalizer = ASTNormalizer()
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast)

        self.assertIn('echo !STR:apple=orange!', output)

    def test_visualizer_command_target_delayed_expansion(self):
        source = '!TARGET_CMD! /v /s'
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()

        tree_str = ASTVisualizer.render_ascii_tree(ast)
        self.assertIn('CommandNode', tree_str)
        self.assertIn('VarExpandNode', tree_str)
        self.assertIn("name='TARGET_CMD'", tree_str)
        self.assertIn('delayed=True', tree_str)

        mermaid_str = ASTVisualizer.render_mermaid(ast)
        self.assertIn('CommandNode', mermaid_str)
        self.assertIn('VarExpandNode', mermaid_str)
        self.assertIn('delayed=True', mermaid_str)

    def test_deobfuscator_engine_negative_offset_clamp_consistent(self):
        from src.deobfuscator_engine import BatchDeobfuscator
        engine = BatchDeobfuscator()
        engine.env_vars["s"] = "0123456789"
        res = engine.resolve_slicing("!s:~-15,3!")
        self.assertEqual(res, "012")

        res_norm = engine.resolve_slicing("!s:~-100,-2!")
        self.assertEqual(res_norm, "01234567")

    def test_deobfuscator_engine_wildcard_and_backslash_substitution(self):
        from src.deobfuscator_engine import BatchDeobfuscator
        engine = BatchDeobfuscator()
        engine.env_vars["filepath"] = r"C:\Windows\System32\calc.exe"
        res = engine.resolve_substitution(r"!filepath:*System32\=!")
        self.assertEqual(res, "calc.exe")

        engine.env_vars["path_var"] = "C:\\Windows\\dummy"
        res_backslash = engine.resolve_substitution(r"!path_var:dummy=\1!")
        self.assertEqual(res_backslash, "C:\\Windows\\\\1")

    def test_deobfuscator_engine_colon_in_substitution_pattern(self):
        from src.deobfuscator_engine import BatchDeobfuscator
        engine = BatchDeobfuscator()
        engine.env_vars["timestamp"] = "12:30:45"
        res = engine.resolve_substitution("!TIMESTAMP:12:30=14:00!")
        self.assertEqual(res, "14:00:45")


if __name__ == '__main__':
    unittest.main()
