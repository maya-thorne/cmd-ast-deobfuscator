"""
Unit and Integration Test Suite for cmd.exe FOR Loop Variables & Parameter Expansion (M06).
Tests tokenization, parsing, AST node representations, path modifier resolution (~dp, ~f, ~nx, ~s, ~$PATH:),
and compiler-grade AST normalization & transform pass integration.
"""

import unittest
from src.lexer import CmdLexer, CmdToken, CmdTokenType
from src.parser import CmdASTParser
from src.ast_nodes import (
    ParamExpandNode, ForNode, CommandNode, AssignmentNode,
    LiteralNode, BlockNode, ScriptNode
)
from src.modifiers import parse_modifiers, PathModifierResolver, ModifierSpec
from src.normalizer import ASTNormalizer
from src.transforms.param_resolver import ParamResolverPass
from src.transforms.base import PassManager
from src.visualizer import ASTVisualizer


class TestForParamExpansion(unittest.TestCase):
    """Exhaustive test suite for FOR variables, script parameters, and path modifiers."""

    # -------------------------------------------------------------------------
    # 1. Lexer Tests
    # -------------------------------------------------------------------------
    def test_lex_positional_param(self):
        lexer = CmdLexer("echo %0 %1 %9 %*")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        param_tokens = [t for t in tokens if t.type == CmdTokenType.PARAM_VAR]
        self.assertEqual(len(param_tokens), 4)
        self.assertEqual([t.value for t in param_tokens], ['%0', '%1', '%9', '%*'])

    def test_lex_for_loop_variables(self):
        lexer = CmdLexer("for %%i in (*.txt) do echo %%i %%I %%a")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        for_tokens = [t for t in tokens if t.type == CmdTokenType.FOR_VAR]
        self.assertEqual(len(for_tokens), 4)
        self.assertEqual([t.value for t in for_tokens], ['%%i', '%%i', '%%I', '%%a'])

    def test_lex_param_modifiers(self):
        lexer = CmdLexer("%~dp0 %~f1 %~nx2 %~1 %~s1 %~$PATH:1")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        param_tokens = [t for t in tokens if t.type == CmdTokenType.PARAM_VAR]
        self.assertEqual(len(param_tokens), 6)
        self.assertEqual([t.value for t in param_tokens], [
            '%~dp0', '%~f1', '%~nx2', '%~1', '%~s1', '%~$PATH:1'
        ])

    def test_lex_for_var_modifiers(self):
        lexer = CmdLexer("%%~dpi %%~fI %%~nxa %%~$PATH:i %%~i")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        for_tokens = [t for t in tokens if t.type == CmdTokenType.FOR_VAR]
        self.assertEqual(len(for_tokens), 5)
        self.assertEqual([t.value for t in for_tokens], [
            '%%~dpi', '%%~fI', '%%~nxa', '%%~$PATH:i', '%%~i'
        ])

    def test_lex_escaped_double_percent(self):
        lexer = CmdLexer("echo 100%% %% done")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        lit_tokens = [t for t in tokens if t.value == '%%']
        self.assertEqual(len(lit_tokens), 2)
        self.assertTrue(all(t.type == CmdTokenType.LITERAL for t in lit_tokens))

    def test_lex_adjacent_params_and_literals(self):
        lexer = CmdLexer("%~dp0bin\\tool.exe")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        self.assertEqual(tokens[0].type, CmdTokenType.PARAM_VAR)
        self.assertEqual(tokens[0].value, '%~dp0')
        self.assertEqual(tokens[1].type, CmdTokenType.LITERAL)
        self.assertEqual(tokens[1].value, 'bin\\tool.exe')

    def test_lex_quoted_modifiers(self):
        lexer = CmdLexer('"%~dp0" "%1"')
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        param_vals = [t.value for t in tokens if t.type == CmdTokenType.PARAM_VAR]
        self.assertEqual(param_vals, ['%~dp0', '%1'])

    # -------------------------------------------------------------------------
    # 2. Parser Tests
    # -------------------------------------------------------------------------
    def test_parse_param_expand_node(self):
        parser = CmdASTParser.from_source("echo %1")
        ast = parser.parse()
        self.assertEqual(len(ast.statements), 1)
        cmd = ast.statements[0]
        self.assertIsInstance(cmd, CommandNode)
        self.assertEqual(len(cmd.arguments), 1)
        param_node = cmd.arguments[0]
        self.assertIsInstance(param_node, ParamExpandNode)
        self.assertEqual(param_node.name, '1')
        self.assertFalse(param_node.is_for_var)
        self.assertEqual(param_node.modifiers, "")
        self.assertFalse(param_node.strip_quotes)

    def test_parse_for_var_node(self):
        parser = CmdASTParser.from_source("echo %%i")
        ast = parser.parse()
        cmd = ast.statements[0]
        for_node = cmd.arguments[0]
        self.assertIsInstance(for_node, ParamExpandNode)
        self.assertEqual(for_node.name, 'i')
        self.assertTrue(for_node.is_for_var)
        self.assertEqual(for_node.modifiers, "")

    def test_parse_modified_parameter_node(self):
        parser = CmdASTParser.from_source("echo %~dp0")
        ast = parser.parse()
        cmd = ast.statements[0]
        param_node = cmd.arguments[0]
        self.assertIsInstance(param_node, ParamExpandNode)
        self.assertEqual(param_node.name, '0')
        self.assertFalse(param_node.is_for_var)
        self.assertEqual(param_node.modifiers, "~dp")
        self.assertTrue(param_node.strip_quotes)

    def test_parse_for_var_with_modifiers(self):
        parser = CmdASTParser.from_source("echo %%~nxA")
        ast = parser.parse()
        cmd = ast.statements[0]
        param_node = cmd.arguments[0]
        self.assertIsInstance(param_node, ParamExpandNode)
        self.assertEqual(param_node.name, 'A')
        self.assertTrue(param_node.is_for_var)
        self.assertEqual(param_node.modifiers, "~nx")
        self.assertTrue(param_node.strip_quotes)

    def test_parse_path_search_param(self):
        parser = CmdASTParser.from_source("echo %~$PATH:1")
        ast = parser.parse()
        cmd = ast.statements[0]
        param_node = cmd.arguments[0]
        self.assertIsInstance(param_node, ParamExpandNode)
        self.assertEqual(param_node.name, '1')
        self.assertEqual(param_node.path_var, "PATH")
        self.assertTrue(param_node.strip_quotes)

    def test_parse_simple_for_loop(self):
        parser = CmdASTParser.from_source("for %%i in (*.txt) do echo %%i")
        ast = parser.parse()
        self.assertEqual(len(ast.statements), 1)
        for_stmt = ast.statements[0]
        self.assertIsInstance(for_stmt, ForNode)
        self.assertEqual(for_stmt.iterator, "%%i")
        self.assertEqual(for_stmt.in_clause, "(*.txt)")
        self.assertIsInstance(for_stmt.body, CommandNode)
        self.assertEqual(for_stmt.body.target, "echo")

    def test_parse_for_f_options(self):
        parser = CmdASTParser.from_source('for /f "tokens=1,2" %%a in (data.csv) do echo %%a')
        ast = parser.parse()
        for_stmt = ast.statements[0]
        self.assertIsInstance(for_stmt, ForNode)
        self.assertEqual(for_stmt.flags, "/f")
        self.assertIn("tokens=1,2", for_stmt.options)
        self.assertEqual(for_stmt.iterator, "%%a")
        self.assertEqual(for_stmt.in_clause, "(data.csv)")

    def test_parse_for_block_body(self):
        parser = CmdASTParser.from_source("for %%i in (*) do ( echo %%i & calc )")
        ast = parser.parse()
        for_stmt = ast.statements[0]
        self.assertIsInstance(for_stmt, ForNode)
        self.assertIsInstance(for_stmt.body, BlockNode)

    # -------------------------------------------------------------------------
    # 3. Modifier Parsing & Path Resolution Tests
    # -------------------------------------------------------------------------
    def test_parse_modifiers_spec(self):
        spec = parse_modifiers("~dp")
        self.assertTrue(spec.strip_quotes)
        self.assertTrue(spec.drive)
        self.assertTrue(spec.path_dir)
        self.assertFalse(spec.name)
        self.assertFalse(spec.extension)

        spec_nx = parse_modifiers("~nx")
        self.assertTrue(spec_nx.name)
        self.assertTrue(spec_nx.extension)

        spec_search = parse_modifiers("~$PATH:")
        self.assertEqual(spec_search.search_var, "PATH")
        self.assertTrue(spec_search.strip_quotes)

    def test_unquote_modifier(self):
        spec = parse_modifiers("~")
        res = PathModifierResolver.resolve(spec, '"C:\\Program Files\\app"')
        self.assertEqual(res, "C:\\Program Files\\app")

    def test_drive_and_path_resolution(self):
        spec = parse_modifiers("~dp")
        res = PathModifierResolver.resolve(spec, r"C:\scripts\sub\tool.bat")
        self.assertEqual(res, "C:\\scripts\\sub\\")

    def test_name_and_extension_resolution(self):
        spec = parse_modifiers("~nx")
        res = PathModifierResolver.resolve(spec, r"C:\scripts\sub\tool.bat")
        self.assertEqual(res, "tool.bat")

    def test_drive_only_resolution(self):
        spec = parse_modifiers("~d")
        res = PathModifierResolver.resolve(spec, r"D:\data\file.csv")
        self.assertEqual(res, "D:")

    def test_path_only_resolution(self):
        spec = parse_modifiers("~p")
        res = PathModifierResolver.resolve(spec, r"C:\data\sub\file.csv")
        self.assertEqual(res, "\\data\\sub\\")

    def test_name_only_resolution(self):
        spec = parse_modifiers("~n")
        res = PathModifierResolver.resolve(spec, r"C:\data\sub\archive.tar.gz")
        self.assertEqual(res, "archive.tar")

    def test_extension_only_resolution(self):
        spec = parse_modifiers("~x")
        res = PathModifierResolver.resolve(spec, r"C:\data\sub\archive.tar.gz")
        self.assertEqual(res, ".gz")

    def test_full_path_relative_resolution(self):
        spec = parse_modifiers("~f")
        res = PathModifierResolver.resolve(spec, "file.txt", base_dir=r"C:\Users\Admin")
        self.assertEqual(res, r"C:\Users\Admin\file.txt")

    def test_short_path_83_resolution(self):
        spec = parse_modifiers("~s")
        res = PathModifierResolver.resolve(spec, r"C:\Program Files\LongFilename.txt")
        self.assertEqual(res, r"C:\PROGRA~1\LONGFI~1.TXT")

    def test_search_path_resolution(self):
        spec = parse_modifiers("~$PATH:")
        env = {'PATH': r"C:\Windows\System32;C:\Windows"}
        res = PathModifierResolver.resolve(spec, "cmd.exe", env=env)
        self.assertEqual(res, r"C:\Windows\System32\cmd.exe")

    def test_metadata_attributes_resolution(self):
        spec = parse_modifiers("~a")
        res = PathModifierResolver.resolve(spec, r"C:\test.txt", fs_metadata={'attributes': 'd---------'})
        self.assertEqual(res, "d---------")

    def test_metadata_size_and_timestamp(self):
        spec_z = parse_modifiers("~z")
        res_z = PathModifierResolver.resolve(spec_z, r"C:\test.txt", fs_metadata={'size': '2048'})
        self.assertEqual(res_z, "2048")

        spec_t = parse_modifiers("~t")
        res_t = PathModifierResolver.resolve(spec_t, r"C:\test.txt", fs_metadata={'timestamp': '2026-10-13 12:00'})
        self.assertEqual(res_t, "2026-10-13 12:00")

    # -------------------------------------------------------------------------
    # 4. AST Normalizer & Transform Pass Integration Tests
    # -------------------------------------------------------------------------
    def test_normalizer_resolves_param(self):
        normalizer = ASTNormalizer(
            params={'0': r"C:\tools\build.bat", '1': r"D:\data\input.csv"}
        )
        parser = CmdASTParser.from_source("echo %~dp0 and %~nx1")
        ast = parser.parse()
        normalized = normalizer.normalize(ast)
        src = normalizer.to_source(normalized)
        self.assertIn("C:\\tools\\", src)
        self.assertIn("input.csv", src)

    def test_normalizer_resolves_for_var(self):
        normalizer = ASTNormalizer(
            for_vars={'i': r"C:\Windows\System32\cmd.exe"}
        )
        parser = CmdASTParser.from_source("echo %%~nxi")
        ast = parser.parse()
        normalized = normalizer.normalize(ast)
        src = normalizer.to_source(normalized)
        self.assertIn("cmd.exe", src)

    def test_normalizer_leaves_unknown_params(self):
        normalizer = ASTNormalizer()
        parser = CmdASTParser.from_source("echo %~dp0 %1")
        ast = parser.parse()
        normalized = normalizer.normalize(ast)
        src = normalizer.to_source(normalized)
        self.assertIn("%~dp0", src)
        self.assertIn("%1", src)

    def test_param_resolver_pass_pipeline(self):
        pass_instance = ParamResolverPass(
            params={'0': r"C:\deploy\start.bat", '1': r"prod"}
        )
        parser = CmdASTParser.from_source("call %~dp0sub.bat %1")
        ast = parser.parse()
        transformed = pass_instance.transform(ast)
        self.assertTrue(pass_instance.modified)
        src = pass_instance.to_source(transformed)
        self.assertIn("C:\\deploy\\sub.bat", src)
        self.assertIn("prod", src)

    def test_param_resolver_pass_assignment(self):
        pass_instance = ParamResolverPass(
            params={'0': r"C:\apps\run.bat"}
        )
        parser = CmdASTParser.from_source("set SCRIPT_DIR=%~dp0")
        ast = parser.parse()
        transformed = pass_instance.transform(ast)
        src = pass_instance.to_source(transformed)
        self.assertIn("set SCRIPT_DIR=C:\\apps\\", src)

    def test_pass_manager_with_param_resolver(self):
        pm = PassManager()
        pm.add_pass(ParamResolverPass(params={'0': r"C:\proj\main.bat"}))
        parser = CmdASTParser.from_source("echo %~dp0")
        ast = parser.parse()
        optimized = pm.run(ast)
        normalizer = ASTNormalizer()
        src = normalizer.to_source(optimized)
        self.assertIn("C:\\proj\\", src)

    def test_to_source_roundtrip_for_loop(self):
        original = 'for /f "tokens=1,2" %%i in (data.txt) do echo %%~dpi'
        parser = CmdASTParser.from_source(original)
        ast = parser.parse()
        normalizer = ASTNormalizer()
        src = normalizer.to_source(ast)
        self.assertIn("for /f", src)
        self.assertIn("tokens=1,2", src)
        self.assertIn("%%i in (data.txt) do", src)
        self.assertIn("%%~dpi", src)

    def test_visualizer_renders_param_and_for(self):
        parser = CmdASTParser.from_source("for %%i in (*.txt) do echo %~dp0 %%i")
        ast = parser.parse()
        ascii_tree = ASTVisualizer.render_ascii_tree(ast)
        self.assertIn("ForNode", ascii_tree)
        self.assertIn("ParamExpandNode", ascii_tree)

        mermaid = ASTVisualizer.render_mermaid(ast)
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("ForNode", mermaid)

        json_dump = ASTVisualizer.render_json(ast)
        self.assertIn("ParamExpandNode", json_dump)
        self.assertIn("ForNode", json_dump)


if __name__ == '__main__':
    unittest.main()
