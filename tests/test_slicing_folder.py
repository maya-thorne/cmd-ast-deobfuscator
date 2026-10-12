"""
Comprehensive Unit Test Suite for Substring Slicing (%VAR:~s,l%) Constant Folding Optimization Pass.
Verifies SlicingFolderPass, ConstantFolderPass, PassManager, and run_transforms across:
  - Positive, negative, clamped, and out-of-bounds start/length indices.
  - Omitted start, omitted length, omitted both, and trailing commas.
  - Explicit plus signs (+2, +3).
  - Whitespace around slice delimiters.
  - Nested variable resolution in slice parameters (%VAR:~%OFF%,%LEN%%).
  - Contiguous slice fusion/coalescing in target, arguments, and assignment values.
  - Full AST rewriting across CommandNode, AssignmentNode, BlockNode, ChainNode, PipeNode, RedirectNode.
  - Boundary conditions and fixed-point iteration convergence.
"""

import unittest
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    CommandNode, AssignmentNode, BlockNode, ChainNode,
    PipeNode, RedirectNode, ScriptNode, VarExpandNode,
    LiteralNode, IfNode, ForNode
)
from src.transforms import (
    TransformPass, PassManager, SlicingFolderPass,
    ConstantFolderPass, run_transforms
)


class TestSlicingFolderPass(unittest.TestCase):

    def setUp(self):
        self.env = {
            'comspec': r'C:\Windows\system32\cmd.exe',
            'msg': 'HelloWorld',
            'alpha': 'abcdefghijklmnopqrstuvwxyz',
            'digits': '0123456789',
        }
        self.slicing_pass = SlicingFolderPass(env=self.env)
        self.constant_pass = ConstantFolderPass(env=self.env)

    # -------------------------------------------------------------------------
    # 1. Direct _calculate_slice semantics
    # -------------------------------------------------------------------------
    def test_calculate_slice_positive_indices(self):
        folder = self.slicing_pass
        self.assertEqual(folder._calculate_slice('HelloWorld', 0, 5), 'Hello')
        self.assertEqual(folder._calculate_slice('HelloWorld', 5, 5), 'World')
        self.assertEqual(folder._calculate_slice('HelloWorld', 2, 3), 'llo')
        # Out-of-bounds length takes up to end of string
        self.assertEqual(folder._calculate_slice('HelloWorld', 0, 100), 'HelloWorld')
        # Start at or beyond length returns empty string
        self.assertEqual(folder._calculate_slice('HelloWorld', 10, 2), '')
        self.assertEqual(folder._calculate_slice('HelloWorld', 15, 2), '')
        # Length 0 returns empty string
        self.assertEqual(folder._calculate_slice('HelloWorld', 0, 0), '')

    def test_calculate_slice_negative_start(self):
        folder = self.slicing_pass
        # -3 takes last 3 characters when length is None
        self.assertEqual(folder._calculate_slice('HelloWorld', -3, None), 'rld')
        self.assertEqual(folder._calculate_slice('HelloWorld', -5, 3), 'Wor')
        # Negative clamp: when -start >= len, clamped to offset 0
        self.assertEqual(folder._calculate_slice('cmd', -10, None), 'cmd')
        self.assertEqual(folder._calculate_slice('cmd', -3, None), 'cmd')
        self.assertEqual(folder._calculate_slice('cmd', -10, 2), 'cm')
        self.assertEqual(folder._calculate_slice('Hello', -100, 3), 'Hel')

    def test_calculate_slice_negative_length(self):
        folder = self.slicing_pass
        # Negative length leaves off abs(length) from end
        self.assertEqual(folder._calculate_slice('HelloWorld', 0, -5), 'Hello')
        self.assertEqual(folder._calculate_slice('abcdef', 1, -2), 'bcd')
        self.assertEqual(folder._calculate_slice('abcdef', 2, -2), 'cd')
        # If end offset <= start offset, returns empty string
        self.assertEqual(folder._calculate_slice('abcdef', 4, -3), '')
        self.assertEqual(folder._calculate_slice('abcdef', 0, -10), '')
        # Negative start and negative length
        self.assertEqual(folder._calculate_slice('abcdef', -5, -2), 'bcd')
        self.assertEqual(folder._calculate_slice('abcdef', -2, -1), 'e')

    # -------------------------------------------------------------------------
    # 2. Omitted Delimiters (%VAR:~,l%, %VAR:~s,%, %VAR:~,%)
    # -------------------------------------------------------------------------
    def test_omitted_start_index(self):
        source = 'echo %MSG:~,5%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        self.assertIsInstance(transformed, ScriptNode)
        cmd = transformed.statements[0]
        self.assertIsInstance(cmd, CommandNode)
        self.assertEqual(cmd.arguments[0].value, 'Hello')

    def test_omitted_length_with_trailing_comma(self):
        # %VAR:~2,% has omitted length -> length=0 -> empty string
        source = 'echo [%MSG:~2,%]'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        # Sliced part is empty string
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertIn('echo []', out)

    def test_omitted_both_start_and_length(self):
        # %VAR:~,% has omitted both -> start=0, length=0 -> empty string
        source = 'echo [%MSG:~,%]'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertIn('echo []', out)

    def test_omitted_length_without_comma(self):
        # %VAR:~5% slices from 5 to end of string
        source = 'echo %MSG:~5%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'World')

    # -------------------------------------------------------------------------
    # 3. Explicit Plus Signs (+2, +3)
    # -------------------------------------------------------------------------
    def test_explicit_plus_signs(self):
        source = 'echo %MSG:~+2,+3%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'llo')

    def test_explicit_plus_start_only(self):
        source = 'echo %MSG:~+5%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'World')

    def test_explicit_plus_length_only(self):
        source = 'echo %MSG:~,+4%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'Hell')

    # -------------------------------------------------------------------------
    # 4. Whitespace around slice delimiters
    # -------------------------------------------------------------------------
    def test_whitespace_around_delimiters(self):
        source = 'echo %MSG:~ 2 , 3 %'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'llo')

    def test_whitespace_with_signed_indices(self):
        source = 'echo %MSG:~  -5 ,  +3 %'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'Wor')

    def test_whitespace_with_omitted_indices(self):
        source = 'echo [%MSG:~  ,  %]'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertIn('echo []', out)

    # -------------------------------------------------------------------------
    # 5. Nested Variable Resolution in Slice Parameters
    # -------------------------------------------------------------------------
    def test_nested_variables_start_and_length(self):
        # Environment pre-populated with OFF=2, LEN=3
        self.slicing_pass.env['off'] = '2'
        self.slicing_pass.env['len'] = '3'
        source = 'echo %MSG:~%OFF%,%LEN%%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'llo')

    def test_nested_variable_start_only(self):
        self.slicing_pass.env['off'] = '5'
        source = 'echo %MSG:~%OFF%,3%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'Wor')

    def test_nested_variable_length_only(self):
        self.slicing_pass.env['len'] = '4'
        source = 'echo %MSG:~0,%LEN%%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'Hell')

    def test_delayed_expansion_with_nested_percent_slice(self):
        self.slicing_pass.env['off'] = '2'
        self.slicing_pass.env['len'] = '3'
        source = 'echo !MSG:~%OFF%,%LEN%!'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'llo')

    def test_sequential_definition_and_nested_slice(self):
        # In a chained script, assignment defines OFF and LEN for subsequent slice
        source = 'set OFF=2 & set LEN=3 & echo %MSG:~%OFF%,%LEN%%'
        ast = CmdASTParser.from_source(source).parse()
        pm = PassManager([self.slicing_pass], max_iterations=5)
        transformed = pm.run(ast)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertIn('echo llo', out)

    # -------------------------------------------------------------------------
    # 6. Contiguous Slice Fusion / Coalescing
    # -------------------------------------------------------------------------
    def test_contiguous_slice_fusion_in_target(self):
        # %COMSPEC:~20,1% = 'c', %COMSPEC:~21,1% = 'm', %COMSPEC:~22,1% = 'd'
        source = '%COMSPEC:~20,1%%COMSPEC:~21,1%%COMSPEC:~22,1% /c whoami'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.target, 'cmd')
        self.assertEqual(len(cmd.target_nodes), 1)
        self.assertEqual(cmd.target_nodes[0].value, 'cmd')

    def test_slice_fused_with_adjacent_literal(self):
        source = 'c%COMSPEC:~21,1%d.exe'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.target, 'cmd.exe')

    def test_contiguous_slice_fusion_in_arguments(self):
        source = 'echo %ALPHA:~0,1%%ALPHA:~1,1%%ALPHA:~2,1%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(len(cmd.arguments), 1)
        self.assertEqual(cmd.arguments[0].value, 'abc')

    def test_separate_arguments_preserved_with_whitespace(self):
        # Arguments separated by spaces must NOT be coalesced
        source = 'echo %ALPHA:~0,2% %ALPHA:~2,2%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(len(cmd.arguments), 2)
        self.assertEqual(cmd.arguments[0].value, 'ab')
        self.assertEqual(cmd.arguments[1].value, 'cd')

    def test_contiguous_slice_fusion_in_assignment_value(self):
        source = 'set RESULT=%DIGITS:~0,1%%DIGITS:~1,1%%DIGITS:~2,1%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        assign = transformed.statements[0]
        self.assertIsInstance(assign, AssignmentNode)
        self.assertEqual(assign.raw_value, '012')
        self.assertEqual(self.slicing_pass.env['result'], '012')

    # -------------------------------------------------------------------------
    # 7. AST Rewriting across Composite Nodes
    # -------------------------------------------------------------------------
    def test_rewriting_across_chain_node(self):
        source = 'echo %MSG:~0,5% & echo %MSG:~5,5%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        self.assertIsInstance(transformed.statements[0], ChainNode)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertEqual(out, 'echo Hello & echo World')

    def test_rewriting_across_pipe_node(self):
        source = 'echo %MSG:~0,5% | findstr %MSG:~0,2%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        self.assertIsInstance(transformed.statements[0], PipeNode)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertEqual(out, 'echo Hello | findstr He')

    def test_rewriting_across_block_node(self):
        source = '( echo %MSG:~0,5% & echo %MSG:~5,5% )'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        self.assertIsInstance(transformed.statements[0], BlockNode)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertEqual(out, '(echo Hello & echo World)')

    def test_rewriting_across_redirect_node(self):
        cmd = CommandNode(target='echo', arguments=[VarExpandNode(name='MSG', slice_start=0, slice_len=5)])
        red = RedirectNode(command=cmd, stream='>', destination='%MSG:~5,5%.txt')
        script = ScriptNode(statements=[red])
        transformed = self.slicing_pass.transform(script)
        res_red = transformed.statements[0]
        self.assertEqual(res_red.command.arguments[0].value, 'Hello')
        self.assertEqual(res_red.destination, 'World.txt')

    def test_rewriting_across_if_node(self):
        then_cmd = CommandNode(target='echo', arguments=[VarExpandNode(name='MSG', slice_start=0, slice_len=5)])
        else_cmd = CommandNode(target='echo', arguments=[VarExpandNode(name='MSG', slice_start=5, slice_len=5)])
        if_node = IfNode(condition='1==1', then_block=then_cmd, else_block=else_cmd)
        script = ScriptNode(statements=[if_node])
        transformed = self.slicing_pass.transform(script)
        res_if = transformed.statements[0]
        self.assertEqual(res_if.then_block.arguments[0].value, 'Hello')
        self.assertEqual(res_if.else_block.arguments[0].value, 'World')

    def test_rewriting_across_for_node(self):
        body_cmd = CommandNode(target='echo', arguments=[VarExpandNode(name='MSG', slice_start=0, slice_len=5)])
        for_node = ForNode(iterator='%%i', in_clause='(1 2 3)', body=body_cmd)
        script = ScriptNode(statements=[for_node])
        transformed = self.slicing_pass.transform(script)
        res_for = transformed.statements[0]
        self.assertEqual(res_for.body.arguments[0].value, 'Hello')

    # -------------------------------------------------------------------------
    # 8. ConstantFolderPass (Slicing + Carets + Quotes + Substitutions)
    # -------------------------------------------------------------------------
    def test_constant_folder_full_suite(self):
        source = 'c^a^l^c.exe "quoted" "" & echo %MSG:~0,5% & set "X=%MSG:Hello=Heav%"'
        ast = CmdASTParser.from_source(source).parse()
        folder = ConstantFolderPass(env=self.env)
        transformed = folder.transform(ast)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(transformed)
        self.assertIn('calc.exe', out)
        self.assertIn('echo Hello', out)
        self.assertIn('set X=HeavWorld', out)

    # -------------------------------------------------------------------------
    # 9. Fixed-Point Iteration Convergence (PassManager & run_transforms)
    # -------------------------------------------------------------------------
    def test_fixed_point_chained_propagation(self):
        source = 'set A=calc.exe\nset B=%A:~0,4%\nset C=%B:~0,2%\necho %C%'
        ast = CmdASTParser.from_source(source).parse()
        res_ast = run_transforms(ast, env=self.env, max_iterations=10)
        normalizer = ASTNormalizer(self.env)
        out = normalizer.to_source(res_ast)
        self.assertIn('echo ca', out)

    # -------------------------------------------------------------------------
    # 10. Edge & Boundary Cases
    # -------------------------------------------------------------------------
    def test_unresolved_unknown_variable_preserved(self):
        source = 'echo %UNKNOWN:~0,4%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertIsInstance(cmd.arguments[0], VarExpandNode)
        self.assertEqual(cmd.arguments[0].name, 'UNKNOWN')

    def test_case_insensitive_variable_lookup(self):
        source = 'echo %msg:~0,5% %Msg:~5,5% %mSG:~0,2%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'Hello')
        self.assertEqual(cmd.arguments[1].value, 'World')
        self.assertEqual(cmd.arguments[2].value, 'He')

    def test_single_character_variable(self):
        self.slicing_pass.env['x'] = 'A'
        source = 'echo %X:~0,1% %X:~1,1% %X:~-1,1%'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.slicing_pass.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.arguments[0].value, 'A')
        self.assertEqual(cmd.arguments[1].value, '')
        self.assertEqual(cmd.arguments[2].value, 'A')


if __name__ == '__main__':
    unittest.main()
