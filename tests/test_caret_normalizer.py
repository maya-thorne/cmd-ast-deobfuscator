"""
Comprehensive Unit Test Suite for Caret Normalization AST Transform (M04).
Validates normalize_carets function, CaretNormalizerPass visitor, quote boundaries,
nested escape reduction, PassManager default pipeline, and ConstantFolderPass integration.
"""

import unittest
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    ScriptNode, CommandNode, AssignmentNode, LiteralNode,
    VarExpandNode, RedirectNode, ChainNode, PipeNode, BlockNode, IfNode, ForNode
)
from src.transforms import (
    CaretNormalizerPass, ConstantFolderPass, SlicingFolderPass,
    PassManager, run_transforms, normalize_carets
)


class TestCaretNormalizer(unittest.TestCase):

    def setUp(self):
        self.pass_instance = CaretNormalizerPass()

    # -------------------------------------------------------------------------
    # 1. normalize_carets Function Tests
    # -------------------------------------------------------------------------
    def test_single_caret_unmasking(self):
        self.assertEqual(normalize_carets('c^a^l^c'), 'calc')
        self.assertEqual(normalize_carets('w^h^o^a^m^i /a^l^l'), 'whoami /all')
        self.assertEqual(normalize_carets('^s^e^t ^v^a^r=^v^a^l'), 'set var=val')

    def test_quoted_string_preservation(self):
        self.assertEqual(normalize_carets('"c^a^l^c"'), '"c^a^l^c"')
        self.assertEqual(normalize_carets('"quoted ^carets ^here"'), '"quoted ^carets ^here"')

    def test_mixed_quoted_and_unquoted(self):
        self.assertEqual(normalize_carets('"quoted ^caret" outside^caret'), '"quoted ^caret" outsidecaret')
        self.assertEqual(normalize_carets('c^m^d "keep ^this" ^/c'), 'cmd "keep ^this" /c')

    def test_escaped_quote_handling(self):
        # ^" emits a literal " without entering quote mode
        res = normalize_carets('^"c^a^l^c^"')
        self.assertEqual(res, '"calc"')

    def test_escaped_caret_pair(self):
        # ^^ outside quotes resolves to literal ^
        self.assertEqual(normalize_carets('^^'), '^')
        self.assertEqual(normalize_carets('echo ^^'), 'echo ^')

    def test_nested_multi_level_carets(self):
        # Multi-level carets should iteratively reduce down to canonical text
        self.assertEqual(normalize_carets('c^^^a^^^l^^^c'), 'calc')
        self.assertEqual(normalize_carets('^^^^c'), 'c')
        self.assertEqual(normalize_carets('s^^^^e^^^^t'), 'set')
        self.assertEqual(normalize_carets('^^^^^^^c'), 'c')

    def test_trailing_caret_stripping(self):
        self.assertEqual(normalize_carets('calc^'), 'calc')
        self.assertEqual(normalize_carets('whoami^', strip_trailing=True), 'whoami')
        self.assertEqual(normalize_carets('whoami^', strip_trailing=False), 'whoami^')

    def test_collapse_redundant_option(self):
        self.assertEqual(normalize_carets('^^^^', collapse_redundant=True), '^')

    def test_empty_and_no_carets(self):
        self.assertEqual(normalize_carets(''), '')
        self.assertEqual(normalize_carets('normal text'), 'normal text')

    # -------------------------------------------------------------------------
    # 2. LiteralNode Visitor Tests
    # -------------------------------------------------------------------------
    def test_literal_node_unquoted(self):
        node = LiteralNode(value='c^a^l^c', is_quoted=False)
        res = self.pass_instance.visit(node)
        self.assertIsInstance(res, LiteralNode)
        self.assertEqual(res.value, 'calc')
        self.assertTrue(self.pass_instance.modified)

    def test_literal_node_quoted(self):
        node = LiteralNode(value='c^a^l^c', is_quoted=True)
        res = self.pass_instance.visit(node)
        self.assertIsInstance(res, LiteralNode)
        self.assertEqual(res.value, 'c^a^l^c')
        self.assertFalse(self.pass_instance.modified)

    # -------------------------------------------------------------------------
    # 3. CommandNode Transformation & Coalescing Tests
    # -------------------------------------------------------------------------
    def test_command_node_target_normalization(self):
        source = 'c^a^l^c.e^x^e /a^r^g'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        cmd = transformed.statements[0]
        self.assertIsInstance(cmd, CommandNode)
        self.assertEqual(cmd.target, 'calc.exe')
        self.assertEqual(cmd.arguments[0].value, '/arg')

    def test_command_node_nested_carets(self):
        source = 'w^^^h^^^o^^^a^^^m^^^i /a^^^l^^^l'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        cmd = transformed.statements[0]
        self.assertEqual(cmd.target, 'whoami')
        self.assertEqual(cmd.arguments[0].value, '/all')

    def test_command_node_preserves_quoted_args(self):
        source = 'echo "hello ^world" o^u^t'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        normalizer = ASTNormalizer()
        out = normalizer.to_source(transformed)
        self.assertIn('hello ^world', out)
        self.assertIn('out', out)


    # -------------------------------------------------------------------------
    # 4. AssignmentNode Transformation Tests
    # -------------------------------------------------------------------------
    def test_assignment_node_unmasking(self):
        source = 'set v^a^r=c^a^l^c.e^x^e'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        assign = transformed.statements[0]
        self.assertIsInstance(assign, AssignmentNode)
        self.assertEqual(assign.var_name, 'var')
        self.assertEqual(assign.raw_value, 'calc.exe')
        self.assertIn('var', self.pass_instance.env)
        self.assertEqual(self.pass_instance.env['var'], 'calc.exe')

    def test_assignment_node_nested_carets(self):
        source = 'set TARGET=p^^^^o^^^^w^^^^e^^^^r^^^^s^^^^h^^^^e^^^^l^^^^l'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        assign = transformed.statements[0]
        self.assertEqual(assign.raw_value, 'powershell')
        self.assertEqual(self.pass_instance.env['target'], 'powershell')

    # -------------------------------------------------------------------------
    # 5. VarExpandNode Transformation Tests
    # -------------------------------------------------------------------------
    def test_var_expand_substitutions_with_carets(self):
        node = VarExpandNode(name='STR', sub_search='^old', sub_replace='^new')
        res = self.pass_instance.visit(node)
        self.assertIsInstance(res, VarExpandNode)
        self.assertEqual(res.sub_search, 'old')
        self.assertEqual(res.sub_replace, 'new')

    def test_var_expand_percent_variable_with_carets(self):
        node = VarExpandNode(name='v^a^r', is_delayed=False)
        res = self.pass_instance.visit(node)
        self.assertEqual(res.name, 'var')

    # -------------------------------------------------------------------------
    # 6. RedirectNode, IfNode & ForNode Tests
    # -------------------------------------------------------------------------
    def test_redirect_node_destination(self):
        red = RedirectNode(command=CommandNode(target='c^a^l^c'), destination='o^u^t.txt')
        transformed = self.pass_instance.visit(red)
        self.assertIsInstance(transformed, RedirectNode)
        self.assertEqual(transformed.destination, 'out.txt')
        self.assertEqual(transformed.command.target, 'calc')

    def test_if_node_condition_normalization(self):
        stmt = IfNode(condition='a^==^a', then_block=CommandNode(target='c^a^l^c'))
        transformed = self.pass_instance.visit(stmt)
        self.assertIsInstance(transformed, IfNode)
        self.assertEqual(transformed.condition, 'a==a')
        self.assertEqual(transformed.then_block.target, 'calc')

    def test_for_node_in_clause_normalization(self):
        stmt = ForNode(iterator='%%i', in_clause='( ^a ^b ^c )', body=CommandNode(target='c^a^l^c'))
        transformed = self.pass_instance.visit(stmt)
        self.assertIsInstance(transformed, ForNode)
        self.assertEqual(transformed.in_clause, '( a b c )')
        self.assertEqual(transformed.body.target, 'calc')


    # -------------------------------------------------------------------------
    # 7. Control Flow & Chaining (ChainNode, PipeNode, BlockNode)
    # -------------------------------------------------------------------------
    def test_chain_and_pipe_normalization(self):
        source = 'c^a^l^c & w^h^o^a^m^i | f^i^n^d "str"'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        chain = transformed.statements[0]
        self.assertIsInstance(chain, ChainNode)
        self.assertEqual(chain.left.target, 'calc')
        pipe = chain.right
        self.assertIsInstance(pipe, PipeNode)
        self.assertEqual(pipe.left.target, 'whoami')
        self.assertEqual(pipe.right.target, 'find')

    def test_block_node_normalization(self):
        source = '( c^a^l^c & w^h^o^a^m^i )'
        ast = CmdASTParser.from_source(source).parse()
        transformed = self.pass_instance.transform(ast)
        block = transformed.statements[0]
        self.assertIsInstance(block, BlockNode)
        self.assertEqual(len(block.statements), 1)
        chain = block.statements[0]
        self.assertEqual(chain.left.target, 'calc')
        self.assertEqual(chain.right.target, 'whoami')

    # -------------------------------------------------------------------------
    # 8. PassManager Default Pipeline & run_transforms Integration
    # -------------------------------------------------------------------------
    def test_pass_manager_default_pipeline_includes_caret_normalizer(self):
        pm = PassManager.default_pipeline()
        pass_names = [p.name for p in pm.passes]
        self.assertIn('CaretNormalizerPass', pass_names)
        self.assertIn('SlicingFolderPass', pass_names)
        self.assertIn('ConstantFolderPass', pass_names)
        # CaretNormalizerPass should be placed first
        self.assertEqual(pass_names[0], 'CaretNormalizerPass')

    def test_run_transforms_caret_and_slicing_co_optimization(self):
        source = 'set A=c^a^l^c\nset B=%A:~0,4%\necho %B%'
        ast = CmdASTParser.from_source(source).parse()
        res_ast = run_transforms(ast, max_iterations=10)
        normalizer = ASTNormalizer()
        out = normalizer.to_source(res_ast)
        self.assertIn('echo calc', out)

    def test_run_transforms_nested_carets_in_chained_commands(self):
        source = 's^^^^e^^^^t P=w^^^^h^^^^o^^^^a^^^^m^^^^i & %P% /a^^^^l^^^^l'
        ast = CmdASTParser.from_source(source).parse()
        res_ast = run_transforms(ast, max_iterations=10)
        normalizer = ASTNormalizer()
        out = normalizer.to_source(res_ast)
        self.assertIn('set P=whoami', out)
        self.assertIn('whoami /all', out)

    # -------------------------------------------------------------------------
    # 9. ConstantFolderPass Delegation to CaretNormalizerPass
    # -------------------------------------------------------------------------
    def test_constant_folder_delegates_to_caret_normalizer(self):
        cf = ConstantFolderPass()
        self.assertIsInstance(cf.caret_normalizer, CaretNormalizerPass)
        # Verify nested carets stripped through ConstantFolderPass
        source = 'c^^^a^^^l^^^c.e^^^x^^^e "arg^quoted"'
        ast = CmdASTParser.from_source(source).parse()
        res_ast = cf.transform(ast)
        cmd = res_ast.statements[0]
        self.assertEqual(cmd.target, 'calc.exe')
        self.assertEqual(cmd.arguments[0].value, '"arg^quoted"')

    # -------------------------------------------------------------------------
    # 10. Complex Obfuscated Script Scenarios
    # -------------------------------------------------------------------------
    def test_invoke_dosfuscation_style_caret_chain(self):
        script = (
            's^e^t ^"A=c^a^l^c^"\n'
            's^e^t ^"B=.e^x^e^"\n'
            '%A%%B%'
        )
        ast = CmdASTParser.from_source(script).parse()
        res_ast = run_transforms(ast, max_iterations=10)
        normalizer = ASTNormalizer()
        out = normalizer.to_source(res_ast)
        self.assertIn('set A=calc', out)
        self.assertIn('set B=.exe', out)
        self.assertIn('calc.exe', out)


if __name__ == '__main__':
    unittest.main()
