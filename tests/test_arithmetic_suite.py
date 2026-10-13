"""
Comprehensive Unit and Integration Test Suite for cmd.exe Arithmetic Expression Evaluation
and AST Constant Folding Pass (M09).
"""

import unittest
from src.parser import CmdASTParser
from src.ast_nodes import AssignmentNode, CommandNode, LiteralNode, ScriptNode
from src.arithmetic.models import (
    NumberNode, VariableNode, UnaryOpNode, BinaryOpNode,
    AssignmentOpNode, SequenceNode, ArithmeticResult
)
from src.arithmetic.parser import ArithmeticParser, ArithmeticLexer, TokenType
from src.arithmetic.evaluator import CmdArithmeticEvaluator, evaluate_arithmetic, to_int32
from src.transforms.arithmetic_folder import ArithmeticFolderPass, fold_arithmetic
from src.transforms.base import PassManager


class TestArithmeticLexerParser(unittest.TestCase):
    """Unit tests for arithmetic lexing and recursive descent parsing."""

    def test_lexer_token_types(self):
        lexer = ArithmeticLexer("x = 0x10 + 020 - 5 * (y / 2) , z <<= 1")
        tokens = lexer.tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertIn(TokenType.IDENT, types)
        self.assertIn(TokenType.ASSIGN, types)
        self.assertIn(TokenType.NUMBER, types)
        self.assertIn(TokenType.BINARY_OP, types)
        self.assertIn(TokenType.LPAREN, types)
        self.assertIn(TokenType.RPAREN, types)
        self.assertIn(TokenType.COMMA, types)

    def test_parse_precedence_multiplication_over_addition(self):
        parser = ArithmeticParser("1 + 2 * 3")
        ast = parser.parse()
        self.assertIsInstance(ast, BinaryOpNode)
        self.assertEqual(ast.operator, "+")
        self.assertIsInstance(ast.left, NumberNode)
        self.assertEqual(ast.left.value, 1)
        self.assertIsInstance(ast.right, BinaryOpNode)
        self.assertEqual(ast.right.operator, "*")

    def test_parse_parentheses_grouping(self):
        parser = ArithmeticParser("(1 + 2) * 3")
        ast = parser.parse()
        self.assertIsInstance(ast, BinaryOpNode)
        self.assertEqual(ast.operator, "*")
        self.assertIsInstance(ast.left, BinaryOpNode)
        self.assertEqual(ast.left.operator, "+")

    def test_parse_unary_operators(self):
        parser = ArithmeticParser("-!~x")
        ast = parser.parse()
        self.assertIsInstance(ast, UnaryOpNode)
        self.assertEqual(ast.operator, "-")
        self.assertIsInstance(ast.operand, UnaryOpNode)
        self.assertEqual(ast.operand.operator, "!")
        self.assertIsInstance(ast.operand.operand, UnaryOpNode)
        self.assertEqual(ast.operand.operand.operator, "~")

    def test_parse_shifts_and_bitwise(self):
        parser = ArithmeticParser("1 << 2 | 3 & 4 ^ 5 >> 1")
        ast = parser.parse()
        # | has lowest precedence among bitwise
        self.assertIsInstance(ast, BinaryOpNode)
        self.assertEqual(ast.operator, "|")

    def test_parse_assignment_right_associative(self):
        parser = ArithmeticParser("a = b = 10")
        ast = parser.parse()
        self.assertIsInstance(ast, AssignmentOpNode)
        self.assertEqual(ast.target, "a")
        self.assertIsInstance(ast.value, AssignmentOpNode)
        self.assertEqual(ast.value.target, "b")

    def test_parse_comma_sequence(self):
        parser = ArithmeticParser("a = 1, b = 2, c = 3")
        ast = parser.parse()
        self.assertIsInstance(ast, SequenceNode)
        self.assertEqual(len(ast.expressions), 3)


class TestArithmeticEvaluator(unittest.TestCase):
    """Unit tests for CmdArithmeticEvaluator 32-bit math and semantics."""

    def setUp(self):
        self.evaluator = CmdArithmeticEvaluator()

    def test_basic_arithmetic(self):
        res = self.evaluator.evaluate("10 + 20 * 3 - 5")
        self.assertEqual(res.value, 65)

    def test_parentheses_evaluation(self):
        res = self.evaluator.evaluate("(10 + 20) * (5 - 3)")
        self.assertEqual(res.value, 60)

    def test_integer_division_truncates_toward_zero(self):
        self.assertEqual(self.evaluator.evaluate("7 / 2").value, 3)
        self.assertEqual(self.evaluator.evaluate("-7 / 2").value, -3)
        self.assertEqual(self.evaluator.evaluate("7 / -2").value, -3)
        self.assertEqual(self.evaluator.evaluate("-7 / -2").value, 3)

    def test_modulus_sign_follows_numerator(self):
        self.assertEqual(self.evaluator.evaluate("7 % 3").value, 1)
        self.assertEqual(self.evaluator.evaluate("-7 % 3").value, -1)
        self.assertEqual(self.evaluator.evaluate("7 % -3").value, 1)
        self.assertEqual(self.evaluator.evaluate("-7 % -3").value, -1)

    def test_division_and_modulus_by_zero_safety(self):
        # Must return 0 without raising ZeroDivisionError
        self.assertEqual(self.evaluator.evaluate("100 / 0").value, 0)
        self.assertEqual(self.evaluator.evaluate("100 % 0").value, 0)

    def test_32bit_signed_overflow_and_underflow(self):
        # Max 32-bit signed int + 1 wraps to -2147483648
        res_max = self.evaluator.evaluate("2147483647 + 1")
        self.assertEqual(res_max.value, -2147483648)

        # Min 32-bit signed int - 1 wraps to 2147483647
        res_min = self.evaluator.evaluate("-2147483648 - 1")
        self.assertEqual(res_min.value, 2147483647)

    def test_number_bases(self):
        self.assertEqual(self.evaluator.evaluate("0x10 + 0x20").value, 48)
        self.assertEqual(self.evaluator.evaluate("010 + 020").value, 24)  # octal 8 + 16 = 24
        self.assertEqual(self.evaluator.evaluate("0x7f").value, 127)

    def test_bitwise_operations(self):
        self.assertEqual(self.evaluator.evaluate("0xFF & 0x0F").value, 15)
        self.assertEqual(self.evaluator.evaluate("0xAA ^ 0x55").value, 255)
        self.assertEqual(self.evaluator.evaluate("0xF0 | 0x0F").value, 255)
        self.assertEqual(self.evaluator.evaluate("~0").value, -1)
        self.assertEqual(self.evaluator.evaluate("~1").value, -2)

    def test_logical_not(self):
        self.assertEqual(self.evaluator.evaluate("!0").value, 1)
        self.assertEqual(self.evaluator.evaluate("!1").value, 0)
        self.assertEqual(self.evaluator.evaluate("!42").value, 0)
        self.assertEqual(self.evaluator.evaluate("!-5").value, 0)

    def test_shifts_and_masking(self):
        self.assertEqual(self.evaluator.evaluate("1 << 4").value, 16)
        self.assertEqual(self.evaluator.evaluate("32 >> 2").value, 8)
        self.assertEqual(self.evaluator.evaluate("-16 >> 2").value, -4)  # arithmetic right shift
        self.assertEqual(self.evaluator.evaluate("1 << 36").value, 16)   # 36 & 31 = 4

    def test_compound_assignments(self):
        res = self.evaluator.evaluate("a = 10, a += 5, a *= 2, a -= 6, a /= 3")
        self.assertEqual(res.value, 8)
        self.assertEqual(res.assignments['a'], 8)

    def test_compound_bitwise_assignments(self):
        res = self.evaluator.evaluate("x = 1, x <<= 3, x |= 2, x &= 7")
        self.assertEqual(res.value, 2)
        self.assertEqual(res.assignments['x'], 2)

    def test_chained_assignment(self):
        res = self.evaluator.evaluate("x = y = z = 42")
        self.assertEqual(res.value, 42)
        self.assertEqual(res.assignments['x'], 42)
        self.assertEqual(res.assignments['y'], 42)
        self.assertEqual(res.assignments['z'], 42)

    def test_undefined_variable_defaults_to_zero(self):
        res = self.evaluator.evaluate("undef_var + 10")
        self.assertEqual(res.value, 10)

    def test_environment_variable_resolution(self):
        env = {'offset': '15', 'scale': '0x10', 'delta': '-3'}
        res = self.evaluator.evaluate("offset * scale + delta", env=env)
        self.assertEqual(res.value, 15 * 16 - 3)

    def test_percent_and_delayed_variable_tokens(self):
        env = {'base': '100', 'step': '25'}
        res = self.evaluator.evaluate("%base% + !step!", env=env)
        self.assertEqual(res.value, 125)

    def test_recursive_variable_resolution_and_cycle_guard(self):
        # Indirect expression in variable
        env = {'expr': '5 * 4', 'final': 'expr + 2'}
        res = self.evaluator.evaluate("final", env=env)
        self.assertEqual(res.value, 22)

        # Cyclic reference safety guard (must not freeze)
        cyclic_env = {'a': 'b + 1', 'b': 'a + 1'}
        res_cyclic = self.evaluator.evaluate("a", env=cyclic_env)
        self.assertIsInstance(res_cyclic.value, int)


class TestArithmeticFolderPass(unittest.TestCase):
    """Unit tests for AST ArithmeticFolderPass and optimization pipeline."""

    def test_fold_single_assignment(self):
        ast = CmdASTParser.from_source("set /a x=10+20*3").parse()
        folder = ArithmeticFolderPass()
        folded = folder.transform(ast)
        self.assertTrue(folder.modified)
        self.assertIsInstance(folded, ScriptNode)
        stmt = folded.statements[0]
        self.assertIsInstance(stmt, AssignmentNode)
        self.assertEqual(stmt.var_name, "x")
        self.assertEqual(stmt.raw_value, "70")
        self.assertEqual(folder.env['x'], "70")

    def test_fold_multi_assignment_sequence(self):
        ast = CmdASTParser.from_source('set /a "a=1+2, b=a*3, c=b-4"').parse()
        folder = ArithmeticFolderPass()
        folded = folder.transform(ast)
        self.assertTrue(folder.modified)
        stmt = folded.statements[0]
        self.assertIsInstance(stmt, AssignmentNode)
        self.assertEqual(folder.env['a'], "3")
        self.assertEqual(folder.env['b'], "9")
        self.assertEqual(folder.env['c'], "5")

    def test_decompose_multi_assignment(self):
        ast = CmdASTParser.from_source('set /a "a=1+2, b=4*5"').parse()
        folder = ArithmeticFolderPass(decompose_multi=True)
        folded = folder.transform(ast)
        self.assertIsInstance(folded, ScriptNode)
        self.assertEqual(len(folded.statements), 2)
        self.assertEqual(folded.statements[0].var_name, "a")
        self.assertEqual(folded.statements[0].raw_value, "3")
        self.assertEqual(folded.statements[1].var_name, "b")
        self.assertEqual(folded.statements[1].raw_value, "20")

    def test_fold_pure_arithmetic_without_assignment(self):
        ast = CmdASTParser.from_source("set /a 100 / 4").parse()
        folder = ArithmeticFolderPass()
        folded = folder.transform(ast)
        stmt = folded.statements[0]
        self.assertIsInstance(stmt, AssignmentNode)
        self.assertEqual(stmt.var_name, "")
        self.assertEqual(stmt.raw_value, "25")

    def test_fold_with_caret_and_quote_escapes(self):
        src = 'set /a "val=1^^^&2, shift=2<<2, flag=1^|2"'
        ast = CmdASTParser.from_source(src).parse()
        folder = ArithmeticFolderPass()
        folder.transform(ast)
        self.assertEqual(folder.env['val'], "0")    # 1 & 2 = 0
        self.assertEqual(folder.env['shift'], "8")  # 2 << 2 = 8
        self.assertEqual(folder.env['flag'], "3")   # 1 | 2 = 3

    def test_propagation_into_substring_slicing(self):
        src = (
            "set /a start=10-8, len=2+1\n"
            "set PAYLOAD=ABCDEFGHIJ\n"
            "echo %PAYLOAD:~%start%,%len%%"
        )
        ast = CmdASTParser.from_source(src).parse()
        pm = PassManager.default_pipeline()
        optimized = pm.run(ast)
        code = pm.passes[0].to_source(optimized)
        self.assertIn("CDE", code)

    def test_command_node_fallback_folding(self):
        cmd = CommandNode(target="set", arguments=[LiteralNode(value="/a"), LiteralNode(value="k=4*5")])
        folder = ArithmeticFolderPass()
        folded = folder.visit(cmd)
        self.assertIsInstance(folded, AssignmentNode)
        self.assertEqual(folded.var_name, "k")
        self.assertEqual(folded.raw_value, "20")

    def test_telemetry_metrics(self):
        src = "set /a a=1+2, b=a*3\nset /a c=b+4"
        ast = CmdASTParser.from_source(src).parse()
        folder = ArithmeticFolderPass()
        folder.transform(ast)
        self.assertGreaterEqual(folder.metrics.expressions_evaluated, 2)
        self.assertGreaterEqual(folder.metrics.assignments_folded, 3)
        self.assertGreaterEqual(folder.metrics.operators_evaluated, 3)

    def test_real_world_obfuscation_payload(self):
        # Obfuscation pattern generating char codes: 99 ('c'), 109 ('m'), 100 ('d')
        src = (
            'set /a "c1=0x60+3, c2=0x60+13, c3=0x60+4"\n'
            'set /a junk=123*456+789\n'
            'echo %c1% %c2% %c3%'
        )
        ast = CmdASTParser.from_source(src).parse()
        pm = PassManager.optimization_pipeline()
        optimized = pm.run(ast)
        code = pm.passes[0].to_source(optimized)
        self.assertIn("99 109 100", code)
        # Verify dead store 'junk' was eliminated by DCE
        self.assertNotIn("junk", code)


if __name__ == "__main__":
    unittest.main()
