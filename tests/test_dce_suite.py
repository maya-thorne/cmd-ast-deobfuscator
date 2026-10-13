"""
Unit and Integration Test Suite for Dead Code Elimination (DCE) and SET Pruning Pass.
Verifies:
  - Unreferenced variable assignment pruning (single, multiple, transitive/chained)
  - Referenced variable preservation (%VAR%, !VAR!, dynamic lookups, slices, substitutions)
  - Conditional branch reference tracking (IF DEFINED, IF NOT DEFINED, comparisons)
  - Control flow references (dynamic GOTO, dynamic CALL, FOR loops, Redirections)
  - Arithmetic expression variable tracking (set /a without percent signs)
  - Consecutive overwrite dead store elimination (with and without intervening reads/barriers)
  - Unreachable statement pruning after unconditional exit and goto
  - Empty parenthesized block and redundant chain pruning
  - Configurable preserve_vars and system variable defaults
  - DCEMetrics reporting and summary statistics
  - ASTNormalizer and PassManager integration
"""

import unittest
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    CommandNode, AssignmentNode, BlockNode, ChainNode,
    ScriptNode, VarExpandNode, LiteralNode, LabelNode,
    GotoNode, ExitNode, IfNode, ForNode
)
from src.transforms import (
    PassManager, DeadCodeEliminationPass, VariableLivenessAnalyzer,
    DCEMetrics, eliminate_dead_code
)


class TestDeadCodeEliminationSuite(unittest.TestCase):

    def test_unreferenced_single_variable_pruned(self):
        source = "set NOISE=9872134 & whoami"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast).strip()
        self.assertEqual(output, "whoami")
        self.assertEqual(dce.metrics.pruned_assignments, 1)
        self.assertIn("NOISE", dce.metrics.pruned_variable_names)

    def test_referenced_variable_preserved(self):
        source = "set TARGET=calc.exe\n%TARGET%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set TARGET=calc.exe", output)
        self.assertIn("%TARGET%", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_case_insensitive_variable_reference(self):
        source = "set MyPayload=whoami /all\n%mYpAyLoAd%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set MyPayload=whoami /all", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_delayed_expansion_variable_preserved(self):
        source = "set MSG=secret\necho !MSG!"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set MSG=secret", output)
        self.assertIn("echo !MSG!", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_transitive_chained_dead_code_elimination(self):
        # a is used by b, b is used by c, but c is never used!
        # Iterative fixed-point DCE should eliminate c, then b, then a.
        source = "set a=1\nset b=%a%\nset c=%b%\necho done"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast).strip()
        self.assertEqual(output, "echo done")
        self.assertEqual(dce.metrics.pruned_assignments, 3)
        self.assertGreaterEqual(dce.metrics.iterations, 2)

    def test_transitive_partially_used_variables(self):
        # a is used by b, b is used by echo, c uses b but c is never used
        source = "set a=1\nset b=%a%\nset c=%b%\necho %b%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set a=1", output)
        self.assertIn("set b=%a%", output)
        self.assertNotIn("set c=", output)
        self.assertEqual(dce.metrics.pruned_assignments, 1)

    def test_variable_in_if_condition_defined(self):
        source = "set FLAG=1\nif defined FLAG echo yes"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set FLAG=1", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_if_condition_comparison(self):
        source = "set MODE=debug\nif \"%MODE%\"==\"debug\" echo ok"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set MODE=debug", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_substring_slice(self):
        source = "set STR=HelloWorld\necho %STR:~0,5%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set STR=HelloWorld", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_substitution(self):
        source = "set DATA=hello_world\necho %DATA:world=there%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set DATA=hello_world", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_for_in_clause(self):
        source = "set ITEM_LIST=foo bar baz\nfor %%i in (%ITEM_LIST%) do echo %%i"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set ITEM_LIST=foo bar baz", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_dynamic_goto(self):
        source = "set STAGE=next\ngoto :%STAGE%\n:next\necho reached"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set STAGE=next", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_dynamic_call(self):
        source = "set PROC=worker\ncall :!PROC!\n:worker\nexit /b"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set PROC=worker", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_variable_in_redirection_destination(self):
        source = "set LOGFILE=test.log\necho info > %LOGFILE%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set LOGFILE=test.log", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_preserve_vars_explicit_configuration(self):
        source = "set EXPORTED_VAR=special_output\necho done"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass(preserve_vars={"exported_var"})
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set EXPORTED_VAR=special_output", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)

    def test_default_preserve_system_variables(self):
        source = "set PATH=C:\\custom;%PATH%\necho done"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        # PATH is in DEFAULT_PRESERVE_VARS
        self.assertIn("set PATH=", output)

    def test_dead_store_consecutive_overwrite_eliminated(self):
        source = "set X=obsolete_val\nset X=final_val\necho %X%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertNotIn("obsolete_val", output)
        self.assertIn("set X=final_val", output)
        self.assertIn("echo %X%", output)
        self.assertEqual(dce.metrics.pruned_overwrites, 1)

    def test_store_read_then_overwrite_preserved(self):
        source = "set X=first\necho %X%\nset X=second\necho %X%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set X=first", output)
        self.assertIn("set X=second", output)
        self.assertEqual(dce.metrics.pruned_overwrites, 0)

    def test_dead_store_across_label_preserved(self):
        source = "set X=initial\n:retry\nset X=updated\necho %X%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        # Because :retry is a label barrier, initial should NOT be eliminated
        self.assertIn("set X=initial", output)
        self.assertIn("set X=updated", output)

    def test_unreachable_code_after_exit_pruned(self):
        source = "exit /b 0\necho unreachable 1\nset dead_var=99\n:next_stage\necho alive"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("exit /b 0", output)
        self.assertNotIn("unreachable 1", output)
        self.assertNotIn("dead_var=99", output)
        self.assertIn(":next_stage", output)
        self.assertIn("echo alive", output)
        self.assertEqual(dce.metrics.pruned_unreachable, 2)

    def test_unreachable_code_after_goto_pruned(self):
        source = "goto :target\necho dead_command\nset junk=1\n:target\necho success"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("goto :target", output)
        self.assertNotIn("dead_command", output)
        self.assertNotIn("junk=1", output)
        self.assertIn(":target", output)
        self.assertIn("echo success", output)
        self.assertEqual(dce.metrics.pruned_unreachable, 2)

    def test_empty_block_pruned(self):
        source = "set UNUSED=1 & ( set DEAD=2 ) & whoami"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast).strip()
        self.assertEqual(output, "whoami")
        self.assertGreaterEqual(dce.metrics.pruned_empty_blocks, 1)

    def test_dce_metrics_summary(self):
        source = "set NOISE=123\nexit\necho dead"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        dce.transform(ast)

        m = dce.metrics
        self.assertGreater(m.total_pruned, 0)
        self.assertIn("Total pruned items", m.summary())
        dict_rep = m.to_dict()
        self.assertIn("pruned_assignments", dict_rep)
        self.assertIn("pruned_unreachable", dict_rep)

    def test_arithmetic_assignment_uses_tracking(self):
        # set /a c=a+b uses a and b without percent signs
        source = "set a=10\nset b=20\nset /a c=a+b\necho %c%"
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertIn("set a=10", output)
        self.assertIn("set b=20", output)
        self.assertIn("set /a c=a+b", output)
        self.assertEqual(dce.metrics.pruned_assignments, 0)


    def test_complex_0xidiz3r_dead_noise_elimination(self):
        source = (
            'set noise1=junk1\n'
            'set p1=po\n'
            'set noise2=junk2\n'
            'set p2=wer\n'
            'set noise3=junk3\n'
            'set p3=shell\n'
            '%p1%%p2%%p3% -NoProfile'
        )
        ast = CmdASTParser.from_source(source).parse()
        dce = DeadCodeEliminationPass()
        cleaned_ast = dce.transform(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned_ast)
        self.assertNotIn("noise1", output)
        self.assertNotIn("noise2", output)
        self.assertNotIn("noise3", output)
        self.assertIn("set p1=po", output)
        self.assertIn("set p2=wer", output)
        self.assertIn("set p3=shell", output)
        self.assertEqual(dce.metrics.pruned_assignments, 3)

    def test_pass_manager_optimization_pipeline(self):
        source = 'set NOISE=999\nset CMD=calc\n%CMD%'
        ast = CmdASTParser.from_source(source).parse()
        pm = PassManager.optimization_pipeline()
        opt_ast = pm.run(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(opt_ast)
        self.assertNotIn("NOISE", output)
        self.assertIn("calc", output)

    def test_normalizer_dce_flag_integration(self):
        source = "set DEAD_VAR=xyz\necho hello"
        ast = CmdASTParser.from_source(source).parse()
        normalizer = ASTNormalizer(dce=True)
        norm_ast = normalizer.normalize(ast)
        output = normalizer.to_source(norm_ast).strip()

        self.assertEqual(output, "echo hello")

    def test_eliminate_dead_code_convenience_function(self):
        source = "set DEAD=1 & dir"
        ast = CmdASTParser.from_source(source).parse()
        cleaned = eliminate_dead_code(ast)

        normalizer = ASTNormalizer()
        output = normalizer.to_source(cleaned).strip()
        self.assertEqual(output, "dir")


if __name__ == '__main__':
    unittest.main()
