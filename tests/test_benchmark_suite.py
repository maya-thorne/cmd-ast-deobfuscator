"""
Unit and Integration Test Suite for cmd-ast-deobfuscator Benchmark Infrastructure.
Verifies Shannon entropy, AST node counting, reduction ratios, corpus integrity,
and 100% ground-truth recovery across real-world batch obfuscation techniques.
"""

import json
import unittest

from src.ast_nodes import CommandNode, LiteralNode, ScriptNode
from src.benchmark import (
    BenchmarkRunner,
    BenchmarkSummary,
    ComplexityMetrics,
    SampleMetricResult,
    calculate_entropy,
    calculate_reduction_ratio,
    count_ast_nodes,
    count_tokens,
    get_benchmark_corpus,
    get_categories,
    get_sample,
)
from src.parser import CmdASTParser


class TestBenchmarkMetrics(unittest.TestCase):
    """Verifies quantitative metric calculation routines."""

    def test_calculate_entropy_empty_and_uniform(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaaaa"), 0.0)
        # Two equally likely characters: entropy = 1.0
        self.assertAlmostEqual(calculate_entropy("abababab"), 1.0, places=2)

    def test_calculate_entropy_increases_with_randomness(self):
        simple = "echo hello world"
        obfuscated = "e^c^h^o %RANDOM:~0,1%%ALLUSERSPROFILE:~2,2%"
        self.assertGreater(calculate_entropy(obfuscated), calculate_entropy(simple))

    def test_calculate_reduction_ratio_bounds(self):
        self.assertEqual(calculate_reduction_ratio(100, 50), 0.5)
        self.assertEqual(calculate_reduction_ratio(100, 100), 0.0)
        self.assertEqual(calculate_reduction_ratio(50, 100), -1.0)
        self.assertEqual(calculate_reduction_ratio(0, 10), 0.0)

    def test_count_ast_nodes(self):
        self.assertEqual(count_ast_nodes(None), 0)
        ast = ScriptNode(statements=[
            CommandNode(
                target="whoami",
                target_nodes=[LiteralNode(value="whoami")],
                arguments=[LiteralNode(value="/all")]
            )
        ])
        # ScriptNode (1) + CommandNode (1) + Target LiteralNode (1) + Arg LiteralNode (1) = 4
        self.assertEqual(count_ast_nodes(ast), 4)

    def test_count_tokens(self):
        self.assertEqual(count_tokens(""), 0)
        tokens_count = count_tokens("whoami /all")
        self.assertGreater(tokens_count, 0)


class TestBenchmarkCorpus(unittest.TestCase):
    """Verifies benchmark corpus validity and accessor methods."""

    def test_corpus_count_and_uniqueness(self):
        corpus = get_benchmark_corpus()
        self.assertGreaterEqual(len(corpus), 12)
        sample_ids = [s.sample_id for s in corpus]
        self.assertEqual(len(sample_ids), len(set(sample_ids)), "Duplicate sample IDs found in corpus")

    def test_sample_structure(self):
        for s in get_benchmark_corpus():
            self.assertTrue(s.sample_id)
            self.assertTrue(s.name)
            self.assertTrue(s.category)
            self.assertTrue(s.raw_code)
            self.assertGreater(len(s.expected_indicators), 0)
            self.assertTrue(s.description)

    def test_get_sample_lookup(self):
        sample = get_sample("DOSFUSC_01_CARETS")
        self.assertIsNotNone(sample)
        self.assertEqual(sample.sample_id, "DOSFUSC_01_CARETS")

        # Case-insensitive lookup
        sample_lower = get_sample("dosfusc_01_carets")
        self.assertIsNotNone(sample_lower)

        # Non-existent sample
        self.assertIsNone(get_sample("NON_EXISTENT_ID"))

    def test_get_categories(self):
        cats = get_categories()
        self.assertIn("Invoke-DOSfuscation", cats)
        self.assertIn("0xidiz3r Pattern", cats)
        self.assertIn("Somalifuscator Pattern", cats)


class TestBenchmarkRunner(unittest.TestCase):
    """Verifies end-to-end benchmark execution, metrics compilation, and report formatting."""

    def setUp(self):
        self.runner_ast = BenchmarkRunner(engine="ast")
        self.runner_auto = BenchmarkRunner(engine="automaton")

    def test_ast_engine_100_percent_recovery(self):
        summary = self.runner_ast.run_all()
        self.assertEqual(summary.failed_samples, 0)
        self.assertEqual(summary.passed_samples, summary.total_samples)
        self.assertEqual(summary.recovery_rate_pct, 100.0)

    def test_automaton_engine_100_percent_recovery(self):
        summary = self.runner_auto.run_all()
        self.assertEqual(summary.failed_samples, 0)
        self.assertEqual(summary.passed_samples, summary.total_samples)
        self.assertEqual(summary.recovery_rate_pct, 100.0)

    def test_benchmark_markdown_report_formatting(self):
        summary = self.runner_ast.run_all()
        md = summary.to_markdown()
        self.assertIn("# Real-World Batch Deobfuscation Benchmark Report", md)
        self.assertIn("`ast` Engine", md)
        self.assertIn("100.0%", md)
        self.assertIn("DOSFUSC_01_CARETS", md)
        self.assertIn("PASS", md)

    def test_benchmark_json_serialization(self):
        summary = self.runner_ast.run_all()
        raw_json = summary.to_json()
        parsed = json.loads(raw_json)
        self.assertEqual(parsed["engine"], "ast")
        self.assertEqual(parsed["recovery_rate_pct"], 100.0)
        self.assertEqual(len(parsed["samples"]), 12)

    def test_individual_sample_evaluations(self):
        sample = get_sample("DOSFUSC_02_QUOTES")
        result = self.runner_ast.run_sample(sample)
        self.assertTrue(result.success)
        self.assertIn("cmd.exe", result.recovered_indicators)
        self.assertIn("whoami", result.recovered_indicators)
        self.assertIn("/all", result.recovered_indicators)
        self.assertGreater(result.metrics.char_reduction_rate, 0.0)


if __name__ == "__main__":
    unittest.main()
