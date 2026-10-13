"""
Benchmark and Evaluation Infrastructure for cmd-ast-deobfuscator.
Provides quantitative evaluation metrics (Shannon entropy, AST node count, token density),
curated real-world batch obfuscation corpus, and benchmark execution runners.
"""

from .metrics import (
    calculate_entropy,
    calculate_reduction_ratio,
    count_ast_nodes,
    count_tokens,
    ComplexityMetrics,
    SampleMetricResult,
)
from .corpus import (
    BenchmarkSample,
    get_benchmark_corpus,
    get_sample,
    get_categories,
)
from .runner import (
    BenchmarkRunner,
    BenchmarkSummary,
)

__all__ = [
    'calculate_entropy',
    'calculate_reduction_ratio',
    'count_ast_nodes',
    'count_tokens',
    'ComplexityMetrics',
    'SampleMetricResult',
    'BenchmarkSample',
    'get_benchmark_corpus',
    'get_sample',
    'get_categories',
    'BenchmarkRunner',
    'BenchmarkSummary',
]
