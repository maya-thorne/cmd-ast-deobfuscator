"""
Benchmark Runner and Evaluation Engine for cmd-ast-deobfuscator.
Executes deobfuscation across the benchmark corpus, benchmarks execution performance,
evaluates ground-truth recovery, and generates Markdown and JSON reports.
"""

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from ..ast_nodes import ASTNode
from ..deobfuscator_engine import BatchDeobfuscator
from ..normalizer import ASTNormalizer
from ..parser import CmdASTParser
from ..transforms import PassManager
from .corpus import BenchmarkSample, get_benchmark_corpus
from .metrics import (
    ComplexityMetrics,
    SampleMetricResult,
    calculate_entropy,
    calculate_reduction_ratio,
    count_ast_nodes,
    count_tokens,
)


@dataclass
class BenchmarkSummary:
    """Consolidated summary statistics of a benchmark execution run."""
    engine: str
    total_samples: int = 0
    passed_samples: int = 0
    failed_samples: int = 0
    recovery_rate_pct: float = 0.0
    avg_char_reduction_pct: float = 0.0
    avg_token_reduction_pct: float = 0.0
    avg_node_reduction_pct: float = 0.0
    avg_entropy_drop_pct: float = 0.0
    total_time_ms: float = 0.0
    sample_results: List[SampleMetricResult] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Serializes summary to standard dictionary structure."""
        return {
            "engine": self.engine,
            "total_samples": self.total_samples,
            "passed_samples": self.passed_samples,
            "failed_samples": self.failed_samples,
            "recovery_rate_pct": self.recovery_rate_pct,
            "avg_char_reduction_pct": self.avg_char_reduction_pct,
            "avg_token_reduction_pct": self.avg_token_reduction_pct,
            "avg_node_reduction_pct": self.avg_node_reduction_pct,
            "avg_entropy_drop_pct": self.avg_entropy_drop_pct,
            "total_time_ms": round(self.total_time_ms, 2),
            "samples": [
                {
                    "sample_id": r.sample_id,
                    "name": r.name,
                    "category": r.category,
                    "success": r.success,
                    "time_ms": round(r.execution_time_ms, 2),
                    "char_reduction_pct": round(r.metrics.char_reduction_rate * 100, 1),
                    "token_reduction_pct": round(r.metrics.token_reduction_rate * 100, 1),
                    "node_reduction_pct": round(r.metrics.node_reduction_rate * 100, 1),
                    "entropy_reduction_pct": round(r.metrics.entropy_reduction_rate * 100, 1),
                    "recovered": r.recovered_indicators,
                    "missing": r.missing_indicators,
                }
                for r in self.sample_results
            ]
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes benchmark summary into formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Generates GitHub-flavored Markdown evaluation report."""
        lines = [
            f"# Real-World Batch Deobfuscation Benchmark Report (`{self.engine}` Engine)",
            "",
            "## Summary Metrics",
            "",
            f"- **Target Engine**: `{self.engine}`",
            f"- **Total Samples Evaluated**: {self.total_samples}",
            f"- **Ground-Truth Recovered**: {self.passed_samples} / {self.total_samples} ({self.recovery_rate_pct:.1f}%)",
            f"- **Mean Character Reduction**: {self.avg_char_reduction_pct:.1f}%",
            f"- **Mean Token Reduction**: {self.avg_token_reduction_pct:.1f}%",
            f"- **Mean AST Node Reduction**: {self.avg_node_reduction_pct:.1f}%",
            f"- **Mean Shannon Entropy Drop**: {self.avg_entropy_drop_pct:.1f}%",
            f"- **Total Execution Latency**: {self.total_time_ms:.2f} ms",
            "",
            "## Detailed Sample Results",
            "",
            "| ID | Sample Name | Category | Status | Time (ms) | Char Red. | Token Red. | Node Red. | Entropy Drop |",
            "|---|---|---|:---:|---:|---:|---:|---:|---:|",
        ]

        for r in self.sample_results:
            status_badge = "PASS" if r.success else "FAIL"
            m = r.metrics
            lines.append(
                f"| `{r.sample_id}` | {r.name} | {r.category} | {status_badge} | "
                f"{r.execution_time_ms:.2f} | {m.char_reduction_rate * 100:.1f}% | "
                f"{m.token_reduction_rate * 100:.1f}% | {m.node_reduction_rate * 100:.1f}% | "
                f"{m.entropy_reduction_rate * 100:.1f}% |"
            )

        lines.append("")
        return "\n".join(lines)


class BenchmarkRunner:
    """Executes the benchmark evaluation harness across specified engines."""
    def __init__(
        self,
        engine: str = "ast",
        corpus: Optional[List[BenchmarkSample]] = None
    ):
        self.engine = engine.lower()
        self.corpus = corpus or get_benchmark_corpus()
        self.pass_manager = PassManager.default_pipeline()
        self.automaton_engine = BatchDeobfuscator()
        self.normalizer = ASTNormalizer()

    def deobfuscate_ast(self, script: str) -> str:
        """Deobfuscates using recursive-descent AST parser and PassManager transforms."""
        parsed_ast = CmdASTParser.from_source(script).parse()
        normalized_ast = self.pass_manager.run(parsed_ast)
        return self.pass_manager.passes[0].to_source(normalized_ast)

    def deobfuscate_automaton(self, script: str) -> str:
        """Deobfuscates using pushdown automaton regex state machine."""
        return self.automaton_engine.deobfuscate(script)

    def run_sample(self, sample: BenchmarkSample, engine_override: Optional[str] = None) -> SampleMetricResult:
        """Runs benchmark evaluation against a single sample."""
        active_engine = (engine_override or self.engine).lower()
        raw_code = sample.raw_code

        # Baseline measurements
        orig_chars = len(raw_code)
        orig_tokens = count_tokens(raw_code)
        try:
            orig_ast = CmdASTParser.from_source(raw_code).parse()
            orig_nodes = count_ast_nodes(orig_ast)
        except Exception:
            orig_nodes = 0
        orig_entropy = calculate_entropy(raw_code)

        # Timed deobfuscation
        t_start = time.perf_counter()
        if active_engine == "automaton":
            deobf_text = self.deobfuscate_automaton(raw_code)
        else:
            deobf_text = self.deobfuscate_ast(raw_code)
        t_end = time.perf_counter()
        elapsed_ms = (t_end - t_start) * 1000.0

        # Post-deobfuscation measurements
        deobf_chars = len(deobf_text)
        deobf_tokens = count_tokens(deobf_text)
        try:
            deobf_ast = CmdASTParser.from_source(deobf_text).parse()
            deobf_nodes = count_ast_nodes(deobf_ast)
        except Exception:
            deobf_nodes = 0
        deobf_entropy = calculate_entropy(deobf_text)

        # Reduction ratios
        metrics = ComplexityMetrics(
            original_chars=orig_chars,
            deobfuscated_chars=deobf_chars,
            char_reduction_rate=calculate_reduction_ratio(orig_chars, deobf_chars),
            original_tokens=orig_tokens,
            deobfuscated_tokens=deobf_tokens,
            token_reduction_rate=calculate_reduction_ratio(orig_tokens, deobf_tokens),
            original_nodes=orig_nodes,
            deobfuscated_nodes=deobf_nodes,
            node_reduction_rate=calculate_reduction_ratio(orig_nodes, deobf_nodes),
            original_entropy=orig_entropy,
            deobfuscated_entropy=deobf_entropy,
            entropy_reduction_rate=calculate_reduction_ratio(
                int(orig_entropy * 10000), int(deobf_entropy * 10000)
            ) if orig_entropy > 0 else 0.0,
        )

        # Indicator recovery verification
        recovered: List[str] = []
        missing: List[str] = []
        clean_lower = deobf_text.lower()

        for ind in sample.expected_indicators:
            if ind.lower() in clean_lower:
                recovered.append(ind)
            else:
                missing.append(ind)

        success = (len(missing) == 0)

        return SampleMetricResult(
            sample_id=sample.sample_id,
            name=sample.name,
            category=sample.category,
            success=success,
            execution_time_ms=elapsed_ms,
            metrics=metrics,
            recovered_indicators=recovered,
            missing_indicators=missing,
            deobfuscated_text=deobf_text,
        )

    def run_all(self, engine_override: Optional[str] = None) -> BenchmarkSummary:
        """Executes benchmark evaluation across all corpus samples and generates summary."""
        active_engine = (engine_override or self.engine).lower()
        results: List[SampleMetricResult] = []
        total_time = 0.0

        for s in self.corpus:
            res = self.run_sample(s, engine_override=active_engine)
            results.append(res)
            total_time += res.execution_time_ms

        total = len(results)
        passed = sum(1 for r in results if r.success)
        failed = total - passed
        recovery_rate = (passed / total * 100.0) if total > 0 else 0.0

        avg_char = (sum(r.metrics.char_reduction_rate for r in results) / total * 100.0) if total > 0 else 0.0
        avg_token = (sum(r.metrics.token_reduction_rate for r in results) / total * 100.0) if total > 0 else 0.0
        avg_node = (sum(r.metrics.node_reduction_rate for r in results) / total * 100.0) if total > 0 else 0.0
        avg_entropy = (sum(r.metrics.entropy_reduction_rate for r in results) / total * 100.0) if total > 0 else 0.0

        return BenchmarkSummary(
            engine=active_engine,
            total_samples=total,
            passed_samples=passed,
            failed_samples=failed,
            recovery_rate_pct=round(recovery_rate, 2),
            avg_char_reduction_pct=round(avg_char, 2),
            avg_token_reduction_pct=round(avg_token, 2),
            avg_node_reduction_pct=round(avg_node, 2),
            avg_entropy_drop_pct=round(avg_entropy, 2),
            total_time_ms=total_time,
            sample_results=results,
        )
