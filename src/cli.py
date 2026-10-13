"""
CLI Entry point for cmd-ast-deobfuscator.
Supports parsing, AST tree inspection, Mermaid flowchart generation, and code reduction.
"""

import argparse
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.parser import CmdASTParser
    from src.normalizer import ASTNormalizer
    from src.visualizer import ASTVisualizer
    from src.benchmark import BenchmarkRunner
    from src.cfg import CFGBuilder, JumpTableResolver, CFGVisualizer
else:
    from .parser import CmdASTParser
    from .normalizer import ASTNormalizer
    from .visualizer import ASTVisualizer
    from .benchmark import BenchmarkRunner
    from .cfg import CFGBuilder, JumpTableResolver, CFGVisualizer


def main():
    parser = argparse.ArgumentParser(
        description="cmd-ast-deobfuscator: Compiler-Grade AST Parser & Pushdown Automaton for cmd.exe scripts."
    )
    parser.add_argument("-i", "--input", help="Path to input batch script (.bat / .cmd)")
    parser.add_argument("-o", "--output", help="Path to save normalized output script")
    parser.add_argument("--tree", action="store_true", help="Print ASCII Abstract Syntax Tree")
    parser.add_argument("--mermaid", action="store_true", help="Print Mermaid flowchart syntax of the AST")
    parser.add_argument("--json", action="store_true", help="Print JSON serialization of the AST")
    parser.add_argument("-c", "--code", help="Inline batch code string to parse")
    parser.add_argument("--cfg", action="store_true", help="Print ASCII Control Flow Graph (CFG) summary")
    parser.add_argument("--cfg-mermaid", action="store_true", help="Print Mermaid flowchart syntax of the CFG")
    parser.add_argument("--cfg-dot", action="store_true", help="Print Graphviz DOT syntax of the CFG")
    parser.add_argument("--cfg-resolve-jumps", action="store_true", help="Perform dynamic jump table resolution on CFG")
    parser.add_argument("--dce", action="store_true", help="Perform Dead Code Elimination (DCE) and unreferenced SET pruning")
    parser.add_argument("--dce-stats", action="store_true", help="Print Dead Code Elimination metrics summary")
    parser.add_argument("--arithmetic", action="store_true", help="Perform arithmetic expression folding (set /a)")
    parser.add_argument("--arithmetic-stats", action="store_true", help="Print arithmetic expression folding metrics summary")
    parser.add_argument("--preserve-vars", help="Comma-separated variable names to protect from dead code elimination")
    parser.add_argument("--benchmark", action="store_true", help="Execute real-world deobfuscation benchmark suite")
    parser.add_argument("--benchmark-engine", choices=["ast", "automaton"], default="ast", help="Engine to evaluate (ast or automaton)")
    parser.add_argument("--benchmark-export", help="Path to save benchmark report (.md or .json)")

    args = parser.parse_args()

    if args.benchmark:
        runner = BenchmarkRunner(engine=args.benchmark_engine)
        summary = runner.run_all()
        md_report = summary.to_markdown()
        print(md_report)
        if args.benchmark_export:
            ext = os.path.splitext(args.benchmark_export)[1].lower()
            with open(args.benchmark_export, "w", encoding="utf-8") as f:
                if ext == ".json":
                    f.write(summary.to_json())
                else:
                    f.write(md_report)
            print(f"[✓] Benchmark report exported to {args.benchmark_export}")
        sys.exit(0)

    if args.code:
        source = args.code
    elif args.input:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    else:
        parser.print_help()
        sys.exit(1)

    ast_parser = CmdASTParser.from_source(source)
    ast = ast_parser.parse()

    if args.tree:
        print("\n=== [AST SYNTAX TREE] ===")
        print(ASTVisualizer.render_ascii_tree(ast))

    if args.mermaid:
        print("\n=== [MERMAID FLOWCHART] ===")
        print(ASTVisualizer.render_mermaid(ast))

    if args.json:
        print("\n=== [JSON AST DUMP] ===")
        print(ASTVisualizer.render_json(ast))

    if args.cfg or args.cfg_mermaid or args.cfg_dot:
        builder = CFGBuilder()
        cfg = builder.build(ast)
        if args.cfg_resolve_jumps:
            resolver = JumpTableResolver()
            resolver.resolve(cfg)
        if args.cfg:
            print("\n=== [CONTROL FLOW GRAPH SUMMARY] ===")
            print(CFGVisualizer.to_ascii(cfg))
        if args.cfg_mermaid:
            print("\n=== [CFG MERMAID FLOWCHART] ===")
            print(CFGVisualizer.to_mermaid(cfg))
        if args.cfg_dot:
            print("\n=== [CFG GRAPHVIZ DOT] ===")
            print(CFGVisualizer.to_dot(cfg))

    preserve_set = None
    if args.preserve_vars:
        preserve_set = {v.strip() for v in args.preserve_vars.split(",") if v.strip()}

    if args.arithmetic or args.arithmetic_stats:
        from src.transforms.arithmetic_folder import ArithmeticFolderPass
        arith_pass = ArithmeticFolderPass()
        ast = arith_pass.transform(ast)
        if args.arithmetic_stats:
            print("\n=== [ARITHMETIC FOLDING STATS] ===")
            print(f"  Expressions evaluated: {arith_pass.metrics.expressions_evaluated}")
            print(f"  Assignments folded   : {arith_pass.metrics.assignments_folded}")
            print(f"  Variables resolved   : {arith_pass.metrics.variables_resolved}")
            print(f"  Operators evaluated  : {arith_pass.metrics.operators_evaluated}")

    if args.dce or args.dce_stats:
        from src.transforms.dce import DeadCodeEliminationPass
        dce_pass = DeadCodeEliminationPass(preserve_vars=preserve_set)
        ast = dce_pass.transform(ast)
        if args.dce_stats:
            print("\n=== [DEAD CODE ELIMINATION STATS] ===")
            print(dce_pass.metrics.summary())

    normalizer = ASTNormalizer(preserve_vars=preserve_set)
    norm_ast = normalizer.normalize(ast)
    clean_code = normalizer.to_source(norm_ast)


    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(clean_code + "\n")
        print(f"[✓] Deobfuscated code written to {args.output}")
    elif not (args.tree or args.mermaid or args.json or args.cfg or args.cfg_mermaid or args.cfg_dot):
        print(clean_code)


if __name__ == "__main__":
    main()
