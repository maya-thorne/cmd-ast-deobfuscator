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
else:
    from .parser import CmdASTParser
    from .normalizer import ASTNormalizer
    from .visualizer import ASTVisualizer


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

    args = parser.parse_args()

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

    normalizer = ASTNormalizer()
    norm_ast = normalizer.normalize(ast)
    clean_code = normalizer.to_source(norm_ast)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(clean_code + "\n")
        print(f"[✓] Deobfuscated code written to {args.output}")
    elif not (args.tree or args.mermaid or args.json):
        print(clean_code)


if __name__ == "__main__":
    main()
