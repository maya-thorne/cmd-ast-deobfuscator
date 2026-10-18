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
    parser.add_argument("--reversal", action="store_true", help="Perform string reversal and transposition deobfuscation")
    parser.add_argument("--reversal-stats", action="store_true", help="Print string reversal and transposition metrics summary")
    parser.add_argument("--quotes", action="store_true", help="Perform quote toggle boundary and empty quote pair normalization")
    parser.add_argument("--quote-stats", action="store_true", help="Print quote normalization metrics summary")
    parser.add_argument("--redirects", "--redirection", action="store_true", dest="redirects", help="Perform I/O redirection and stream routing normalization")
    parser.add_argument("--redirect-stats", "--redirection-stats", action="store_true", dest="redirect_stats", help="Print I/O redirection and stream routing metrics summary")
    parser.add_argument("--dosfuscation", "--dosf", action="store_true", dest="dosfuscation", help="Perform Invoke-DOSfuscation concatenation decoding (variable chains, delimiters, loops)")
    parser.add_argument("--dosf-stats", action="store_true", help="Print Invoke-DOSfuscation concatenation metrics summary")
    parser.add_argument("--deflat", action="store_true", help="Perform Control Flow De-flattening (Anti-CFF) and state machine unrolling")
    parser.add_argument("--deflat-stats", action="store_true", help="Print Control Flow De-flattening metrics summary")
    parser.add_argument("--packer-detect", "--packers-detect", action="store_true", dest="packers_detect", help="Detect 0xidiz3r, Somalifuscator, CertUtil, and batch packer signatures")
    parser.add_argument("--packers-unpack", action="store_true", help="Recursively unpack multi-stage batch packers and stubs")
    parser.add_argument("--packers-layers", action="store_true", help="Print multi-stage layer transitions, entropy deltas, and provenance")
    parser.add_argument("--md", "--packers-md", action="store_true", dest="md", help="Format output as Markdown table or document")
    parser.add_argument("--to-python", "--to-py", action="store_true", dest="to_python", help="Transpile batch script to clean Python 3 script via IR")
    parser.add_argument("--to-powershell", "--to-ps1", action="store_true", dest="to_powershell", help="Transpile batch script to clean PowerShell script via IR")
    parser.add_argument("--emit-ir", action="store_true", help="Print Intermediate Representation (IR) JSON dump")
    parser.add_argument("--ir-stats", action="store_true", help="Print Intermediate Representation compilation & transpilation telemetry")
    parser.add_argument("--ir-no-main", action="store_true", help="Do not wrap Python transpilation output in def main()")
    parser.add_argument("--diff", action="store_true", help="Print colored diff between original and deobfuscated code")
    parser.add_argument("--side-by-side", "--side", action="store_true", dest="side_by_side", help="Render side-by-side split column diff")
    parser.add_argument("--diff-width", type=int, default=None, help="Terminal column width for side-by-side diff (default auto)")
    parser.add_argument("--diff-stats", action="store_true", help="Print quantitative code difference metrics")
    parser.add_argument("--step-diff", action="store_true", help="Print step-by-step diff for every transform pass that modified the AST")
    parser.add_argument("--inspect", "--tui", "--debugger", action="store_true", dest="inspect", help="Launch interactive terminal AST pipeline debugger (TUI)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color escape codes in diffs and trees")
    parser.add_argument("--preserve-vars", help="Comma-separated variable names to protect from dead code elimination")
    parser.add_argument("--benchmark", action="store_true", help="Execute real-world deobfuscation benchmark suite")
    parser.add_argument("--benchmark-engine", choices=["ast", "automaton"], default="ast", help="Engine to evaluate (ast or automaton)")
    parser.add_argument("--benchmark-export", help="Path to save benchmark report (.md or .json)")
    parser.add_argument("--scan-dir", help="Path to directory containing batch scripts to scan and deobfuscate in bulk")
    parser.add_argument("--output-dir", help="Destination directory for deobfuscated batch scripts")
    parser.add_argument("--in-place", action="store_true", help="Modify batch scripts in-place within the scanned directory")
    parser.add_argument("--backup", action="store_true", default=True, help="Create .bak backups when modifying in-place (default: True)")
    parser.add_argument("--no-backup", action="store_false", dest="backup", help="Disable .bak backups when modifying in-place")
    parser.add_argument("--workers", type=int, default=4, help="Number of concurrent worker threads for directory scanning (default: 4)")
    parser.add_argument("--max-size", type=int, default=10 * 1024 * 1024, help="Maximum file size in bytes to scan (default: 10MB)")
    parser.add_argument("--file-patterns", help="Comma-separated file extensions or glob patterns to scan (default: *.bat,*.cmd,*.btm)")
    parser.add_argument("--report-json", help="Path to export directory scan summary report as JSON")
    parser.add_argument("--report-csv", help="Path to export directory scan summary report as CSV")
    parser.add_argument("--report-md", help="Path to export directory scan summary report as Markdown")
    parser.add_argument("--dry-run", action="store_true", help="Perform discovery, AST parsing, and analysis without writing output")
    parser.add_argument("--fail-fast", action="store_true", help="Halt directory scan immediately upon encountering first error")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress per-file progress log during directory scan")
    parser.add_argument("--ioc", "--extract-iocs", action="store_true", dest="extract_iocs", help="Extract malware Indicators of Compromise (IOCs) from AST")
    parser.add_argument("--ioc-stats", action="store_true", help="Print malware IOC extraction telemetry metrics")
    parser.add_argument("--ioc-filter", help="Comma-separated IOC types to filter (e.g. ipv4,url,domain,file_drop,lolbin)")
    parser.add_argument("--ioc-min-confidence", type=float, default=0.0, help="Minimum confidence threshold for extracted IOCs (0.0 to 1.0)")
    parser.add_argument("--ioc-defang", action="store_true", help="Defang indicators in output (e.g. hxxp://, evil[.]com, 192.168.1[.]1)")
    parser.add_argument("--ioc-json", help="Path to export extracted IOCs as JSON")
    parser.add_argument("--ioc-csv", help="Path to export extracted IOCs as CSV")
    parser.add_argument("--ioc-md", help="Path to export extracted IOCs as Markdown report")
    parser.add_argument("--ioc-stix", help="Path to export extracted IOCs as STIX 2.1 JSON bundle")
    parser.add_argument("--ffi-export-header", nargs="?", const="", default=None, help="Export C ABI header (include/cmd_deobfuscator.h) to target path")
    parser.add_argument("--ffi-test-roundtrip", action="store_true", help="Execute C/Rust FFI native acceleration roundtrip verification")
    parser.add_argument("--ebnf-validate", action="store_true", help="Validate input batch script against formal cmd.exe EBNF grammar specifications")
    parser.add_argument("--ebnf-report", action="store_true", help="Generate formal cmd.exe EBNF grammar conformance and coverage report")
    parser.add_argument("--ebnf-audit-suite", action="store_true", help="Execute canonical cmd.exe EBNF test corpus audit suite")
    parser.add_argument("--ebnf-json", help="Path to export EBNF conformance/audit report as JSON")
    parser.add_argument("--ebnf-md", help="Path to export EBNF conformance/audit report as Markdown")

    args = parser.parse_args()

    if args.ebnf_audit_suite or args.ebnf_validate or args.ebnf_report:
        from src.ebnf import handle_ebnf_cli
        src_code = args.code
        if src_code is None and args.input:
            if not os.path.isfile(args.input):
                print(f"[!] Error: File not found: {args.input}", file=sys.stderr)
                sys.exit(1)
            with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
                src_code = f.read()
        sys.exit(handle_ebnf_cli(args, source=src_code))

    if args.ffi_export_header is not None:
        from src.ffi import export_c_header
        target = args.ffi_export_header if args.ffi_export_header != "" else None
        out_file = export_c_header(target)
        print(f"[✓] C ABI header exported to: {out_file}")
        sys.exit(0)

    if args.ffi_test_roundtrip:
        import json
        from src.ffi import verify_roundtrip
        report = verify_roundtrip()
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["status"] == "PASS" else 1)

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

    if args.scan_dir:
        from src.scanner import DirectoryScanner, ScanConfig, FileScanStatus
        preserve_set = None
        if args.preserve_vars:
            preserve_set = {v.strip() for v in args.preserve_vars.split(",") if v.strip()}

        patterns = ["*.bat", "*.cmd", "*.btm"]
        if args.file_patterns:
            patterns = [p.strip() for p in args.file_patterns.split(",") if p.strip()]

        config = ScanConfig(
            input_dir=args.scan_dir,
            output_dir=args.output_dir,
            recursive=True,
            file_patterns=patterns,
            max_file_size=args.max_size,
            workers=args.workers,
            in_place=args.in_place,
            backup=args.backup,
            dry_run=args.dry_run,
            enable_dce=args.dce,
            preserve_vars=preserve_set,
            fail_fast=args.fail_fast,
        )

        def progress_cb(item, current, total):
            if not args.quiet:
                status_symbol = "[✓]" if item.status == FileScanStatus.SUCCESS else (
                    "[=]" if item.status == FileScanStatus.UNCHANGED else (
                        "[!]" if item.status == FileScanStatus.FAILED else "[-]"
                    )
                )
                print(f"{status_symbol} [{current}/{total}] {item.status.value:<9} {item.relative_path} ({item.elapsed_ms:.1f}ms)")

        if not args.quiet:
            print(f"\n=== [DIRECTORY BATCH SCANNER: {os.path.abspath(args.scan_dir)}] ===")
            print(f"[*] Workers: {config.workers} | DCE: {config.enable_dce} | In-Place: {config.in_place} | Dry-Run: {config.dry_run}")

        scanner = DirectoryScanner(config)
        summary = scanner.scan_and_deobfuscate(config, progress_callback=progress_cb)

        if not args.quiet:
            print("\n" + summary.to_markdown())

        DirectoryScanner.export_reports(
            summary,
            json_path=args.report_json,
            csv_path=args.report_csv,
            markdown_path=args.report_md,
        )
        if args.report_json:
            print(f"[✓] JSON scan report written to {args.report_json}")
        if args.report_csv:
            print(f"[✓] CSV scan report written to {args.report_csv}")
        if args.report_md:
            print(f"[✓] Markdown scan report written to {args.report_md}")

        sys.exit(0 if summary.failed_count == 0 else 1)

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

    if args.inspect:
        from src.tui import ASTPipelineDebugger, ColorMode
        color_mode = ColorMode.NEVER if args.no_color else ColorMode.AUTO
        dbg = ASTPipelineDebugger(source=source, color_mode=color_mode)
        dbg.repl()
        sys.exit(0)

    if args.step_diff:
        from src.tui import ASTPipelineDebugger, ColorMode, DiffStyle
        color_mode = ColorMode.NEVER if args.no_color else ColorMode.AUTO
        dbg = ASTPipelineDebugger(source=source, color_mode=color_mode)
        recs = dbg.run_all()
        style = DiffStyle.SIDE_BY_SIDE if args.side_by_side else DiffStyle.UNIFIED
        print("\n=== [STEP-BY-STEP TRANSFORM PIPELINE DIFF] ===")
        modified_steps = [r for r in recs if r.modified]
        if not modified_steps:
            print("[*] No transformation passes modified the script.")
        else:
            prev_code = source
            for r in modified_steps:
                print(dbg.diff_renderer.render_step_diff(
                    r.pass_name, prev_code, r.source_code, style=style
                ))
                prev_code = r.source_code
        sys.exit(0)

    if args.tree:
        print("\n=== [AST SYNTAX TREE] ===")
        print(ASTVisualizer.render_ascii_tree(ast))

    if args.mermaid:
        print("\n=== [MERMAID FLOWCHART] ===")
        print(ASTVisualizer.render_mermaid(ast))

    if args.json and not (args.packers_detect or args.packers_unpack or args.packers_layers):
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

    if args.reversal or args.reversal_stats:
        from src.transforms.reversal_folder import ReversalFolderPass
        rev_pass = ReversalFolderPass()
        ast = rev_pass.transform(ast)
        if args.reversal_stats:
            print("\n=== [STRING REVERSAL & TRANSPOSITION STATS] ===")
            print(f"  Loops detected           : {rev_pass.metrics.loops_detected}")
            print(f"  Loops folded             : {rev_pass.metrics.loops_folded}")
            print(f"  Transposed slices folded : {rev_pass.metrics.transposed_slices_folded}")
            print(f"  GOTO stack loops folded  : {rev_pass.metrics.goto_loops_folded}")
            print(f"  Characters decoded       : {rev_pass.metrics.characters_decoded}")

    if args.quotes or args.quote_stats:
        from src.transforms.quote_normalizer import QuoteNormalizerPass
        quote_pass = QuoteNormalizerPass()
        ast = quote_pass.transform(ast)
        if args.quote_stats:
            print("\n=== [QUOTE NORMALIZATION STATS] ===")
            print(quote_pass.metrics.summary())

    if args.redirects or args.redirect_stats:
        from src.transforms.redirection_pass import RedirectionPass
        red_pass = RedirectionPass()
        ast = red_pass.transform(ast)
        if args.redirect_stats:
            print("\n=== [I/O REDIRECTION & STREAM ROUTING STATS] ===")
            stats = red_pass.metrics.to_dict()
            for k, v in stats.items():
                print(f"  {k:<24}: {v}")

    if args.dosfuscation or args.dosf_stats:
        from src.transforms.dosfuscation_pass import DosfuscationPass
        dosf_pass = DosfuscationPass()
        ast = dosf_pass.transform(ast)
        if args.dosf_stats:
            print("\n=== [INVOKE-DOSFUSCATION CONCATENATION STATS] ===")
            print(f"  Variable chains fused    : {dosf_pass.metrics.var_chains_fused}")
            print(f"  Junk variables stripped  : {dosf_pass.metrics.junk_vars_stripped}")
            print(f"  Delimiters normalized    : {dosf_pass.metrics.delimiters_normalized}")
            print(f"  Loops accumulated        : {dosf_pass.metrics.loops_accumulated}")
            print(f"  Trampolines unrolled     : {dosf_pass.metrics.trampolines_unrolled}")

    if args.packers_detect or args.packers_unpack or args.packers_layers:
        from src.packers.cli_helper import handle_packers_cli
        handle_packers_cli(source, args)

    if args.deflat or args.deflat_stats:
        from src.transforms.deflat_pass import DeflatPass
        deflat_pass = DeflatPass()
        ast = deflat_pass.transform(ast)
        if args.deflat_stats:
            print("\n=== [CONTROL FLOW DE-FLATTENING STATS] ===")
            stats = deflat_pass.deflat_metrics.to_dict()
            for k, v in stats.items():
                print(f"  {k:<32}: {v}")
            if deflat_pass.packer_detection and deflat_pass.packer_detection.is_packed:
                p_stats = deflat_pass.packer_detection.metrics.to_dict()
                print("  --- Packer Extraction Telemetry ---")
                for k, v in p_stats.items():
                    print(f"  {k:<32}: {v}")

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

    if args.extract_iocs or args.ioc_stats or args.ioc_json or args.ioc_csv or args.ioc_md or args.ioc_stix or args.ioc_defang:
        from src.ioc import IOCExtractor, IOCType
        extractor = IOCExtractor(min_confidence=args.ioc_min_confidence)
        ioc_res = extractor.extract_from_ast(norm_ast, source_file=args.input, source_text=source)
        if clean_code:
            extractor._scan_raw_source_fallback(clean_code)
            ioc_res = extractor._build_result()
        elif source:
            extractor._scan_raw_source_fallback(source)
            ioc_res = extractor._build_result()

        if args.ioc_filter:
            filter_types = []
            for t_str in args.ioc_filter.split(","):
                norm_t = t_str.strip().lower()
                if norm_t in ("ip", "ips"):
                    filter_types.extend([IOCType.IPV4, IOCType.IPV6])
                elif norm_t in ("hash", "hashes"):
                    filter_types.extend([IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256])
                elif norm_t in ("file", "files"):
                    filter_types.extend([IOCType.FILE_DROP, IOCType.FILE_PATH])
                else:
                    try:
                        filter_types.append(IOCType(norm_t))
                    except ValueError:
                        pass
            if filter_types:
                ioc_res = ioc_res.filter(ioc_types=filter_types)

        if args.ioc_defang:
            ioc_res = ioc_res.defang()

        if args.ioc_stats:
            print("\n=== [MALWARE IOC EXTRACTION STATS] ===")
            print(ioc_res.metrics.summary())

        if args.ioc_json:
            with open(args.ioc_json, "w", encoding="utf-8") as f:
                f.write(ioc_res.to_json())
            print(f"[✓] IOC JSON report written to {args.ioc_json}")

        if args.ioc_csv:
            with open(args.ioc_csv, "w", encoding="utf-8") as f:
                f.write(ioc_res.to_csv())
            print(f"[✓] IOC CSV report written to {args.ioc_csv}")

        if args.ioc_md:
            with open(args.ioc_md, "w", encoding="utf-8") as f:
                f.write(ioc_res.to_markdown())
            print(f"[✓] IOC Markdown report written to {args.ioc_md}")

        if args.ioc_stix:
            with open(args.ioc_stix, "w", encoding="utf-8") as f:
                f.write(ioc_res.to_stix_json())
            print(f"[✓] STIX 2.1 bundle written to {args.ioc_stix}")

        if args.extract_iocs:
            print("\n" + ioc_res.to_markdown())

    if args.to_python or args.to_powershell or args.emit_ir or args.ir_stats:
        from src.ir import BatchTranspiler, ASTToIRBuilder
        builder = ASTToIRBuilder()
        ir_prog = builder.build(norm_ast)

        if args.ir_stats:
            print("\n=== [INTERMEDIATE REPRESENTATION (IR) STATS] ===")
            print(builder.metrics.summary())
            stats = builder.metrics.to_dict()
            for k, v in stats.items():
                print(f"  {k:<24}: {v}")

        if args.emit_ir:
            import json
            print("\n=== [INTERMEDIATE REPRESENTATION (IR) DUMP] ===")
            print(json.dumps(ir_prog.to_dict(), indent=2))

        target_lang = "python" if args.to_python else "powershell"
        trans_res = transpiler.transpile(norm_ast, target=target_lang, wrap_in_main=not args.ir_no_main)
        final_output = trans_res.emitted_code
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(final_output)
            print(f"[✓] Transpiled {target_lang.capitalize()} code written to {args.output}")
        else:
            print(final_output)
        sys.exit(0)

    if args.diff or args.side_by_side or args.diff_stats:
        from src.tui import ColoredDiffRenderer, ColorMode
        color_mode = ColorMode.NEVER if args.no_color else ColorMode.AUTO
        diff_renderer = ColoredDiffRenderer(color_mode=color_mode)
        if args.diff or args.side_by_side:
            print("\n=== [DEOBFUSCATION DIFF] ===")
            if args.side_by_side:
                print(diff_renderer.render_side_by_side(source, clean_code, width=args.diff_width))
            else:
                print(diff_renderer.render_unified(source, clean_code))
        if args.diff_stats:
            metrics = diff_renderer.compute_metrics(source, clean_code)
            print("\n=== [DEOBFUSCATION DIFF STATS] ===")
            for k, v in metrics.to_dict().items():
                print(f"  {k:<20}: {v}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(clean_code + "\n")
        print(f"[✓] Deobfuscated code written to {args.output}")
    elif not (args.tree or args.mermaid or args.json or args.cfg or args.cfg_mermaid or args.cfg_dot or args.diff or args.side_by_side or args.extract_iocs or args.packers_detect or args.packers_unpack or args.packers_layers):
        print(clean_code)


if __name__ == "__main__":
    main()
