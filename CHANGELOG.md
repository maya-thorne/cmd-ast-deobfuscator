# Changelog

All notable changes to `cmd-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.18.0] - 2026-10-16

### Added
- **AST-based Malware Indicator of Compromise (IOC) Extractor (`src/ioc/`)**:
  - Implemented syntax-tree-aware malware indicator extraction engine (`src/ioc/extractor.py`) featuring `IOCExtractor` traversing command nodes, string literals, variable expansions, and stream redirection targets.
  - Implemented multi-class IOC identification: IPv4 addresses (with port support and octet validation), IPv6 addresses, URLs (HTTP, HTTPS, FTP, SFTP), standalone domain names, email addresses, cryptographic hashes (MD5, SHA1, SHA256), registry run keys, and file drop artifacts.
  - Implemented LOLBins (Living Off The Land Binaries) detection registry (`src/ioc/patterns.py`) tracking 30+ native Windows system binaries (`powershell.exe`, `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `vssadmin.exe`, `schtasks.exe`, etc.).
  - Added MITRE ATT&CK technique mapping and command flag disambiguation supporting T1059 (Command/Scripting Interpreter), T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode), T1197 (BITS Jobs), T1218 (Proxy Execution), T1490 (Inhibit Recovery), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), and T1070.001 (Clear Event Logs).
- **Automated Defanging Protocols & Threat Intelligence Formatting (`src/ioc/models.py`)**:
  - Implemented safe indicator defanging protocols (`defang_ipv4`, `defang_ipv6`, `defang_domain`, `defang_url`, `defang_ioc`) neutralizing active C2 endpoints for secure SOC analysis (`hxxp://`, `evil[.]com`, `192.168.1[.]1`).
  - Added data models (`IOCType`, `IOCSeverity`, `MitreTactic`, `MitreAttackMapping`, `IOCItem`, `IOCMetrics`, and `IOCExtractionResult`).
  - Added subset filtering methods (`filter()`) by indicator type, confidence threshold, and MITRE technique ID.
  - Implemented in-memory cryptographic zeroization (`zeroize()`) across items, metrics, and extraction result containers.
- **Multi-Format Threat Intelligence Exporters (`src/ioc/exporters.py`)**:
  - Implemented standard CSV serialization (`export_csv`) with full metadata attributes.
  - Implemented human-readable Markdown summary tables (`export_markdown`) with MITRE ATT&CK technique matrices.
  - Implemented OASIS STIX 2.1 Threat Intelligence Bundle exporter (`export_stix_bundle`, `export_stix_json`) generating compliant `indicator`, `attack-pattern`, and `relationship` objects.
- **AST Compiler Transform Pass Integration (`src/ioc/transforms.py`, `src/transforms/ioc_pass.py`)**:
  - Implemented `IOCTransformPass` subclasses of `TransformPass` for plug-and-play inclusion in the AST `PassManager` pipeline.
  - Added high-level convenience function `extract_iocs()` supporting AST nodes and raw script sources.
- **CLI Options**:
  - Added `--ioc` / `--extract-iocs`, `--ioc-stats`, `--ioc-filter`, `--ioc-min-confidence`, `--ioc-defang`, `--ioc-json`, `--ioc-csv`, `--ioc-md`, and `--ioc-stix` flags to `src/cli.py`.
- **Comprehensive Test Suite**:
  - Added `tests/test_ioc_suite.py` with 26 unit and integration tests covering IP addresses, URLs, domains, file drops, LOLBins, MITRE ATT&CK techniques, defanging protocols, CSV/MD/JSON/STIX 2.1 exports, memory zeroization, and CLI flags.
  - Repository test suite expanded to 484 tests with 100% pass rate.


## [0.17.0] - 2026-10-15

### Added
- **High-Throughput Directory Batch Scanner Engine (`src/scanner/`)**:
  - Implemented parallel directory scanner (`src/scanner/engine.py`) featuring `DirectoryScanner` for bulk discovery, parsing, AST optimization pass execution, and persistence across entire filesystem directory trees.
  - Added thread-pool worker orchestration (`ThreadPoolExecutor`) with configurable concurrency levels (`--workers`), fail-fast execution control (`--fail-fast`), and real-time per-file progress callbacks.
  - Implemented automated report export (`DirectoryScanner.export_reports`) generating structured JSON telemetry, CSV item records, and Markdown summary tables.
- **Batch File Discovery & Security Path Traversal Defenses (`src/scanner/collector.py`)**:
  - Implemented `FileCollector` supporting recursive file tree traversal, customizable file extensions (`*.bat`, `*.cmd`, `*.btm`), depth restrictions (`max_depth`), and pattern-based directory exclusions (`.git`, `node_modules`, `__pycache__`, virtualenvs).
  - Enforced path traversal defense using canonical realpath resolution (`os.path.commonpath`) and symlink cycle detection to prevent directory escape attacks.
- **Multi-Encoding Ingestion & Safe File Persistence (`src/scanner/worker.py`)**:
  - Implemented `ScannerWorker` with multi-encoding fallback loader (`utf-8-sig`, `utf-8`, `cp437`, `cp1252`, `cp949`, `latin-1`) and automatic BOM stripping.
  - Implemented single-file deobfuscation pipeline with AST node counting, Shannon entropy calculation before/after, and reduction ratio metrics.
  - Added safe in-place file modification with automatic `.bak` backup generation and output directory mirroring preserving relative subdirectory paths.
  - Implemented file size caps (`max_file_size`, default 10MB) to skip oversized or non-script binaries safely.
- **Data Models, Telemetry & Zeroize Memory Sanitization (`src/scanner/models.py`)**:
  - Added `ScanConfig`, `FileScanStatus` (`SUCCESS`, `UNCHANGED`, `FAILED`, `SKIPPED`), `ScanItem`, and `ScanSummary`.
  - Added aggregate metrics computing throughput (files/second, MB/second), overall bytes processed, and average Shannon entropy reduction.
  - Implemented in-memory zeroization protocol (`zeroize()`) across `ScanItem` and `ScanSummary` to wipe file paths, hash digests, and error buffers from memory upon task completion.
- **CLI Options**:
  - Added `--scan-dir`, `--output-dir`, `--in-place`, `--backup` / `--no-backup`, `--workers`, `--max-size`, `--file-patterns`, `--report-json`, `--report-csv`, `--report-md`, `--dry-run`, `--fail-fast`, and `-q` / `--quiet` flags to `src/cli.py`.
- **Comprehensive Test Suite**:
  - Added `tests/test_scanner_suite.py` with 14 unit and integration tests covering path discovery, recursion and depth limits, directory exclusions, multi-encoding fallback, file size caps, in-place backup, output directory mirroring, parallel execution, report export, memory zeroization, and CLI flags.
  - Repository test suite expanded to 458 tests with 100% pass rate.

## [0.16.0] - 2026-10-15

### Added
- **Interactive Terminal AST Inspector & TUI Debugger (`src/tui/`)**:
  - Implemented step-by-step transform pipeline debugger (`src/tui/debugger.py`) featuring `ASTPipelineDebugger` with command evaluation loop (`step`, `next`, `run`, `diff`, `tree`, `env`, `source`, `node <id>`, `passes`, `reset`, `stats`, `help`, `quit`) and interactive REPL mode.
  - Added pipeline execution snapshot history tracking (`StepRecord`) preserving AST states, serialized code, and environment symbol tables across passes.
  - Implemented node property inspector (`inspect_node`) providing attribute details for individual AST nodes by identifier.
- **Colored Diff Visualizer (`src/tui/diff.py`)**:
  - Implemented unified diff renderer (`render_unified`) with ANSI escape coloring for added lines (`+`), deleted lines (`-`), hunks (`@@`), and file headers.
  - Implemented side-by-side split column diff renderer (`render_side_by_side`) with clean Unicode box-drawing borders (`┌`, `┬`, `┐`, `│`, `├`, `┼`, `┤`, `└`, `┴`, `┘`), line number tracking, modification markers (`|`, `+`, `-`), and dynamic terminal width auto-adaptation.
  - Added step-by-step pipeline diff renderer (`render_step_diff`) highlighting modifications introduced by each transform pass.
  - Added quantitative difference metrics (`compute_metrics`) computing line counts, additions, deletions, modifications, and character similarity ratios.
- **Colorized AST Syntax Tree Renderer (`src/tui/tree_view.py`)**:
  - Implemented `ColoredASTTreeRenderer` rendering AST hierarchies with colorized node types, variable names, literals, and operators, with sequential index badges (`[#1]`, `[#2]`, ...) and bounded recursion depth (`max_depth`).
- **Data Models, Terminal Stylers & Telemetry (`src/tui/models.py`)**:
  - Added `DiffStyle`, `ColorMode` (`AUTO`, `ALWAYS`, `NEVER`), `DiffLineType`, `DiffLine`, `DiffMetrics`, and `InspectorMetrics`.
  - Added `ANSI` styling constants, `strip_ansi()`, `ansi_len()`, and `should_color()` supporting the `NO_COLOR` standard and terminal capability detection.
  - Implemented secure memory zeroization (`zeroize()`) on telemetry models, diff buffers, and debugger snapshots.
- **CLI Options**:
  - Added `--diff`, `--side-by-side` (`--side`), `--diff-width`, `--diff-stats`, `--step-diff`, `--inspect` (`--tui`, `--debugger`), and `--no-color` flags to `src/cli.py`.
- **Test Suite**:
  - Added `tests/test_tui_inspector_suite.py` with 26 unit and integration tests covering ANSI strip/length calculation, unified and side-by-side diff rendering, colored AST trees, debugger commands and REPL sessions, memory zeroization, and CLI flags.
  - Overall test suite expanded to 444 tests with 100% pass rate.

## [0.15.0] - 2026-10-14

### Added
- **Intermediate Representation (IR) Transpiler Engine (`src/ir/`)**:
  - Implemented language-agnostic Intermediate Representation data models (`src/ir/models.py`) with `IRProgram`, `IRBlock`, `IRFunction`, `IRStatement`, `IRExpression`, `IRConstant`, `IRVariable`, `IRPathModifier`, `IRBinaryOp`, `IRUnaryOp`, `IRSlice`, `IRSubst`, `IRAssignment`, `IRExec`, `IREcho`, `IRRedirect`, `IRIf`, `IRFor`, `IRCall`, and `IRReturn`.
  - Added telemetry and security metrics (`IRMetrics`) with secure in-memory zeroization (`zeroize()`).
  - Implemented AST-to-IR builder (`src/ir/builder.py`) converting cmd.exe AST trees into structured IR programs, lifting internal subroutine labels into callable functions, mapping batch built-in commands (`echo`, `cls`, `pause`, `mkdir`, `del`, `copy`, `move`, `timeout`), parsing complex `IF` conditions (`==`, `equ`, `neq`, `exist`, `errorlevel`), structured `FOR` loops (`/l` range, `/r` recursive files, items), and argument and environment expansions.
  - Implemented expression and condition parser (`src/ir/expressions.py`) providing modular operand conversion, comparison operator normalization, and variable slice extraction.
- **Python 3 Target Emitter (`src/ir/targets/python.py`)**:
  - Emits clean, PEP 8-compliant Python 3 code with automated standard library import resolution (`os`, `sys`, `subprocess`, `pathlib.Path`, `shutil`, `time`).
  - Translates batch parameter modifiers (`%~dp0` -> `SCRIPT_DIR = Path(__file__).resolve().parent`, `%*` -> `sys.argv`).
  - Emits callable functions for lifted batch subroutines and structured `def main():` entry point with `if __name__ == "__main__":`.
  - Translates built-ins to native operations (`Path.mkdir`, `Path.unlink`, `shutil.copy`, `shutil.move`, `time.sleep`, `print`).
- **PowerShell Target Emitter (`src/ir/targets/powershell.py`)**:
  - Emits clean, idiomatic PowerShell code with cmdlet mappings (`Write-Host`, `New-Item`, `Remove-Item`, `Copy-Item`, `Move-Item`, `Start-Sleep`).
  - Maps environment variables to `$env:VAR`, path modifiers to `$PSScriptRoot`, and subroutines to `function Invoke-*` with `[CmdletBinding()]`.
  - Maps I/O redirections (`> nul` -> `| Out-Null`, `>> file` -> `Out-File -Append`).
- **Batch Transpiler Coordinator (`src/ir/transpiler.py`)**:
  - Added `BatchTranspiler` providing unified `transpile()`, `transpile_to_python()`, and `transpile_to_powershell()` APIs, with optional automated pre-deobfuscation pipeline.
- **CLI Commands**:
  - Added `--to-python` (`--to-py`), `--to-powershell` (`--to-ps1`), `--emit-ir`, `--ir-stats`, and `--ir-no-main` flags to `src/cli.py`.
- **Comprehensive Test Suite**:
  - Added `tests/test_ir_transpiler_suite.py` with 15 tests covering IR node models, AST-to-IR translation, Python compilation syntax validation via `ast.parse()`, PowerShell emission, subroutine lifting, memory zeroization, and CLI execution. Total test suite expanded to 418 tests with 100% pass rate.

## [0.14.0] - 2026-10-14

### Added
- **0xidiz3r & Batch Packer Signature Detection and Unpacking (`src/packers/`)**:
  - Implemented multi-rule signature detector (`src/packers/detector.py`) identifying 0xidiz3r obfuscation banners, noise variables, hex character maps, CertUtil self-extracting payload stubs (base64 and hex), Somalifuscator ciphers, script drop stubs (`.vbs`, `.ps1`), and generic control flow flattening dispatchers with weighted confidence metrics.
  - Implemented recursive multi-layer payload unpacker (`src/packers/unpacker.py`) decoding embedded PEM/base64 and hex blocks from CertUtil stubs, stripping 0xidiz3r anti-debugging name guards and noise comments, and unrolling up to 5 nested packaging layers with strict size limits (`MAX_PAYLOAD_SIZE = 10 MB`).
  - Added domain models and telemetry (`src/packers/models.py`) with `PackerType`, `PackerSignature`, `PackerMetrics`, and `PackerDetectionResult` featuring secure memory zeroization (`zeroize()`).
- **Control Flow De-flattening & State Machine Linearization Engine (`src/cff/`)**:
  - Implemented CFF analyzer (`src/cff/analyzer.py`) detecting central dispatcher loops across basic blocks, extracting state variables (`state`, `s`), state keys, switch cases, and computed jump targets (`goto :state_%s%`).
  - Implemented CFF linearizer and decompiler (`src/cff/decompiler.py`) unrolling state machine paths from initial state, splicing sequential basic blocks into clean linear statement orders, reconstructing structured conditional branching (`IfNode`), detecting natural loops, eliminating dispatcher loops, and pruning intermediate state assignments and dead jumps back to the hub.
  - Added CFF domain models (`src/cff/models.py`) with `CFFPatternType`, `CFFBlockInfo`, `CFFStateMachine`, `DeflatMetrics`, and `DeflatResult`.
- **De-flattening AST Transform Pass (`DeflatPass`)**:
  - Implemented `DeflatPass` (`src/transforms/deflat_pass.py`) orchestrating packer unwrapping and CFF linearization directly on `ScriptNode` and `BlockNode` hierarchies, preserving independent external routines while eliminating obfuscated dispatcher hubs.
  - Integrated `DeflatPass` into `PassManager.default_pipeline` and `PassManager.optimization_pipeline`.
  - Integrated `PackerUnpacker` into `BatchDeobfuscator.deobfuscate` (`src/deobfuscator_engine.py`) for automatic unpacking during multi-pass regex and automaton deobfuscation.
- **CLI Commands**:
  - Added `--deflat`, `--deflat-stats`, and `--packer-detect` flags to `src/cli.py` for standalone packer analysis and control flow unrolling.
- **Comprehensive Test Suite**:
  - Added `tests/test_deflat_suite.py` with 15 tests covering 0xidiz3r signature matching, CertUtil base64/hex payload recovery, anti-debug stripping, switch/computed CFF analysis, linear sequence unrolling, conditional branch structuring, loop reconstruction, AST pass pipeline execution, DoS recursion clamping, and memory zeroization.
  - Overall test suite expanded to 403 tests with 100% pass rate.

## [0.13.0] - 2026-10-14

### Added
- **Invoke-DOSfuscation Concatenation Heuristic Engine (M13)**:
  - Implemented dedicated domain package (`src/dosfuscation/`):
    - `DosfuscationConcatenationDecoder` (`src/dosfuscation/concatenation.py`): Multi-phase heuristic deobfuscator specifically tuned for Daniel Bohannon's Invoke-DOSfuscation concatenation techniques, resolving environment variable fragment chains (`%a%%b%%c%`), stripping interleaved junk/empty variables (`%junk%c%junk%m%junk%d`), normalizing scrambled parameter delimiters (commas `,`, semicolons `;`) outside quotes, slices, and loops into canonical single spaces, resolving FOR token accumulation loops (`for %x in (c a l c) do set out=!out!%x`), and unwrapping dynamic CALL execution trampolines (`call %cmd% -> cmd`).
    - `DosfuscationDetector` (`src/dosfuscation/detector.py`): Heuristic classifier and scoring engine analyzing token fragmentation density, delimiter scrambling index, variable expansion ratios, and entropy to detect and classify Invoke-DOSfuscation Levels 1 through 5.
    - Data models and telemetry structures (`src/dosfuscation/models.py`) with `ConcatenationType`, `ConcatenationPattern`, `DosfuscationMetrics`, and `DosfuscationResult` with explicit in-memory zeroization (`zeroize()`).
    - Package interface (`src/dosfuscation/__init__.py`) exposing clean public domain symbols.
- **Concatenation AST Transform Pass (`DosfuscationPass`)**:
  - Implemented `DosfuscationPass` (`src/transforms/dosfuscation_pass.py`):
    - Transforms `CommandNode`, `AssignmentNode`, `ForNode`, `CallNode`, and `ChainNode` hierarchies to unmask concatenated command targets and arguments.
    - Propagates virtual environment symbol definitions across sequential and compound (`&`, `&&`) statement chains.
    - Folds FOR token accumulation loops into direct constant `AssignmentNode` entries.
    - Integrated as standard pass in `PassManager.default_pipeline` and `PassManager.optimization_pipeline`.
- **Batch Deobfuscator Engine Integration**:
  - Integrated `DosfuscationConcatenationDecoder` into `BatchDeobfuscator.deobfuscate` (`src/deobfuscator_engine.py`) for automated multi-pass peeling of Invoke-DOSfuscation concatenation layers.
- **CLI Flags**:
  - Added `--dosfuscation`, `--dosf`, and `--dosf-stats` flags to `src/cli.py` for direct command line concatenation deobfuscation and reduction metric reporting.
- **Dedicated Test Suite**:
  - Created `tests/test_dosfuscation_suite.py` with 26 comprehensive tests covering junk variable stripping, delimiter scrambling with quote/slice preservation, variable chaining, loop accumulation, trampoline unwrapping, AST pass transformation, detector scoring, memory zeroization, and CLI invocation.
  - Test suite expanded to 388 total tests with 100% pass rate.

## [0.12.0] - 2026-10-13

### Added
- **I/O Redirection & Stream Routing Engine (M12)**:
  - Implemented dedicated redirection domain package (`src/redirection/`):
    - `StreamRouter` (`src/redirection/router.py`): Simulates cmd.exe stream redirection handle routing, sequential left-to-right descriptor state tracking, handle duplication chains (`>&`, `<&`), circular forwarding cycle protection with recursion depth limiting (`MAX_FORWARD_DEPTH = 10`), and stealth command execution detection.
    - Token extractor and AST builder (`src/redirection/extractor.py`): Extracts prefix, middle, and suffix redirections from token streams, supporting all source handles 0..9, handle duplication (`2>&1`, `1>&2`, `>&2`), handle closing (`2>&-`), quoted destination paths, and DOS reserved device classification (`nul`, `con`, `prn`, `aux`, `com1`..`com9`, `lpt1`..`lpt9`) with DoS boundary guards (`MAX_REDIRECTS_PER_COMMAND = 64`).
    - Data models and telemetry structures (`src/redirection/models.py`) with `StreamType`, `RedirectOperator`, `DestinationType`, `RedirectEntry`, `StreamRoute`, `RedirectPlan`, and `RedirectMetrics`.
    - Package interface (`src/redirection/__init__.py`) exposing clean public symbols.
- **Redirection AST Transform Pass (`RedirectionPass`)**:
  - Implemented `RedirectionPass` (`src/transforms/redirection_pass.py`):
    - Canonicalizes destination paths by unmasking carets (`o^u^t.txt` -> `out.txt`), collapsing empty quotes, and resolving environment variable substitutions.
    - Lifts unparsed literal redirect tokens from command argument lists into structured `RedirectNode` hierarchies.
    - Simulates stream routes, updates telemetry counters, and supports zeroization for secure memory sanitization.
    - Aliased `RedirectNormalizerPass = RedirectionPass` for backward compatibility.
    - Integrated into `PassManager.default_pipeline`.
- **Grammar Separation & Parser Integration**:
  - Integrated `extract_redirections` and `build_redirect_tree` into `CmdASTParser` (`src/parser.py`) for atomic commands and parenthesized compound blocks `( ... ) > out.txt 2>&1`.
  - Added `RedirectNode` serialization in `ASTNormalizer.to_source` (`src/normalizer.py`).
- **CLI Flags**:
  - Added `--redirection`, `--redirects`, `--redirection-stats`, `--redirect-stats` flags to `src/cli.py`.
- **Exhaustive Test Suite**:
  - Created dedicated test suites `tests/test_redirect_suite.py` and `tests/test_redirection_suite.py` covering tokenization, handle extraction (0..9), duplication/closing, device classification, stream routing simulation, stealth detection, AST integration, normalizer pass execution, and security bounds.
  - Overall test suite expanded to 362 passing tests with 100% pass rate.

## [0.11.0] - 2026-10-13

### Added
- **Quote Toggle Boundary & Nested Quote Normalization Engine**:
  - Implemented dedicated quotes domain package (`src/quotes/`):
    - `QuoteToggleAutomaton` (`src/quotes/automaton.py`): Pushdown state machine tracking cmd.exe quotation toggle boundaries, unmasking escaped quotes (`^"`), collapsing empty quote pairs (`""`), and reducing multi-level consecutive quotes (`""""`, `""""""` -> `""`) with memory bounds.
    - Command target executable deobfuscator (`normalize_target`): Implements cmd.exe command lookup semantics by stripping all quote toggles and unmasking carets from target names (`"c"m"d"`, `c""m""d`, `""powershell""`, `w^"h^"o^"a^"m^"i` -> `cmd`, `powershell`, `whoami`).
    - Argument canonicalizer (`normalize_argument`): Strips redundant quote toggles from safe alphanumeric tokens while preserving canonical quotes for arguments containing whitespace or special metacharacters (`&`, `|`, `<`, `>`, `^`).
    - Assignment normalizer (`normalize_assignment`): Canonicalizes enclosed variable assignments (`set "k=v"`, `set ""k=v""`, `set "k"="v"` -> `k=v`).
    - `QuoteNormalizer` (`src/quotes/normalizer.py`): High-level normalization coordinator and AST literal coalescer fusing contiguous tokens within lexical argument boundaries.
    - Telemetry and data structures (`src/quotes/models.py`) with `QuoteState`, `QuoteSegment`, and `QuoteNormalizerMetrics`.
- **Quote Normalization AST Transform Pass (`QuoteNormalizerPass`)**:
  - Implemented `QuoteNormalizerPass` (`src/transforms/quote_normalizer.py`) traversing AST hierarchies:
    - Fuses contiguous literal argument tokens sharing adjacent source spans (`prev.span[1] == curr.span[0]`) before evaluating quotation boundaries.
    - Normalizes command targets, command arguments, and variable assignments across commands, assignments, blocks, chains, and conditional statements.
    - Integrated into `PassManager.default_pipeline` and `PassManager.optimization_pipeline`.
    - Integrated with `ConstantFolderPass` and `BatchDeobfuscator` for unified empty quote pair elimination.
- **CLI Options & Telemetry**:
  - Added `--quotes` (enable quote toggle boundary and empty quote normalization) and `--quote-stats` (print quote normalization metrics summary) CLI flags to `src/cli.py`.
- **Verification & Test Suite**:
  - Added dedicated test suite `tests/test_quote_normalizer_suite.py` with 27 unit and integration tests covering quote toggle state transitions, empty quote collapsing, command target deobfuscation, argument canonicalization, variable assignment normalization, AST pass transformations, PassManager pipeline execution, and memory zeroization.
  - Expanded test suite coverage from 279 to 306 passing tests with 100% success rate.
  - Bumped project version to 0.11.0 in `pyproject.toml`.

## [0.10.0] - 2026-10-13

### Added
- **String Reversal & Transposition Deobfuscation Engine**:
  - Implemented dedicated reversal and transposition domain package (`src/reversal/`):
    - `StringReversalAutomaton` (`src/reversal/automaton.py`): Pushdown automaton and state-machine engine simulating `FOR /L` reverse string loops (`for /l %i in (len,-1,0)`), prepending accumulation loops (`for /l %i in (0,1,len)`), dictionary index transpositions (`for %a in (indices)`), pushdown stack GOTO reversal loops, permutation vectors, and rail-fence transposition ciphers with strict DoS simulation step limits (`MAX_SIMULATION_STEPS = 20000`) and safe out-of-bounds slice clamping.
    - `ReversalPatternDetector` (`src/reversal/detector.py`): AST pattern recognition engine identifying Somalifuscator-style `FOR /L` reverse loops, `FOR IN` dictionary lookup loops, GOTO stack reversal state machines, and contiguous decreasing slice sequences (`%s:~3,1%%s:~2,1%%s:~1,1%%s:~0,1%`) with high precision.
    - Data models and telemetry structures (`src/reversal/models.py`) with `ReversalPatternType`, `ReversalLoopSpec`, `TranspositionResult`, and `ReversalMetrics`.
- **Reversal AST Transform Pass (`ReversalFolderPass`)**:
  - Implemented `ReversalFolderPass` (`src/transforms/reversal_folder.py`) optimizing reversal and transposition patterns within AST trees:
    - Resolves reverse `FOR /L` and `FOR IN` loops into static decoded assignments (`set out=decoded_val`), propagating decoded symbols to `self.env` for downstream constant folding and dead code elimination.
    - Folds GOTO stack reversal loops into single assignments while marking the source stack variable as exhausted.
    - Folds contiguous runs of decreasing/transposed slices in commands and assignments into single consolidated literals.
    - Integrated into `PassManager.default_pipeline` and `PassManager.optimization_pipeline`.
- **Regex & Automaton Engine Integration**:
  - Enhanced `BatchDeobfuscator` (`src/deobfuscator_engine.py`) with `resolve_reversal_loops` for seamless multi-pass reverse loop resolution and symbol extraction.
- **CLI Options & Telemetry**:
  - Added `--reversal` (enable string reversal and transposition deobfuscation) and `--reversal-stats` (print reversal metrics) flags to `src/cli.py`.
- **Verification & Test Suite**:
  - Added dedicated test suite `tests/test_reversal_suite.py` with 24 unit and integration tests covering automaton simulation, pattern detection, AST folding, pipeline integration, GOTO stack loops, and real-world Somalifuscator payloads.
  - Expanded test suite coverage from 255 to 279 passing tests with 100% success rate.
  - Bumped project version to 0.10.0 in `pyproject.toml`.

## [0.9.0] - 2026-10-13

### Added
- **Arithmetic Expression Folding (`set /a`) & AST Optimization Pass**:
  - Implemented dedicated arithmetic domain engine (`src/arithmetic/`):
    - Lexer and recursive descent parser (`src/arithmetic/parser.py`) implementing exact cmd.exe operator precedence, number formats (decimal, hexadecimal `0x...`, octal `0...`), unary operators (`+`, `-`, `~`, `!`), arithmetic operators (`*`, `/`, `%`), bitwise shifts (`<<`, `>>`), bitwise logic (`&`, `^`, `|`), compound assignments (`=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `^=`, `|=`, `<<=`, `>>=`), and comma sequence expressions (`a=1, b=2`).
    - 32-bit signed integer evaluation engine (`CmdArithmeticEvaluator`, `src/arithmetic/evaluator.py`) with signed overflow wrapping (`[-2147483648, 2147483647]`), C-style truncation toward zero for integer division, and safe zero-division/modulus handling returning 0 without raising exceptions.
    - Environment symbol table integration resolving bare variable identifiers, percent variables (`%VAR%`), and delayed expansion (`!VAR!`) with recursion depth limits preventing denial-of-service on cyclic references.
- **Arithmetic AST Transform Pass (`ArithmeticFolderPass`)**:
  - Implemented `ArithmeticFolderPass` (`src/transforms/arithmetic_folder.py`) evaluating static arithmetic statements, updating the pass environment symbol table for downstream slicing and constant folding passes, and normalizing folded `AssignmentNode` representations.
  - Multi-variable assignment support (`set /a "a=1, b=2"`) with optional statement decomposition (`decompose_multi`).
  - Integrated into `PassManager.default_pipeline` and `PassManager.optimization_pipeline`.
  - Integrated with `ASTNormalizer` and `ConstantFolderPass` for unified constant propagation.
- **CLI Flags & Metrics Telemetry**:
  - Added `--arithmetic` (enable arithmetic expression folding) and `--arithmetic-stats` (print evaluation telemetry) CLI flags in `src/cli.py`.
  - `ArithmeticMetrics` tracking expressions evaluated, assignments folded, variables resolved, and operators evaluated.
- **Verification & Test Suite**:
  - Added comprehensive test suite `tests/test_arithmetic_suite.py` with 33 unit and integration tests covering tokenization, operator precedence, 32-bit overflow wrapping, zero-division safety, number bases, compound assignments, caret unmasking, AST folding, and pipeline deobfuscation.
  - Expanded test suite coverage from 222 to 255 passing tests with 100% success rate.
  - Bumped project version to 0.9.0 in `pyproject.toml`.

## [0.8.0] - 2026-10-13

### Added
- **Dead Code Elimination (DCE) & SET Pruning Pass**:
  - Implemented `DeadCodeEliminationPass` (`src/transforms/dce.py`) for iterative fixed-point optimization and dead code reduction across batch script ASTs.
  - Multi-pass variable liveness analysis engine (`VariableLivenessAnalyzer`) tracking referenced symbols across variable expansion nodes (`%VAR%`, `!VAR!`), substring slices, substitution parameters, conditional tests (`if defined`, `if %VAR%`), FOR in-clauses, dynamic jumps (`goto`, `call`), redirections, and arithmetic expressions (`set /a`).
  - Unreferenced assignment pruning stripping dead variable assignments (`set NOISE=...`) injected by adversarial tools (e.g. 0xidiz3r, Invoke-DOSfuscation, Somalifuscator).
  - Consecutive overwritten dead store elimination removing redundant write-after-write operations within linear execution sequences while respecting label and control-flow barriers.
  - Unreachable statement pruning removing code blocks and statement sequences immediately following unconditional control transfers (`exit`, `exit /b`, static `goto`).
  - Redundant block collapsing pruning empty parenthesized compound blocks (`()`) and dangling empty chain fragments.
  - Configurable symbol preservation safeguarding default Windows system environment variables (`DEFAULT_PRESERVE_VARS` such as `PATH`, `COMSPEC`, `SYSTEMROOT`, `ERRORLEVEL`) and custom user-provided export variable lists.
- **Pipeline & CLI Integration**:
  - Integrated `DeadCodeEliminationPass` into `PassManager.optimization_pipeline` and `run_transforms` with fixed-point iteration convergence guards.
  - Added CLI options (`src/cli.py`): `--dce` (enable dead code elimination), `--dce-stats` (print pruning summary metrics), and `--preserve-vars` (comma-separated list of symbols to protect).
  - Detailed metrics reporting via `DCEMetrics` tracking pruned assignments, overwritten stores, unreachable statements, empty blocks, and affected symbol names.
- **Verification & Test Suite**:
  - Added comprehensive test suite `tests/test_dce_suite.py` with 32 unit and integration tests covering unreferenced variable pruning, transitive dependency chains, conditional branch tracking, dynamic jump targets, arithmetic expressions, consecutive overwrites, unreachable branches, and CLI flags.
  - Expanded test suite coverage to 222 passing tests with 100% success rate.
  - Bumped project version to 0.8.0 in `pyproject.toml`.

## [0.7.0] - 2026-10-13

### Added
- **Control Flow Graph (CFG) Construction Engine**:
  - Implemented modular CFG domain package (`src/cfg/`) for static batch script execution analysis and topology generation.
  - Basic block partitioning (`CFGBuilder`, `src/cfg/builder.py`) segmenting linear instruction sequences between jump targets, conditionals, and subroutine boundaries.
  - Complete edge classification (`CFGEdgeType`, `src/cfg/models.py`) modeling `SEQUENTIAL`, `FALLTHROUGH` (cmd.exe label fallthrough behavior), `BRANCH_TRUE`, `BRANCH_FALSE`, `UNCONDITIONAL_JUMP`, `CALL_SUBROUTINE`, `RETURN_SUBROUTINE`, and `DYNAMIC_JUMP`.
  - Topology analysis metrics (`CFGMetrics`) computing total blocks, edges, dead code block count, cycle detection via DFS back-edge discovery, and McCabe cyclomatic complexity ($E - V + 2P$).
  - Reachability analysis via breadth-first graph traversal identifying unreachable blocks and dead execution paths.
- **Dynamic CALL & GOTO Jump Table Resolver**:
  - Implemented `JumpTableResolver` (`src/cfg/jump_table.py`) tracking symbolic variable assignments across script blocks to resolve dynamic targets (`goto %VAR%`, `call !TARGET!`).
  - Pattern-based prefix resolution matching wildcards (`goto :stage_*`) against available label declarations.
  - Control Flow Flattening (CFF) dispatcher identification detecting obfuscation state machine loops and dispatch hubs with high in-degree connectivity.
- **AST Architecture & Statement Parser Modularization**:
  - Added `LabelNode`, `GotoNode`, `CallNode`, and `ExitNode` to `src/ast_nodes.py` with visitor hierarchy support.
  - Extracted specialized statement parsers into `src/statement_parsers.py` (`parse_for_statement`, `parse_if_statement`, `parse_set_assignment`, `parse_goto_statement`, `parse_call_statement`, `parse_exit_statement`), maintaining strict modularity under 500 lines per module.
  - Enhanced recursive descent parser (`src/parser.py`) to recognize label declarations (`:lbl`) and delegate statement parsing cleanly.
  - Extended `ASTNormalizer` (`src/normalizer.py`), `TransformPass` (`src/transforms/base.py`), `CaretNormalizerPass` (`src/transforms/caret_normalizer.py`), and `ASTVisualizer` (`src/visualizer.py`) to support all control flow AST nodes.
- **Multi-Format Graph Visualizers & CLI Integration**:
  - Implemented `CFGVisualizer` (`src/cfg/visualizer.py`) exporting control flow graphs to Mermaid flowcharts with custom styling for dead code and back-edges, Graphviz DOT syntax, formatted ASCII block diagrams, and structured JSON dictionaries.
  - Added CLI flags (`src/cli.py`): `--cfg` (ASCII control flow summary), `--cfg-mermaid` (Mermaid diagram export), `--cfg-dot` (Graphviz DOT export), and `--cfg-resolve-jumps` (symbolic dynamic jump table resolution).
- **Verification & Test Suite**:
  - Added test suite `tests/test_cfg_suite.py` with 26 test cases covering AST node parsing, block partitioning, label fallthrough, conditional branching, call/return pairing, jump tables, CFF dispatchers, visualizers, and CLI flags.
  - Expanded test suite to 190 passing tests with zero regressions.
  - Bumped project version to 0.7.0 in `pyproject.toml`.

## [0.6.0] - 2026-10-13

### Added
- **FOR Loop Variable & Parameter Path Modifier Interpreter**:
  - Implemented `PathModifierResolver` and `ModifierSpec` (`src/modifiers.py`) evaluating cmd.exe parameter and FOR loop path/attribute modifiers (`~f`, `~d`, `~p`, `~n`, `~x`, `~s`, `~a`, `~t`, `~z`, `~$PATH:`).
  - Canonical path decomposition into drive, directory path with trailing backslash, filename, and extension components matching cmd.exe runtime semantics without executing host processes.
  - 8.3 short name synthesizer (`to_83_short_name`) generating compliant representations for long or space-separated paths (e.g., `Program Files` -> `PROGRA~1`).
  - Search path resolver (`search_in_var`) locating binaries across semicolon-separated directory lists defined in environment variables (such as `%~$PATH:1`).
  - File metadata simulation hooks for attributes (`~a`), modification timestamps (`~t`), and file byte sizes (`~z`).
- **AST Architecture & Tokenizer Support**:
  - Added `ParamExpandNode` to `src/ast_nodes.py` representing positional arguments (`%0`..`%9`, `%*`) and FOR loop variables (`%%i`..`%%z`) with modifier metadata.
  - Enhanced `ForNode` with explicit `flags`, `options`, `iterator`, `in_clause`, and `body` fields.
  - Updated lexical analyzer (`src/lexer.py`) with `CmdTokenType.PARAM_VAR` and `CmdTokenType.FOR_VAR` tokens, accurately distinguishing double percent loop prefixes, modifier runs, single-digit script arguments, and literal `%%` escapes.
  - Enhanced recursive descent parser (`src/parser.py`) with nested parenthesis tracking in `parse_atomic_command` and dedicated `_parse_for_statement` routine handling single-command and block loop bodies.
- **AST Normalization & Optimization Pass**:
  - Integrated `visit_ParamExpandNode` and `visit_ForNode` in `ASTNormalizer` (`src/normalizer.py`), resolving known positional parameters and loop variables into evaluated literal path strings.
  - Created `ParamResolverPass` (`src/transforms/param_resolver.py`) with pass manager integration, argument coalescing, and dynamic symbol propagation.
  - Updated `ASTVisualizer` (`src/visualizer.py`) with formatted ASCII tree, Mermaid flowchart, and JSON AST representation for parameter and loop nodes.
- **Verification & Test Suite**:
  - Added dedicated test suite `tests/test_for_param_expansion.py` containing 36 comprehensive test cases covering lexer tokenization, AST parsing, modifier resolution, 8.3 short paths, PATH searching, and pass transformations.
  - Expanded test suite coverage to 166 passing tests with zero regressions.
  - Bumped project version to 0.6.0 in `pyproject.toml`.

## [0.5.0] - 2026-10-13

### Added
- **Real-World Sample Deobfuscation Benchmark & Evaluation Harness**:
  - Curated evaluation corpus of 12 production-representative batch obfuscation samples (`src/benchmark/corpus.py`) covering Invoke-DOSfuscation (caret masking, empty quote stuffing, environment variable negative slicing, piecewise bootstrap staging), 0xidiz3r (dead variable interleaving), Somalifuscator (substitution cipher tables), download cradles (certutil, bitsadmin), living-off-the-land discovery sequences, and service shadow deletion scripts.
  - Exported standalone `.bat` sample collection in `samples/benchmark/` for direct inspection and offline testing.
  - Quantitative complexity metrics engine (`src/benchmark/metrics.py`) computing Shannon entropy deltas, AST node count reduction, character reduction rates, and lexical token density.
  - Multi-engine benchmark runner (`src/benchmark/runner.py`) evaluating the recursive-descent AST pipeline (`PassManager` + `ASTNormalizer`) and pushdown automaton engine (`BatchDeobfuscator`), achieving 100% ground-truth payload recovery across all test cases.
  - Structured reporting with formatted Markdown summaries, detailed per-sample comparison tables, and JSON export capabilities.
  - Command-line interface integration (`src/cli.py`) with `--benchmark`, `--benchmark-engine {ast,automaton}`, and `--benchmark-export <file>`.
  - Added dedicated unit test suite `tests/test_benchmark_suite.py` containing 14 tests (expanding test suite to 130 passing tests).
- **Core Engine & Normalizer Enhancements**:
  - Enhanced `src/parser.py` to preserve internal whitespace tokens across SET assignment values (`set VAR=VAL`), preventing loss of whitespace delimiters in unquoted assignment arguments.
  - Fixed command argument reconstruction in `src/transforms/caret_normalizer.py` to join arguments with spaces when promoting dynamically resolved commands into `AssignmentNode`.
  - Extended `NodeCounterVisitor` in `src/benchmark/metrics.py` with leaf visitor methods and clean `generic_visit` handling.

## [0.4.0] - 2026-10-13

### Added
- **Caret Normalization AST Transform (M04)**:
  - Implemented `CaretNormalizerPass` and `normalize_carets` in `src/transforms/caret_normalizer.py` for comprehensive resolution of cmd.exe caret (`^`) escape sequences.
  - Multi-level and nested caret reduction collapsing exponential escape multipliers (e.g., `c^^^a^^^l^^^c` -> `calc`, `s^^^^e^^^^t` -> `set`, `^^^^^^^c` -> `c`).
  - Quoting boundary tracking preserving literal carets inside double quotes (`"c^a^l^c"` preserved) while unmasking outside quotes.
  - Escaped double quote (`^"`) support emitting literal quotation marks without toggling quoting state.
  - Escaped caret pair normalization (`^^` -> `^`) with options for preserving literal carets or collapsing redundant runs.
  - AST visitor hierarchy support across `LiteralNode`, `CommandNode`, `AssignmentNode`, `VarExpandNode`, `RedirectNode`, `IfNode`, `ForNode`, `BlockNode`, `ChainNode`, and `PipeNode`.
  - Automatic conversion and promotion of obfuscated `set` commands (e.g. `s^e^t VAR=VAL`, `s^^^^e^^^^t ^"A=c^a^l^c^"`) into `AssignmentNode` and symbol table registration.
  - Coalescing of adjacent unquoted literal fragments into consolidated AST tokens.
- **Pipeline & Transforms Integration**:
  - Exported `CaretNormalizerPass` and `normalize_carets` from `src/transforms/__init__.py`.
  - Wired `CaretNormalizerPass` into `PassManager.default_pipeline` (ordered first in pass pipeline) and `run_transforms`.
  - Wired `CaretNormalizerPass` into `ConstantFolderPass` delegating artifact stripping and quote-aware unmasking.
  - Unified symbol table synchronization across passes in `PassManager.run`.
- **Packaging & Test Suite**:
  - Added dedicated unit test suite `tests/test_caret_normalizer.py` containing 28 comprehensive tests (total test suite expanded to 116 passing tests).
  - Updated `pyproject.toml` to version 0.4.0.

## [0.3.0] - 2026-10-13

### Added
- **Substring Slicing Constant Folding Optimization Pass**:
  - Implemented `SlicingFolderPass` in `src/transforms/slicing_folder.py` for AST-level constant reduction of `%VAR:~s,l%` and `!VAR:~s,l!` expressions.
  - Comprehensive slicing arithmetic matching cmd.exe semantics: 0-based positive offsets, negative offsets clamped from string tail, negative lengths leaving off characters from tail, and out-of-bounds boundary safety.
  - Full support for omitted slice parameters: `%VAR:~,len%` (start defaults to 0), `%VAR:~start,%` (length defaults to 0 returning empty string), `%VAR:~,%` (empty string), and `%VAR:~start%` (slice to end).
  - Explicit sign parsing (`+2`, `+0`) and whitespace tolerance (`%VAR:~ 2 , 3 %`) in slicing definitions.
  - Nested variable expression evaluation in slicing parameters (`%VAR:~%OFF%,%LEN%%`, `!VAR:~%OFF%,%LEN%!`).
  - Contiguous slice coalescing: fusions of adjacent slice nodes into consolidated `LiteralNode` values (e.g. `%COMSPEC:~20,1%%COMSPEC:~21,1%%COMSPEC:~22,1%` folded into `LiteralNode('cmd')`).
  - Constant folding and AST rewriting across `CommandNode` targets, arguments, `AssignmentNode` value nodes, `BlockNode`, `ChainNode`, `PipeNode`, and `RedirectNode`.
- **Modular Transforms Architecture (`src/transforms/`)**:
  - `src/transforms/base.py`: AST visitor-based `TransformPass` base class and `PassManager` with fixed-point iteration until convergence.
  - `src/transforms/constant_folder.py`: Unified constant folding pass combining slicing, caret stripping, empty quote elimination, string substitution, and symbol table propagation.
  - `src/transforms/__init__.py`: Clean package exports for `TransformPass`, `PassManager`, `SlicingFolderPass`, `ConstantFolderPass`, and `run_transforms`.
- **Parser & Lexer Improvements**:
  - Updated `src/lexer.py` to tokenize slicing variables containing nested percent parameters.
  - Updated `src/parser.py` to parse omitted slice parameters, strip whitespace, and construct AST node trees for assignments.
  - Normalized `_calculate_slice` across `src/normalizer.py` and `src/deobfuscator_engine.py` as static `calculate_slice`.
- **Packaging & Test Suite**:
  - Added `pyproject.toml` standard packaging manifest at version 0.3.0.
  - Added dedicated test suite `tests/test_slicing_folder.py` containing 34 unit tests (total test suite expanded to 88 passing tests).

## [0.2.0] - 2026-10-13

### Added
- **Delayed Expansion (`!VAR!`) AST Support (M02)**:
  - Lexical tokenization of delayed expansion variables in `src/lexer.py` via `CmdTokenType.EXCLAM_VAR`.
  - Full support for delayed expansion substring slicing syntax (`!VAR:~start,len!`, `!VAR:~start!`, negative offsets and negative lengths).
  - String substitution support for delayed expansion (`!VAR:old=new!`, `!VAR:search=!`, whitespace replacement `!VAR: =_!`, and wildcard replacement `!VAR:*pattern=rep!`).
  - Escaped caret tokenization (`^!`) outside and inside quotes preventing unintended delayed expansion triggering.
  - Delayed expansion parsing inside double quotes (`"!VAR!"`, `"!VAR:~0,4!"`).
  - Recursive descent AST parsing in `src/parser.py` producing `VarExpandNode` with `is_delayed=True`.
  - Normalization and constant-folding in `src/normalizer.py` for delayed expansion variables across the symbol table.
  - Mathematical slicing calculation engine with full support for positive/negative indices and boundary truncation.
  - AST round-trip serialization in `to_source` retaining `!...!` delimiters for unresolved delayed expansion tokens.
  - Visualizer enhancements in `src/visualizer.py` displaying `delayed=True` in ASCII tree, Mermaid diagrams, and JSON dumps, including traversal of dynamic command target nodes (`!TARGET_CMD! /v /s`).
  - Slicing semantics aligned with cmd.exe for omitted lengths / trailing commas (`!VAR:~start,!`, `!VAR:~,!`) returning zero-length substrings.
  - Chained assignment multi-pass fixed-point resolution in `src/normalizer.py` evaluating nested/dynamic variable expressions (`set SUB=!STR:~%OFFSET%,3!`).
  - Pre-evaluation of nested percent variables in delayed search/replace substitution patterns (`!STR:%OLD%=%NEW%!`).
  - Deobfuscator engine (`src/deobfuscator_engine.py`) negative offset clamping consistency, wildcard prefix substitution (`!filepath:*System32\=!`), backslash replacement safety, and non-greedy colon variable matching.
  - Comprehensive unit test suite expanded across `tests/test_delayed_expansion.py`, `tests/test_ast_suite.py`, and `tests/test_deobfuscator.py` (total 54 passing unit tests).

## [0.1.0] - 2026-10-12

### Added
- Initial project scaffold and core compiler pipeline (M01).
- Character-level lexical scanner (`src/lexer.py`) modeling cmd.exe Phase 1 and Phase 2 parsing.
- Pushdown automaton state machine (`src/automaton.py`) tracking block nesting and command boundaries.
- Abstract Syntax Tree node hierarchy (`src/ast_nodes.py`) and recursive descent parser (`src/parser.py`).
- Normalization engine (`src/normalizer.py`) and multi-pass deobfuscator (`src/deobfuscator_engine.py`).
- Visualizer engine (`src/visualizer.py`) rendering ASCII trees, Mermaid graphs, and JSON outputs.
- Command-line interface (`src/cli.py`) with deobfuscate, ast, and visualize commands.
- Initial test suite with 16 test cases.
