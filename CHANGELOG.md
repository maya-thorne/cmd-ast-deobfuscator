# Changelog

All notable changes to `cmd-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
