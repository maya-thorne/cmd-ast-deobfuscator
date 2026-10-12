# Changelog

All notable changes to `cmd-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
