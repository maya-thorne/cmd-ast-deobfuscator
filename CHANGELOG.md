# Changelog

All notable changes to `cmd-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
