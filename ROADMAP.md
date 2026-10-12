# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for `cmd-ast-deobfuscator`.

---

## Shipped Capabilities

- [x] **Core AST Architecture & Tokenizer** — Lexical scanner, pushdown automaton state machine, abstract syntax tree models, and base visitor pipeline.
- [x] **Delayed Variable Expansion (`!VAR!`) Engine** — Lexical tokenization, recursive descent AST parsing, caret escape handling, and multi-pass delayed evaluation.
- [x] **Substring Slicing Constant Folding Pass** — Compiler optimization pass (`src/transforms/`) featuring `SlicingFolderPass`, `ConstantFolderPass`, and `PassManager` for fixed-point resolution of `%VAR:~s,l%` expressions, negative indices, boundary clamping, omitted parameters, nested parameters, and contiguous slice coalescing.
- [x] **Nested Caret Escape Normalization** — AST transform pass (`src/transforms/caret_normalizer.py`) featuring `CaretNormalizerPass` and `normalize_carets` for multi-level escape sequence resolution (`^^^`), quoting boundary tracking, adjacent literal coalescing, and pipeline integration into `PassManager` and `ConstantFolderPass`.

---

## Planned Milestones

- [ ] **Real-World Sample Deobfuscation Benchmark** — End-to-end evaluation suite targeting classic malware loaders, Invoke-DOSfuscation, and 0xidiz3r script patterns.
- [ ] **FOR Loop Parameter Expansion (`%%i`, `%~dp0`, `%~f1`)** — Tokenizer and AST nodes for loop variables and file-path expansion modifiers.
- [ ] **Control Flow Graph (CFG) Construction** — Dynamic jump and label analysis for `CALL` and `GOTO` statements.
- [ ] **Dead Code Elimination (DCE)** — Removal of unreferenced variable assignments and unreachable command branches.
- [ ] **Arithmetic Expression Folding (`set /a`)** — Constant evaluation for obfuscated arithmetic operations.
- [ ] **Multi-Encoding Lossless Ingestion Pipeline** — Automatic detection and decoding of legacy batch encodings (ANSI, OEM-CP437, UTF-16LE, and UTF-8 BOM).
- [ ] **Adversarial Batch Obfuscation Entropy & Threat Scoring** — Heuristic detection and complexity metrics for enterprise SIEM, YARA, and Sigma integration.
