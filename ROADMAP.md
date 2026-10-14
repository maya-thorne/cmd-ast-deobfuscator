# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for `cmd-ast-deobfuscator`.

---

## Shipped Capabilities

- [x] **Core AST Architecture & Tokenizer** — Lexical scanner, pushdown automaton state machine, abstract syntax tree models, and base visitor pipeline.
- [x] **Delayed Variable Expansion (`!VAR!`) Engine** — Lexical tokenization, recursive descent AST parsing, caret escape handling, and multi-pass delayed evaluation.
- [x] **Substring Slicing Constant Folding Pass** — Compiler optimization pass (`src/transforms/`) featuring `SlicingFolderPass`, `ConstantFolderPass`, and `PassManager` for fixed-point resolution of `%VAR:~s,l%` expressions, negative indices, boundary clamping, omitted parameters, nested parameters, and contiguous slice coalescing.
- [x] **Nested Caret Escape Normalization** — AST transform pass (`src/transforms/caret_normalizer.py`) featuring `CaretNormalizerPass` and `normalize_carets` for multi-level escape sequence resolution (`^^^`), quoting boundary tracking, adjacent literal coalescing, and pipeline integration into `PassManager` and `ConstantFolderPass`.
- [x] **Real-World Sample Deobfuscation Benchmark & Evaluation Suite** — Quantitative evaluation harness (`src/benchmark/`) computing Shannon entropy deltas, AST node reduction, and lexical token density across 12 production-representative obfuscation patterns with 100% ground-truth payload recovery.
- [x] **FOR Loop Variable & Parameter Path Modifier Interpreter** — Tokenizer, AST nodes, and evaluation engine (`src/modifiers.py`, `src/transforms/param_resolver.py`) supporting parameter path modifiers (`~dp`, `~f`, `~nx`, `~s`, `~a`, `~t`, `~z`, `~$PATH:`), 8.3 short name conversion, and FOR loop block statements.
- [x] **Control Flow Graph (CFG) Construction & Dynamic Jump Table Resolver** — Basic block partitioning, cmd.exe label fallthrough semantics, edge classification, reachability analysis, McCabe cyclomatic complexity metric, symbolic dynamic jump resolution (`goto %VAR%`, `call !TARGET!`), pattern prefix matching, Control Flow Flattening (CFF) dispatcher identification, and multi-format exporters (Mermaid, DOT, ASCII, JSON).
- [x] **Dead Code Elimination (DCE) & Unreferenced SET Pruning Pass** — Compiler optimization pass (`src/transforms/dce.py`) featuring `DeadCodeEliminationPass`, `VariableLivenessAnalyzer`, and `DCEMetrics` for fixed-point elimination of unreferenced variable assignments, consecutive dead store overwrites, unreachable statements following unconditional terminators (`exit`, `goto`), redundant block collapsing, and configurable symbol preservation.
- [x] **Arithmetic Expression Folding (`set /a`) & AST Optimization Pass** — Compiler-grade arithmetic evaluation engine (`src/arithmetic/`, `src/transforms/arithmetic_folder.py`) featuring `CmdArithmeticEvaluator` and `ArithmeticFolderPass` supporting 32-bit signed two's complement integer math, cmd.exe arithmetic and bitwise operators (`*`, `/`, `%`, `+`, `-`, `<<`, `>>`, `&`, `^`, `|`, `~`, `!`), compound assignments (`+=`, `-=`, etc.), comma-separated sequencing, decimal/hex/octal literal formats, and zero-division fault protection.
- [x] **String Reversal & Transposition Deobfuscation Engine** — Dedicated domain package (`src/reversal/`, `src/transforms/reversal_folder.py`) featuring `StringReversalAutomaton`, `ReversalPatternDetector`, and `ReversalFolderPass` for resolving Somalifuscator-style `FOR /L` reverse loops (`for /l %i in (len,-1,0)`), `FOR IN` dictionary index transpositions (`for %a in (indices)`), pushdown stack GOTO loops, decreasing slice sequences, rail-fence transpositions, and pipeline integration into `PassManager` and `BatchDeobfuscator`.
- [x] **Quote Toggle Boundary & Nested Quote Normalization Engine** — Dedicated domain package (`src/quotes/`, `src/transforms/quote_normalizer.py`) featuring `QuoteToggleAutomaton`, `QuoteNormalizer`, and `QuoteNormalizerPass` for tracking cmd.exe quotation toggle boundaries, unmasking escaped quotes (`^"`), collapsing empty quote pairs (`""`), reducing multi-level consecutive quotes (`""""`, `""""""`), deobfuscating command target executable names (`"c"m"d"` -> `cmd`), canonicalizing command arguments with whitespace/metacharacter awareness, and normalizing enclosed variable assignments (`set "k=v"`).
- [x] **I/O Redirection & Stream Routing Engine** — Dedicated domain package (`src/redirection/`, `src/transforms/redirection_pass.py`) featuring `StreamRouter`, `RedirectEntry`, `RedirectPlan`, and `RedirectionPass` for simulating cmd.exe stream handle routing, handle duplication chains (`2>&1`, `1>&2`, `>&2`), handle closing (`2>&-`), source handle routing (0..9), device sink classification (`nul`, `con`, `prn`, `aux`, `com1`..`com9`, `lpt1`..`lpt9`), stealth suppression pattern detection, caret/quote destination unmasking, unparsed literal argument lifting, and parenthesized block redirection grammar separation.
- [x] **Invoke-DOSfuscation Concatenation Pattern Heuristic Engine** — Dedicated domain package (`src/dosfuscation/`, `src/transforms/dosfuscation_pass.py`) featuring `DosfuscationConcatenationDecoder`, `DosfuscationDetector`, and `DosfuscationPass` for unmasking environment variable fragment chains (`%a%%b%%c%`), eliminating interleaved empty/junk variables (`%junk%c%junk%m%junk%d`), normalizing scrambled parameter delimiters (`,`, `;`) outside quotes and variable slices, folding FOR token accumulator loops into constant assignments, unrolling dynamic CALL execution trampolines, and scoring Invoke-DOSfuscation levels 1 through 5.

---

## Planned Milestones

- [ ] **Multi-Encoding Lossless Ingestion Pipeline** — Automatic detection and decoding of legacy batch encodings (ANSI, OEM-CP437, UTF-16LE, and UTF-8 BOM).
- [ ] **Adversarial Batch Obfuscation Entropy & Threat Scoring** — Heuristic detection and complexity metrics for enterprise SIEM, YARA, and Sigma integration.
- [ ] **Dynamic AST Instrumentation & Runtime Tracer** — Lightweight execution tracer monitoring runtime environment variable mutations and temporary file drops.
- [ ] **Ghidra Headless Analyzer Bridge** — Bidirectional IPC interface for automated extraction and AST deobfuscation of embedded batch scripts inside compiled executables.
- [ ] **Symbolic Variable Scope & Environment Stack (SETLOCAL/ENDLOCAL)** — Procedure call frames and localized symbol stack simulator.
- [ ] **Automated YARA Rule Synthesizer** — AST pattern-based rule generation for static malware triage and defense.
- [ ] **Automated De-Flattening & Control Flow Unweaving (Anti-CFF Pass)** — State machine unrolling and linear restructuring for control-flow-flattened batch obfuscators.
- [ ] **Batch Script Taint Analysis & Data Flow Tracking** — Source-to-sink tracking for untrusted user inputs and execution sinks (cmd.exe, powershell, certutil, wscript).
- [ ] **Bat2Exe Embedded Archive Extractor & Binary Forensics Pipeline** — Static extraction and decompilation of embedded `.bat` scripts packed inside PE binaries (IExpress, Quick Batch Compiler, Bat To Exe Converter).
- [ ] **Batch Script Static CFG Dominator Tree & Natural Loop Detection** — Dominance frontiers, loop headers, and back-edge cycle decomposition for automated restructuring of obfuscated spaghetti control flows.
- [ ] **Metamorphic Batch Script Normalization & Entropy Flattening Pass** — Reversing anti-signature polynomial transformations and mutating command aliases.
- [ ] **Batch Script Mixed Code Page (CHCP 65001, 949, 1252) & Multi-Byte Normalization Pass** — Restoring localized character set and code page obfuscation.
- [ ] **Obfuscated Batch Virtual Machine (Batch-VM / Bytecode Interpreter) Decompiler** — Static symbol recovery and instruction lifting for virtualized batch malware.
