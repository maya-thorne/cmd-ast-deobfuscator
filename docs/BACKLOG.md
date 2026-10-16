# Engineering Task Backlog

This backlog tracks completed engineering milestones, active features, and future development sprints for `cmd-ast-deobfuscator`.

---

## 🏁 Completed Milestones

| Milestone | Capability / Feature | Domain Module | Tests | Version | Status |
|---|---|---|---|---|---|
| **M01** | Core AST Architecture, Lexer & Pushdown Automaton | `src/lexer.py`, `src/parser.py`, `src/automaton.py` | `tests/test_ast_suite.py` | v0.1.0 | Shipped |
| **M02** | Delayed Variable Expansion (`!VAR!`) & Caret Escapes | `src/statement_parsers.py`, `src/normalizer.py` | `tests/test_delayed_expansion.py` | v0.2.0 | Shipped |
| **M03** | Substring Slicing (`%VAR:~s,l%`) Constant Folder Pass | `src/transforms/slicing_folder.py`, `src/transforms/base.py` | `tests/test_slicing_folder.py` | v0.3.0 | Shipped |
| **M04** | Nested Caret Escape Normalization Pass | `src/transforms/caret_normalizer.py` | `tests/test_caret_normalizer.py` | v0.4.0 | Shipped |
| **M05** | Real-World Benchmark Corpus & Entropy Evaluator | `src/benchmark/` | `tests/test_benchmark_suite.py` | v0.5.0 | Shipped |
| **M06** | FOR Loop Variable Scoping & Parameter Path Modifiers | `src/modifiers.py`, `src/transforms/param_resolver.py` | `tests/test_for_param_expansion.py` | v0.6.0 | Shipped |
| **M07** | Control Flow Graph (CFG) Construction & Jump Tables | `src/cfg/` | `tests/test_cfg_suite.py` | v0.7.0 | Shipped |
| **M08** | Dead Code Elimination (DCE) & SET Pruning Pass | `src/transforms/dce.py` | `tests/test_dce_suite.py` | v0.8.0 | Shipped |
| **M09** | 32-bit Signed Arithmetic Evaluator (`set /a`) | `src/arithmetic/`, `src/transforms/arithmetic_folder.py` | `tests/test_arithmetic_suite.py` | v0.9.0 | Shipped |
| **M10** | String Reversal & Transposition Deobfuscation Engine | `src/reversal/`, `src/transforms/reversal_folder.py` | `tests/test_reversal_suite.py` | v0.10.0 | Shipped |
| **M11** | Quote Toggle Boundary & Empty Quote Normalizer | `src/quotes/`, `src/transforms/quote_normalizer.py` | `tests/test_quote_normalizer_suite.py` | v0.11.0 | Shipped |
| **M12** | I/O Redirection & Stream Routing Engine | `src/redirection/`, `src/transforms/redirection_pass.py` | `tests/test_redirection_suite.py` | v0.12.0 | Shipped |
| **M13** | Invoke-DOSfuscation Concatenation Heuristic Engine | `src/dosfuscation/`, `src/transforms/dosfuscation_pass.py` | `tests/test_dosfuscation_suite.py` | v0.13.0 | Shipped |
| **M14** | 0xidiz3r & Batch Packer Detection & Anti-CFF De-flattening | `src/packers/`, `src/cff/`, `src/transforms/deflat_pass.py` | `tests/test_deflat_suite.py` | v0.14.0 | Shipped |
| **M15** | Intermediate Representation (IR) Transpiler (Python & PS1) | `src/ir/`, `src/ir/targets/` | `tests/test_ir_transpiler_suite.py` | v0.15.0 | Shipped |
| **M16** | Terminal AST Inspector & Colored Diff Visualizer (TUI Debugger) | `src/tui/` | `tests/test_tui_inspector_suite.py` | v0.16.0 | Shipped |
| **M17** | High-Throughput Directory Batch Scanner Pipeline | `src/scanner/` | `tests/test_scanner_suite.py` | v0.17.0 | Shipped |
| **M18** | AST-based Malware IOC Extractor & Threat Intelligence Pipeline | `src/ioc/`, `src/transforms/ioc_pass.py` | `tests/test_ioc_suite.py` | v0.18.0 | Shipped |

---

## 🔮 Upcoming Sprint Backlog

### Sprint 19: Multi-Encoding Lossless Ingestion Pipeline (M19)
- **Goal**: Full automatic detection and decoding of legacy batch encodings (ANSI, OEM-CP437, UTF-16LE with null-byte padding, and UTF-8 BOM).
- **Scope**: `src/encodings/` with stream decoders, byte-order-mark filters, and non-destructive AST source mapping.

### Sprint 20: Adversarial Batch Obfuscation Entropy & Threat Scoring (M20)
- **Goal**: Granular structural and lexical threat scoring system for enterprise SIEM, YARA, and Sigma ingestion.
- **Scope**: `src/scoring/` with Shannon entropy deltas, token density metrics, and composite threat score computation.

### Sprint 21: Dynamic AST Instrumentation & Lightweight Runtime Tracer (M21)
- **Goal**: In-memory virtual environment execution sandbox monitoring environment variable mutations and temporary file drops.
- **Scope**: `src/runtime/` with sandboxed cmd.exe built-in emulation and call sequence logs.

### Sprint 22: Ghidra Headless Analyzer Bridge (M22)
- **Goal**: Automated binary forensics pipeline extracting and deobfuscating batch scripts embedded in PE executables and resource sections.
- **Scope**: `src/bridge/ghidra/` with headless script integration.
