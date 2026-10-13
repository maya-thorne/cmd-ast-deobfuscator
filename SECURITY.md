# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Static Analysis & Memory Safety Invariants

1. **Static Offline Execution**: The AST parser, automaton state machine, and transform passes analyze batch syntax statically in memory without ever spawning or invoking guest shell processes or executing commands.
2. **Bounds & Overflow Protection**: Substring slicing (`%VAR:~s,l%`), index parsing, and variable table evaluations enforce strict length clamping, non-negative offsets, and bounded iterations to prevent stack overflow or memory exhaustion on malicious inputs.
3. **Regular Expression & Injection Defense**: Dynamic search and substitution expressions (`%VAR:s1=s2%`) are sanitized using `re.escape()` and literal lambda replacers, eliminating regex injection and unintended backreference expansions.
4. **Credential & Environment Hygiene**: Virtual symbol tables and AST visitor instances provide complete environment isolation from the host operating system, preventing accidental disclosure of host environment variables.
5. **Caret Iteration Caps & Escape Depth Bounds**: Multi-level caret reduction algorithms enforce bounded pass iterations (default max 10 passes) with fixed-point termination guards, preventing infinite looping or memory exhaustion when processing pathological input containing recursive caret sequences.
6. **Benchmark Sandbox & Zero Dynamic Execution**: The benchmark evaluation harness (`src/benchmark/`) processes all real-world adversarial samples strictly offline in memory using static AST transformations, with zero dynamic shell dispatch, external network requests, or child process spawning.
7. **Static Path Modifier Sandboxing**: Parameter and FOR variable path modifier resolution (`%~dp0`, `%~f1`, `%~$PATH:i`) operates strictly on static lexical strings and mock directory structures by default, preventing arbitrary disk access or path traversal exploits during static analysis.
8. **Static CFG Boundary Safety & Loop Depth Clamping**: Control Flow Graph (CFG) block partitioning and dynamic jump table tracking enforce recursion limits, cycle detection via DFS back-edge discovery, and bounded BFS reachability exploration. Dynamic variable expansions in jumps are resolved against strictly isolated in-memory symbol tables without executing external processes or evaluating arbitrary shell commands.
9. **Dead Code Elimination & Static Liveness Bounds**: The Dead Code Elimination (DCE) optimization pass computes variable liveness and dead store analysis strictly in-memory using static AST traversal. Fixed-point optimization iterations are capped (default max 10 iterations) with loop convergence detection to prevent denial-of-service on cyclic or deeply nested control flows. Standard system environment variables (`DEFAULT_PRESERVE_VARS`) and explicit user symbols are safeguarded against accidental pruning, ensuring semantic equivalence of preserved code.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or cryptographic flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
