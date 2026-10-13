# Briefing: M08 - Dead Code Elimination (DCE) and SET Pruning Pass

## Goal
Implement and verify M08 optimization pass: Dead Code Elimination (DCE) and SET Pruning for cmd-ast-deobfuscator.

## Scope of Work
1. `src/transforms/dce.py`:
   - Enhance `DeadCodeEliminationPass`, `VariableLivenessAnalyzer`, and `DCEMetrics`.
   - Ensure support for:
     * Unreferenced variable pruning (including within chains, blocks, scripts).
     * Overwritten dead store elimination (linear statements and chains).
     * Unreachable statement pruning (post-`goto` / post-`exit` before `LabelNode`).
     * Empty block / chain cleanup (`()`, empty chains).
     * Configurable `preserve_vars` (case-insensitive).
     * Transitive dependency pruning across iterations.
     * Accurate reference tracking across all node types (`VarExpandNode`, `IfNode` defined, `ForNode`, `CommandNode`, `GotoNode`, `CallNode`, arithmetic `set /a`).
   - Line count constraint: keep `src/transforms/dce.py` under 500 lines.
2. Pipeline & CLI Integration:
   - `src/transforms/__init__.py`: Export `DeadCodeEliminationPass`, etc.
   - `src/transforms/base.py`: PassManager and run_transforms support `enable_dce`.
   - `src/normalizer.py`: ASTNormalizer support `enable_dce` flag and `preserve_vars`.
   - `src/cli.py`: `--dce`, `--dce-stats`, `--preserve-vars`.
3. Test Suite:
   - Create `tests/test_dce_suite.py` with comprehensive unit and integration tests.
4. Documentation & Verification:
   - Update `TASK_BACKLOG.md`, `CHANGELOG.md`, `README.md`, `ROADMAP.md`, `scripts/ARCHITECTURE_MAP.md`.
   - Ensure all 190 existing tests pass, new tests pass.
   - Ensure `node scripts/check.mjs` and `node scripts/verify_assets.mjs` exit 0.
