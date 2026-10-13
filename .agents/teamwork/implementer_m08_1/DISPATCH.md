## 2026-10-13T03:08:30Z
Working directory: C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator\.agents\teamwork\implementer_m08_1
Project root: C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator
Parent orchestrator: f62ae840-5f9c-41d5-925d-474d58360fb9

Task Specification:
This is a single self-contained fix; keep it small and focused.
Implement M08 - Dead Code Elimination (DCE) and SET Pruning Optimization Pass for cmd-ast-deobfuscator.
Integrity mode: development

Requirements:
- R1: Module Architecture (`src/transforms/dce.py`):
  - Implement `DeadCodeEliminationPass` (inheriting from `TransformPass`), `VariableLivenessAnalyzer`, and `DCEMetrics`.
  - Support:
    1. Unreferenced variable pruning (`set VAR=val` where `VAR` is never used across the AST).
    2. Overwritten dead store elimination (`set VAR=val1` immediately followed by `set VAR=val2` without intervening read/branch).
    3. Unreachable statement pruning (statements following unconditional `goto :target` or `exit` / `exit /b` before a `LabelNode`).
    4. Empty block / chain cleanup (`()`, empty statements).
    5. Configurable `preserve_vars` (e.g. standard environment variables, caller exports).
    6. Case-insensitive variable lookup (`.lower()`).
    7. Accurate reference tracking across `VarExpandNode` (%VAR%, !VAR!, slices, search/replace), `IfNode` conditions (`defined VAR`, etc.), `ForNode`, `CommandNode`, `GotoNode`/`CallNode`.
  - Keep `src/transforms/dce.py` under 500 lines.
- R2: Pipeline & CLI Integration:
  - Export `DeadCodeEliminationPass` in `src/transforms/__init__.py`.
  - Integrate with `PassManager` and `ASTNormalizer` (optional `enable_dce` flag).
  - Add CLI flags in `src/cli.py`: `--dce`, `--dce-stats`, `--preserve-vars`.
- R3: Test Suite (`tests/test_dce_suite.py`):
  - Comprehensive unit and integration tests covering unreferenced variable pruning, transitive dependency pruning (`set a=1 & set b=%a%`), dead overwrites, unreachable branches, `if defined` preservation, preserved roots, and metrics.
- R4: Verification & Documentation:
  - All existing 190 tests plus new DCE tests must pass. Keep existing benchmark and tests intact.
  - `node scripts/check.mjs` and `node scripts/verify_assets.mjs` pass with exit code 0.
  - Update `TASK_BACKLOG.md` (mark M08 completed), `CHANGELOG.md`, `README.md`, `ROADMAP.md`, `scripts/ARCHITECTURE_MAP.md`.

Acceptance Criteria:
- All unit and integration tests pass with exit code 0.
- `node scripts/check.mjs` and `node scripts/verify_assets.mjs` pass with exit code 0.

Constraints:
- ZERO AI tool attribution anywhere.
- No TODOs or mock stubs.
- Maintain BRIEFING.md and progress.md in your working directory (.agents/teamwork/implementer_m08_1/).
- When finished and verified, write handoff.md and send a message to your orchestrator (f62ae840-5f9c-41d5-925d-474d58360fb9) with your verification record and report.
