# BRIEFING — Implementer M04

## Mission
Implement M04 Caret Normalization AST Transform in `src/transforms/caret_normalizer.py` (<500 lines), export and wire into `src/transforms/__init__.py`, `PassManager`, `run_transforms`, and `ConstantFolderPass`, implement comprehensive unit tests in `tests/test_caret_normalizer.py` (<500 lines), and update architecture docs and project roadmaps.

## 🔒 Identity & Constraints
- Role: `teamwork_preview_implementer` (SWE Light Implementer)
- Working directory: `C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator\.agents\teamwork\teamwork_preview_implementer_m04_1`
- Parent orchestrator ID: `193c0877-3305-4fde-9e39-c25a62f92a9d`
- ZERO AI tool attribution anywhere.
- No TODOs or mock stubs.
- Verifiable with `python -m unittest discover tests`, `node scripts/check.mjs`, and `node scripts/verify_assets.mjs`.

## Requirements Checklist
- [x] R1: Implement M04 Caret Normalization AST Transform in `src/transforms/caret_normalizer.py` (399 lines, <500 lines limit).
- [x] R2: Export `CaretNormalizerPass` in `src/transforms/__init__.py` and wire into `PassManager` / `run_transforms` / `ConstantFolderPass`.
- [x] R3: Implement dedicated unit tests in `tests/test_caret_normalizer.py` (267 lines, <500 lines limit, 28 tests).
- [x] R4: Update `scripts/ARCHITECTURE_MAP.md`, `TASK_BACKLOG.md`, `ROADMAP.md`, `README.md`, `CHANGELOG.md`, and `pyproject.toml`.

## Verification Record
- Python unittests: 116/116 tests passing (exit code 0).
- `node scripts/check.mjs`: All steps passed (exit code 0).
- `node scripts/verify_assets.mjs`: 58 Markdown files & 21 SVG files checked (exit code 0).
- Line counts:
  - `src/transforms/caret_normalizer.py`: 399 lines (<500)
  - `tests/test_caret_normalizer.py`: 267 lines (<500)
- Invariants: 0 external image leaks, 0 AI attribution terms, 0 TODOs/stubs.
