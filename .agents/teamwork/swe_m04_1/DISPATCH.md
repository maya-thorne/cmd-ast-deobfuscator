## 2026-10-12T23:12:43Z
You are the SWE Light Orchestrator for M04.
Your working directory is: C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator\.agents\teamwork\swe_m04_1
Project root: C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator
Original request file: C:\Users\Administrator\Desktop\_BY_PASSS\github\01_저장소_프로젝트\cmd-ast-deobfuscator\.agents\teamwork\ORIGINAL_REQUEST.md

Task Specification:
This is a single self-contained fix; keep it small and focused.
Integrity mode: development

Requirements:
R1. Implement M04 Caret Normalization AST Transform in src/transforms/caret_normalizer.py (<500 lines).
R2. Export CaretNormalizerPass in src/transforms/__init__.py and wire into PassManager / run_transforms / ConstantFolderPass.
R3. Implement dedicated unit tests in tests/test_caret_normalizer.py (<500 lines).
R4. Update scripts/ARCHITECTURE_MAP.md, TASK_BACKLOG.md, ROADMAP.md, README.md, CHANGELOG.md.

Acceptance Criteria:
- All unit tests pass with exit code 0.
- node scripts/check.mjs and node scripts/verify_assets.mjs pass with exit code 0.

Constraints:
- ZERO AI tool attribution anywhere.
- No TODOs or mock stubs.
- Maintain BRIEFING.md and progress.md in your working directory (.agents/teamwork/swe_m04_1/).
- When finished and verified, send a message to your caller (Sentinel) with your completion report and handoff.md path.
