# 🔍 전담 작업자 피드백 감사 및 리팩토링 체크리스트 (feedback_audit.md)

> **[상위 지침 연동]**: `_BY_PASSS/WORKER_FEEDBACK_GUIDE.md`
> **[기억 리트리벌 키워드]**: `@feedback`, `@clean-root`, `@english-naming`, `@semantic-commit`, `@security-audit`, `@custom-license`

---

## 📌 본 저장소 필수 개선 액션 플랜

- [x] **1. [@clean-root] 루트 디렉터리 슬림화 (최대 6~7개 항목 유지)**:
  - 첫 접속 시 화면에 README.md와 히어로 배너가 가려지지 않도록 루트를 슬림화 완료.
  - `rules/` -> `references/detection_rules/`, `samples/` -> `references/classic_samples/` 이동 완료.
  - 루트에는 오직 `src/`, `docs/`, `references/`, `tests/`, `memory/`, `LICENSE`, `README.md` (6개 디렉터리 + 3개 파일)만 유지.

- [x] **2. [@english-naming] 100% 영문 디렉터리 및 파일명 표준화**:
  - `references/batch_corpus_28`
  - `references/huggingface_ai`
  - `references/classic_samples`
  - `references/detection_rules`
  - 저장소 내 모든 폴더 및 파일명에서 한글 100% 배제 및 영문 표준화 검증 완료 (0건).

- [x] **3. [@semantic-commit] 파일/모듈별 맥락 커밋 메시지 분리**:
  - 일괄 커밋 도배(`feat: release ...`) 배제, 파일/모듈 단위 시맨틱 커밋 12단계 분리 적용.
    - `refactor(layout): slim root directory and relocate rules and samples to references`
    - `chore(license): apply dedicated Maya Thorne Systems & Security Research License (MT-SRL)`
    - `feat(lexer): implement cmd.exe lexical analyzer and 18-token specifications`
    - `feat(automaton): implement pushdown automaton state transition engine`
    - `feat(ast): implement abstract syntax tree nodes and recursive descent parser`
    - `feat(normalizer): implement AST normalizer with environment slicing and symbol propagation`
    - `feat(visualizer): implement ASCII box-drawing tree, mermaid diagram, and json visualizers`
    - `feat(cli): implement command-line interface with utf-8 encoding support`
    - `docs(spec): add cmd.exe EBNF grammar, pushdown automata, and AST architecture specifications`
    - `test(ast): add comprehensive AST unit tests and compiler invariant suites`
    - `docs(locales): synchronize multilingual documentation with clean root and new ast architecture`
    - `docs(memory): update feedback audit and active task checklists`

- [x] **4. [@security-audit] 전수 보안 감사 (Zero-Leak Audit)**:
  - `.env`, 임시 캐시(`.cache`, `__pycache__`), 디버그 로그, 불필요한 대용량 바이너리 배제 완료.
  - `.gitignore` 파일에 민감 파일 및 불필요 아티팩트 차단 룰 대폭 강화.

- [x] **5. [@custom-license] Maya Thorne 전용 라이선스 적용**:
  - 루트의 `LICENSE` 파일을 Maya Thorne Systems & Security Research License (MT-SRL)로 교체 완료.
