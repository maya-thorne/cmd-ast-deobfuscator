# 📋 Worker 4 액티브 태스크 체크리스트 (cmd-ast-deobfuscator)

## 📌 6대 필수 품질 과업

- [x] **1. 실제 깃허브 웹페이지 접속 및 인간 관점 UI/UX 실측 검증**:
  - Chrome CDP(포트 9227) 격리 탭으로 `https://github.com/maya-thorne/cmd-ast-deobfuscator` 접속 실측 완료.
  - AST 파서 구조도, 문법 트리 예시, 상태 머신 다이어그램 가독성 실측 검증 및 스크린샷 2종 캡처 완료 (`Assets_스크린샷/cmd_ast_deobfuscator_*.png`).
  - 모든 이미지는 클릭 시 raw 미디어 뷰어로 튕기지 않도록 `<a href="...">` 래핑 100% 유지.

- [x] **2. 10개국어 다국어 네비게이션 및 시각 자료 현지화**:
  - 10개국어 문서(`docs/locales/*.md`) 링크 100% 정상 작동 검증 및 10종 다크 터미널 SVG 배너 완비.
  - AST 구문 트리 다이어그램, 렉서-파서 파이프라인, 알고리즘 단계별 설명의 레이블 현지화 완료.

- [x] **3. 시각적 에셋(AST 구문 트리 SVG / 상태 머신 다이어그램) 고도화**:
  - 난독화된 배치 코드가 AST 트리 노드로 분해되고 정규화되는 고해상도 SVG 다이어그램 (`docs/assets/cmd_ast_pipeline_architecture.svg`) 완비.
  - 5-Phase 파서 상태 머신 전이 과정을 보여주는 EBNF 및 PDA 명세서 완비.

- [x] **4. GitHub 공식 Release 및 Git Tag (`v1.0.0`) 발행**:
  - `v1.0.0` 태그 생성 및 원격 푸시 완료.
  - GitHub REST API를 통해 AST 파서 코어 모듈, 파싱 알고리즘 스펙, 릴리즈 노트 정식 등록 완료 (ID: 409143124).

- [x] **5. 라이선스(LICENSE) 규격화 및 컴파일러 공학 명세**:
  - 공식 LICENSE (Maya Thorne Systems & Security Research License, MT-SRL) 완비 및 학술 연구 면책 조항 명시.
  - EBNF 문법 명세(`docs/CMD_EXE_EBNF_GRAMMAR.md`), 오토마타 명세(`docs/PUSHDOWN_AUTOMATA_SPECIFICATION.md`), AST 구조도(`docs/AST_NODE_ARCHITECTURE.md`) 완비.

- [x] **6. 전역 규칙 준수 (AI 도구명/워터마크 0건)**:
  - 코드, 알고리즘 주석, 문서 어디에도 AI 도구명이나 워터마크가 들어가지 않도록 전수 감사 완료 (0건 확인).

---

## 🛠️ 최근 유지보수 및 무결성 강화 작업 (Maintenance & Invariant QA)

- [x] **1. 파손된 SVG 에셋 XML 문법 복구**:
  - `docs/assets/cmd_ast_pipeline_architecture.svg` 내 비이스케이프 `&` 기호를 `&amp;`로 완벽 치환.
  - Python `xml.etree.ElementTree` 및 PowerShell `[xml]` 파싱 100% 무결성 통과 검증 완료.
- [x] **2. 깨진 목차(TOC) 앵커 링크 3종 및 명시적 span id 복구**:
  - URL 인코딩된 `%EF%B8%8F` 바이트 제거 및 명시적 `<span id="...">` 앵커 배치:
    * `⚙️ cmd.exe 5-Phase Parser State Machine` -> `<span id="cmdexe-5-phase-parser-state-machine"></span>` / `#cmdexe-5-phase-parser-state-machine`
    * `🛡️ 12 Major Obfuscation Vectors Countered` -> `<span id="12-major-obfuscation-vectors-countered"></span>` / `#12-major-obfuscation-vectors-countered`
    * `⚖️ License & Responsible Disclosure` -> `<span id="license--responsible-disclosure"></span>` / `#license--responsible-disclosure`
  - 10개국어 문서(`docs/locales/*.md`) 목차 앵커도 전수 동기화 및 무결성 검증 완료.
- [x] **3. 저장소 구조(Repository Structure) 아키텍처 맵 표 구축**:
  - `README.md` 내 `### 📁 Repository Architecture & Directory Map` 신규 섹션 구축.
  - 루트(`README.md`, `LICENSE`, `.gitignore`), `src/`(9개 핵심 모듈), `tests/`(2개 테스트 스위트) 및 보조 디렉터리 1줄 설명 HTML 표 완비.
- [x] **4. 보안 & .gitignore 표준화**:
  - `.gitignore`에 `memory/` 및 `.gemini/` 배제 규칙 표준화 완료.
  - 로컬 `memory/` 디렉터리 파일 점검 및 상태 최신화 완료.

---

## 🚀 실행 모드 & 협업 도구 지침 (Teamwork & Quality Invariants)
- 🤖 **/teamwork-preview 및 멀티 에이전트 협업 허용**: 필요 시 /teamwork-preview 및 서브에이전트 병렬 디스패치(invoke_subagent)를 적극 활용하여 작업 생산성 및 리서치/검증 품질을 극대화할 수 있습니다.
- 💎 **토큰 제한 없음 (Uncapped Token Mode)**: 토큰을 아끼기 위해 코드를 축약하거나 문서를 요약하지 마십시오. 완전한 코드, 완전한 다국어 문서, 고해상도 시각 에셋을 타협 없이 완성하십시오.
- 🔥 **/goal 완주 철칙**: **대충 X · 토큰제한X · 오래 걸린다고 품질 저하X**. 6대 품질 과업(브라우저 실측 검증, 10개국어 다이어그램 현지화, SVG/GIF 에셋, v1.0.0 릴리즈/태그, LICENSE)을 기계적/시각적으로 100% 입증될 때까지 완주하십시오.

---

## 🔍 피드백 리팩토링 & 키워드 기억 리트리벌 (Memory Recall Protocol)
> **[전담 피드백 체크리스트]**: `memory/feedback_audit.md` (상위: `_BY_PASSS/WORKER_FEEDBACK_GUIDE.md`)
- [x] **`@clean-root`**: 루트 항목을 6~7개로 극도 슬림화 (백서는 `docs/whitepapers/`, 레퍼런스는 `references/`로 이동하여 첫 뷰포트 배너 노출 보장).
- [x] **`@english-naming`**: 한글 폴더/파일명 전면 금지, 100% 영문 표준 네이밍 치환.
- [x] **`@semantic-commit`**: 일괄 커밋 도배 금지, 파일/모듈별 개별 맥락 커밋 메시지 적용.
- [x] **`@security-audit`**: `.env`, 캐시, 불필요 바이너리 등 배제 및 클린 커밋 검증, `memory/` 원격 추적 차단 완료.
- [x] **`@custom-license`**: Maya Thorne 전용 연구 라이선스(MT-SRL) 적용.
- [x] **`@table-ux`**: 마크다운 표 30:70 HTML 너비 통제 및 9개국어 문서 동기화 완료.
- [x] **`@responsive-audit`**: 6대 디바이스(iPhone SE, iPhone 16, Galaxy A55, iPad Mini, iPad Pro 13, Desktop 1440) 실측 캡처 검증 완료.
- [x] **`@feedback`**: 사용자 3대 시각 피드백 종합 반영 체크리스트 완수.
- [x] **`@localized-diagrams`**: 10개국 언어별 맞춤형 SVG 아키텍처 다이어그램(`docs/assets/locales/<lang>/pipeline_architecture.svg`) 생성 및 XML 무결성 100% 검증 완료.
- [x] **`@collapsible-sections`**: `README.md` 및 10개국어 문서 전체에 5대 핵심 섹션 인터랙티브 접기/펼치기(`<details open><summary>`) 적용 완료.
- [x] **`@live-cdp-audit`**: Chrome CDP 포트 9227을 통한 원격 GitHub 실측 렌더링 검증 및 고해상도 스크린샷 캡처 완료 (영문 및 한국어 뷰포트 100% 정상 노출).
