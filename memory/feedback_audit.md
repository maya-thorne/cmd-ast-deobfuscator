# 🧠 프로젝트 로컬 메모리: 작업자 피드백 & UI/UX 감사 표준 (feedback_audit.md)

> **[위치]**: `_BY_PASSS/memory/feedback_audit.md` (로컬 전용 메모리)  
> **[역할]**: 5개 연구 저장소 작업자(Worker 1 ~ Worker 5)가 세션 시작 또는 작업 분기 시 키워드로 회상(Recall)하여 준수해야 하는 최종 UI/UX 및 리팩토링 불변식.

---

## 🔑 1. 키워드 기반 기억 인덱스 (Memory Retrieval Keywords)

작업자가 작업 도중 아래 키워드를 마주치면 즉시 기억을 되살려 행동 양식을 일치시킵니다:

| 리트리벌 키워드 | 발동되는 핵심 행동 양식 및 규격 |
| :--- | :--- |
| **`@clean-root`** | 루트 디렉터리 항목을 5~7개로 극도 슬림화하여 첫 화면 README 히어로 배너 노출 보장 |
| **`@english-naming`** | 한글 폴더/파일명 전면 금지, 100% 영문 케밥/스네이크 케이스 표준화 (`references/batch_corpus_28/` 등) |
| **`@semantic-commit`** | 일괄 커밋(`git add .`) 도배 금지, 파일·모듈별 개별 맥락 커밋 메시지 (`feat(ast):`, `docs(whitepaper):`) 적용 |
| **`@security-audit`** | `.env`, 빌드 아티팩트, 임시 로그, 더미 바이너리 누출 차단 (Zero-Leak) |
| **`@custom-license`** | Maya Thorne 전용 시스템 & 보안 연구 라이선스(`MT-SRL`) 100% 적용 |
| **`@svg-typography`** | SVG 다이어그램 텍스트 침범 방지 (카드폭 176px+, 2줄 텍스트 래핑, `geometricPrecision` 선명 폰트) |
| **`@table-ux`** | 마크다운 표 HTML `<table>` 너비 통제 (30:70 비율), 2줄 링크 구조, 외톨이 글자(Orphan wrap) 완전 제거 |
| **`@responsive-audit`** | 모바일(iPhone SE 375px, iPhone 16, Galaxy A55)~태블릿(iPad Mini, Pro)~PC(1440px) 전 환경 실측 검증 및 `<wbr>` 삽입 |
| **`@ui-ux-standard`** | 위 SVG, 테이블 및 반응형 규격을 포함한 저장소 전역 UI/UX 표준 강제 적용 |
| **`@feedback`** | 위 모든 피드백 전수 종합 검증 및 리팩토링 체크리스트 완수 |

---

## 📐 2. SVG 다이어그램 UI/UX 불변식 (`@svg-typography`)

1. **텍스트 박스 침범(Overflow) 절대 금지**:
   - 단일행 `<text>`에 긴 문자열을 통째로 넣으면 영문/다국어에서 박스 오른쪽 테두리를 뚫고 나감 (`Phase 2: Caret & Quote Stripp...`).
   - 반드시 단계 접두사(`PHASE 02`, `2단계`)와 메인 타이틀을 분리하고, 메인 타이틀은 16자 내외로 2줄 래핑(`wrapText`)하여 배치.
   - 카드 가로폭을 최소 `176px` 이상으로 확보.
2. **크리스탈 선명도 (Zero-Blur Monospace)**:
   - 하단 인디케이터/덤프 박스 내 모노스페이스 폰트는 `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace` 폰트 스택 적용.
   - 최소 폰트 크기 `9.5px` 이상 지정 및 `text-rendering="geometricPrecision"` 속성 필수 부여 (픽셀 뭉개짐 원천 방지).
   - 상태 배지(`STATUS: EVAL_OK`)는 별도 미니 렉트(`rx="3"`)로 녹색 네온 대비 강조.

---

## 📊 3. 마크다운 테이블 UI/UX 불변식 (`@table-ux`)

1. **HTML `<table>` 30:70 황금 분할**:
   - GitHub 마크다운 기본 파이프 표(`|---|---|`)는 긴 단일행 파일명에 50~60%의 폭을 빼앗겨 왼쪽은 텅텅 비고 오른쪽 핵심 기술 설명은 찌그러짐.
   - 반드시 HTML `<table width="100%">`를 사용하여 `<th width="30%~32%">` vs `<th width="68%~70%">`로 너비를 통제.
2. **파일명 2줄 구조 (Two-Line Artifact Representation)**:
   - 직관적인 문서 타이틀 링크 + 하단 `<code>파일명.md</code>`의 2줄 구조로 배치하여 가로폭 폭주를 원천 차단하고 시각적 전문성 극대화.
3. **외톨이 단어/글자 줄바꿈(Orphan Wrapping) 및 공백 버그 제거**:
   - 인라인 코드 블록 뒤 쉼표/마침표 앞 공백(`Invoke-DOSfuscation ,` ➔ `Invoke-DOSfuscation,`) 전수 제거.
   - 넉넉한 70% 가로폭을 통해 주요 기술 키워드가 1~2글자만 다음 줄로 밀려나는 현상 완전 근절.

---

## 📱 4. 멀티 디바이스 반응형 실측 불변식 (`@responsive-audit`)

1. **긴 파일명 단어 경계 줄바꿈 (`<wbr>` 인라인 태그)**:
   - 40~50자 이상의 긴 마크다운 백서 파일명(`BATCH_OBFUSCATION_ARCHITECTURE_AND_CODE_ANALYSIS.md`)은 브라우저 렌더러에서 단어 중간이 쪼개지거나 마지막 1글자(`.md` 또는 `d`)만 고립되어 다음 줄로 떨어지는 Orphan Wrap 현상이 발생함.
   - 반드시 언더스코어(`_`) 뒤에 `<wbr>` 태그를 삽입(`BATCH_OBFUSCATION_<wbr>ARCHITECTURE_<wbr>AND_CODE_ANALYSIS.md`)하여 모바일(375px) 화면에서도 의미론적 2~3줄로 완벽히 분할되도록 제어.
2. **테이블 모바일 가로 스크롤 및 최소 폭 (`min-width: 580px~620px`)**:
   - 모바일 화면(375px~412px)에서 2~4열 테이블이 강제로 압축되어 글자가 난장판으로 쪼개지는 것을 방지하기 위해 가로 스크롤 컨테이너(`.table-scroll-wrap`)를 보장.
3. **SVG 다이어그램 멀티 해상도 벡터 스케일링**:
   - `viewBox="0 0 1000 500"` 또는 `viewBox="0 0 1000 390"` 표준 뷰박스 확장 + `width="100%"` 벡터 스케일링으로 모바일 초소형부터 4K 와이드까지 텍스트 테두리 침범 0% 및 선명도 100% 유지.

---

## 🛡️ 5. 로컬 메모리 격리 불변식

- `memory/` 폴더는 AI 작업자의 로컬 인지 및 태스크 관리를 위한 내부 파일이므로, 모든 저장소의 `.gitignore`에 등록하여 **GitHub 원격 저장소에는 일체 업로드되지 않도록 원격 추적을 전면 차단**합니다.
- 외부 방문자에게는 오직 `src`, `docs`, `references`, `tests`, `LICENSE`, `README.md`만 깔끔하게 노출됩니다.
