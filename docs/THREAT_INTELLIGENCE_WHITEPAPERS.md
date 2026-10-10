# 🔬 보안 컨퍼런스 & 글로벌 위협 인텔리전스 배치 난독화 연구 백서

## 1. 개요
Windows 배치 파일(`.bat`, `.cmd`)은 1980년대 MS-DOS 시절부터 이어져 온 레거시 인터프리터인 `cmd.exe`에 의해 구동됩니다. 그러나 이 유서 깊은 환경은 복잡하고 기괴한 토큰 파싱 규칙, 문맥 종속적 이스케이프, 환경변수 슬라이싱 기능을 품고 있어, 오늘날 공격자들에게는 **강력한 EDR/AV 우회용 무기**로, 방어자들에게는 **가장 까다로운 분석 대상**으로 자리잡았습니다.

본 문서는 Mandiant, Palo Alto Networks Unit 42, Canadian Cyber Centre 등 글로벌 최고 수준의 연구 기관들이 발표한 공인 연구 백서와 기술 보고서를 총망라하여 정리한 분석서입니다.

---

## 2. 핵심 연구 백서 및 위협 분석 보고서

### 2.1 Mandiant: Invoke-DOSfuscation (Daniel Bohannon, 2017)
- **발표 무대**: Black Hat USA 2017 & DEF CON 25
- **연구 핵심**:
  - `cmd.exe`의 내부 파서가 문자열을 토큰화하는 과정에서 발생하는 파싱 불일치(Parsing Discrepancy)를 최초로 체계화.
  - 단순 텍스트 시그니처 기반의 안티바이러스 탐지기를 100% 무력화하는 4대 난독화 계층(Character, String, Command, Encoding) 정립.
- **cmd.exe 5단계 파싱 파이프라인**:
  1. **Phase 1 (특수문자 스캔)**: `%` 기호를 감지하여 환경변수 블록을 식별.
  2. **Phase 2 (변수 확장)**: `%VAR%` 및 `%VAR:~pos,len%`을 즉각 메모리상에서 치환.
  3. **Phase 3 (캐럿 이스케이프)**: 따옴표 밖의 `^` 기호는 다음 문자를 그대로 출력하고 스스로 소멸. (예: `c^m^d` ➔ `cmd`).
  4. **Phase 4 (인용부호 처리)**: 따옴표(`"`) 내부에서는 캐럿이 이스케이프되지 않고 리터럴 문자로 보존됨.
  5. **Phase 5 (리다이렉션 & 파이프라인 분기)**: `<`, `>`, `|`, `&`, `&&`를 기준으로 명령어를 분할하여 하위 프로세스로 실행.

---

### 2.2 Palo Alto Networks Unit 42: BatCloak 위협 분석 보고서 (2023)
- **보고서명**: *BatCloak: An Engine for Creating FUD (Fully Undetectable) Batch Files*
- **연구 핵심**:
  - 공격자 그룹이 안티바이러스(AV) 및 EDR 솔루션을 회피하기 위해 서비스형 패커(Packer-as-a-Service, PaaS) 형태로 유통한 'BatCloak' 난독화 엔진을 최초 역공학.
  - 스크러브크립트(ScrubCrypt) 등 상용 멀웨어 크립터와 결합되어 VenomRAT, GuLoader, RedLine Stealer 등을 무탐지(FUD) 상태로 유포.
- **BatCloak의 핵심 5대 회피 기법**:
  1. **BOM (Byte Order Mark) & 제로위드스 조작**: 파일 선두에 UTF-16 LE BOM(`\xFF\xFE`)을 주입하고 줄바꿈을 조작하여 정적 시그니처 스캐너의 텍스트 파서를 크래시시키거나 텍스트가 빈 파일인 것처럼 위장.
  2. **인라인 인증서 위장**: `-----BEGIN X509 CRL-----`과 같은 더미 공개키/인증서 블록 사이에 실제 악성 셸코드/배치 페이로드를 인라인 은닉.
  3. **다단계 지연 실행 (Multi-stage Delayed Stager)**: 배치 스크립트 실행 즉시 악성 행위를 하지 않고, 정상 윈도우 유틸리티(`certutil.exe`, `bitsadmin.exe`, `findstr.exe`)를 체이닝하여 메모리에서 복호화.
  4. **환경변수 동적 테이블(Scrambled Variable Table)**: 200~500줄 이상의 무의미한 `set <rnd>=<char>` 난독화 테이블을 선언한 뒤 인덱스로 명령어를 재조립.
  5. **Anti-AMSI / Anti-ETW 체인**: PowerShell을 호출하기 전 메모리 패칭 대신 배치 스크립트 레벨에서 환경변수(`COMPlus_ETWEnabled=0` 등)를 사전 조작하여 모니터링 무력화.

---

### 2.3 Canadian Centre for Cyber Security: Assemblyline BatchDeobfuscator
- **보고서 및 오픈소스**: *Assemblyline Service BatchDeobfuscator (CybercentreCanada)*
- **연구 핵심**:
  - 대규모 악성코드 자동 분석 파이프라인인 Assemblyline에 탑재하기 위한 고성능 Python 기반 상태 머신(State Machine) 개발.
  - 기존 DissectMalware 엔진을 확장하여 중첩된 `FOR /F` 루프, 동적 `IF` 분기, 다중 레이어 파일 드롭을 샌드박스 없이 정적으로 완전히 풀어내는 휴리스틱 룰셋 구축.

---

## 3. 고전(Classic)부터 현대(Modern)까지의 세대별 진화 계보도

```
[1세대: 1990s~2000s - 클래식 치환]
- 단순 캐럿(^) 삽입: c^m^d
- 환경변수 기본 치환: %COMSPEC%
- Bat2Exe (IExpress SED 기반 단독 실행파일 래핑)
       │
       ▼
[2세대: 2010s - 수학적 파싱 및 진법 인코딩]
- Invoke-DOSfuscation (Daniel Bohannon)
- 환경변수 슬라이싱: %PATH:~0,1%
- 정수 연산/루프 토큰 언롤링: for /L in (...)
- 16진수/8진수 환경변수 동적 조합
       │
       ▼
[3세대: 2020s 초반 - 복합 안티 분석 (Anti-Analysis)]
- Somalifuscator, Abobus, wirebits
- UTF-16 BOM 주입 및 콘솔 화면 조작 (Anti-Echo, Anti-Color)
- 가상머신/샌드박스 탐지 (Anti-VM, Anti-Debug via tasklist)
- 시저 암호 및 다중 패스 인덱스 셔플링
       │
       ▼
[4세대: 2023s~현재 - PaaS 크립터 & 지능형 탐지 우회]
- BatCloak, ScrubCrypt, Rust 기반 0xidiz3r
- 인증서(X.509/CRL) 모사 블록 페이로드 은닉
- EDR 프로세스 트리 단절 (Explorer COM / WMI 스폰)
- AI 기반 탐지 모델 회피용 적대적 섭동(Adversarial Perturbation) 주입
```
