# 🚫 Worker 4 중복 방지 규칙 (Anti-Patterns)

1. **PE 바이너리 및 Ghidra 역공학 중복 금지**:
   - `cmd-ast-deobfuscator`는 순수 텍스트 배치 파서 전담이므로, `.exe` 바이너리나 Ghidra 디컴파일러를 일체 다루지 않는다. (해당 기능은 Worker 5의 `bat2exe-ghidra-forensics`에 위임)

2. **블루팀 관제 룰셋 중복 금지**:
   - Sigma 규칙이나 YARA 룰을 작성하지 않는다. (해당 기능은 Worker 3의 `batch-forensics-and-ghidra-re`에 위임)

3. **30년 역사 백과사전 중복 금지**:
   - 역사적 진화 백서를 메인 문서로 다루지 않는다. (해당 내용은 Worker 1의 `batch-obfuscation-research`에 위임)

4. **상용 CLI 도구 패키징 중복 금지**:
   - 복잡한 CLI 인터페이스보다는 순수 파서 라이브러리 및 CS 알고리즘에 집중한다. (해당 기능은 Worker 2의 `batch-deobfuscator-re`에 위임)
