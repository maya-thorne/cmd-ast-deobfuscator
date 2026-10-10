@echo off
:: ==============================================================================
:: [Reference Sample 02] Caret Escape & Delimiter Anomaly (캐럿 및 구분자 난독화)
:: Principle: 따옴표 밖의 캐럿()은 파서에 의해 제거되며, 공백 대신 쉼표/세미콜론 사용 가능
:: ==============================================================================

:: 1. 캐럿 인터리빙: 정적 문자열 검색 방지
:: 문자 사이에 삽입된 캐럿()은 cmd.exe 파서가 명령어 해석 시 완전히 무시함
echo [1. Caret Interleaving Execution]
cmd /c whoami

:: 2. 유연한 구분자(Delimiters) 변칙 사용
:: cmd.exe는 공백 대신 쉼표(,), 세미콜론(;), 등호(=)를 유효한 인자 구분자로 처리함
echo [2. Delimiter Anomaly Execution]
cmd.exe,=,/c,whoami

:: 3. 따옴표 무작위 분할 (Quotation Fragmentation)
echo [3. Quotation Fragmentation]
"c"md /c "w"ho"a"mi