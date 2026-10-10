@echo off
:: ==============================================================================
:: [Reference Sample 05] Certutil Base64 Pipeline (주석 내 인라인 디코딩)
:: Principle: 배치 주석에 Base64 페이로드를 숨기고 certutil -decode로 런타임 추출
:: ==============================================================================

set "TEMP_B64=%TEMP%\payload.b64"
set "TEMP_TXT=%TEMP%\decoded.txt"

:: 1. 주석 영역에서 Base64 블록만 필터링하여 임시 파일로 추출
findstr "^::B64:" "%~f0" > "%TEMP_B64%"
powershell -Command "(Get-Content '%TEMP_B64%') -replace '^::B64:', '' | Set-Content '%TEMP_B64%'"

:: 2. certutil -decode를 통한 네이티브 복호화
certutil -decode -f "%TEMP_B64%" "%TEMP_TXT%" >nul 2>&1

:: 3. 복호화된 페이로드 확인 및 실행
if exist "%TEMP_TXT%" (
    echo [Payload Decoded Successfully]:
    type "%TEMP_TXT%"
    del /f /q "%TEMP_B64%" "%TEMP_TXT%" >nul 2>&1
)
exit /b

:: ==============================================================================
:: INLINE BASE64 PAYLOAD ("echo Hello from Decoded Payload!")
:: ==============================================================================
::B64:ZWNobyBIZWxsbyBmcm9tIERlY29kZWQgUGF5bG9hZCE=
