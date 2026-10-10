@echo off
setlocal EnableDelayedExpansion
:: ==============================================================================
:: [Reference Sample 04] Reverse String Reconstruction (역순 문자열 동적 재조합)
:: Principle: 악성 문자열을 거꾸로 저장한 뒤 런타임에 루프로 뒤집어 실행
:: ==============================================================================

:: 1. 뒤집힌 문자열 정의 ("whoami" -> "imaohw")
set "REVERSED=imaohw"
set "RESTORED="

:: 2. 지연 확장(!VAR!) 및 for 루프를 통한 역순 순회
set "LEN=6"
for /L %%i in (5,-1,0) do (
    set "CHAR=!REVERSED:~%%i,1!"
    set "RESTORED=!RESTORED!!CHAR!"
)

echo [Restored Command]: !RESTORED!
!RESTORED!
