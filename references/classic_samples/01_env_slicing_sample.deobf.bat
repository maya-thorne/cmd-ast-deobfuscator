@echo off
:: ==============================================================================
:: [Reference Sample 01] Environment Variable Slicing (환경 변수 슬라이싱 난독화)
:: Principle: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem, C:\Windows\system32\cmd.exe, C:\Windows 등 기본 OS 환경 변수에서 특정 글자 추출
:: ==============================================================================

:: 1. 정적 시스템 변수에서 문자 추출
:: C:\Windows\system32\cmd.exe -> C:\Windows\system32\cmd.exe
:: C -> 'C'
:: W -> 'W'
:: cmd -> 'cmd'

:: 2. 문자열 슬라이싱을 이용한 "whoami" 동적 합성
set _c=c
set _m=m
set _d=d

set _w=w
set _h=h
set _o=o
set _a=a
set _m=m
set _i=i

:: 3. 최종 난독화 명령 실행 (실제로는 whoami 형태로 실행)
echo [Obfuscated Execution via Slicing]
cmd /c whoami