@echo off
:: ==============================================================================
:: [Reference Sample 01] Environment Variable Slicing (환경 변수 슬라이싱 난독화)
:: Principle: %PATH%, %COMSPEC%, %SYSTEMROOT% 등 기본 OS 환경 변수에서 특정 글자 추출
:: ==============================================================================

:: 1. 정적 시스템 변수에서 문자 추출
:: %COMSPEC% -> C:\Windows\system32\cmd.exe
:: %COMSPEC:~0,1% -> 'C'
:: %COMSPEC:~3,1% -> 'W'
:: %COMSPEC:~-7,3% -> 'cmd'

:: 2. 문자열 슬라이싱을 이용한 "whoami" 동적 합성
set _c=%COMSPEC:~-7,1%
set _m=%COMSPEC:~-6,1%
set _d=%COMSPEC:~-5,1%

set _w=w
set _h=h
set _o=o
set _a=a
set _m=m
set _i=i

:: 3. 최종 난독화 명령 실행 (실제로는 %_w%%_h%%_o%%_a%%_m%%_i% 형태로 실행)
echo [Obfuscated Execution via Slicing]
%_c%%_m%%_d% /c %_w%%_h%%_o%%_a%%_m%%_i%
