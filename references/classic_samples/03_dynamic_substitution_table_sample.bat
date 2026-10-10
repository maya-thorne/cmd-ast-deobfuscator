@echo off
:: ==============================================================================
:: [Reference Sample 03] Dynamic Variable Substitution (동적 치환 사전 난독화)
:: Principle: Somalifuscator 및 현대적 파이썬 배치 난독화기들이 사용하는 핵심 기법
:: ==============================================================================

:: 1. 가변 사전 정의 (알파벳 매핑 테이블을 무작위 변수명으로 매핑)
set jkl2=c
set opq9=m
set rst1=d
set uvw4=/
set xyz8=c
set abc0=w
set def5=h
set ghi7=o
set mno3=a
set pqr6=i

:: 2. 무의미한 더미 쓰레기 변수 삽입 (Unexpanded Garbage Variables)
:: 정의되지 않은 %RANDOM_JUNK% 변수는 cmd.exe에서 공백이나 널(null)로 평가되어 증발함
set DUMMY=

:: 3. 치환 사전을 결합하여 명령 실행
echo [Obfuscated Execution via Variable Substitution]
%jkl2%%opq9%%rst1% %uvw4%%xyz8% %abc0%%DUMMY%%def5%%ghi7%%DUMMY%%opq9%%mno3%%DUMMY%%pqr6%
