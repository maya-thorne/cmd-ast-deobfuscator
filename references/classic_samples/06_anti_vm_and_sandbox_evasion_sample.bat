@echo off
:: ==============================================================================
:: [Reference Sample 06] Anti-VM & Sandbox Evasion (가상머신 및 분석 환경 탐지)
:: Principle: 시스템 드라이브 용량, 아티팩트 프로세스, 가상 드라이버 검사
:: ==============================================================================

echo [*] Checking Execution Environment...

:: 1. 가상머신 특정 드라이버 및 프로세스 검사
tasklist /FI "IMAGENAME eq VBoxService.exe" 2>nul | find /I /N "VBoxService.exe" >nul
if "%ERRORLEVEL%"=="0" (
    echo [-] VirtualBox Environment Detected! Exiting...
    exit /b 1
)

tasklist /FI "IMAGENAME eq vmtoolsd.exe" 2>nul | find /I /N "vmtoolsd.exe" >nul
if "%ERRORLEVEL%"=="0" (
    echo [-] VMware Environment Detected! Exiting...
    exit /b 1
)

:: 2. 샌드박스 탐지: 시스템 총 메모리 용량 검사 (4GB 미만 시 샌드박스로 의심)
for /f "tokens=2 delims==" %%a in ('wmic computersystem get TotalPhysicalMemory /value 2^>nul') do set "MEM=%%a"
if defined MEM (
    :: 4294967296 bytes = 4 GB
    if %MEM% LSS 4000000000 (
        echo [-] Low Memory Detected (likely Sandbox): %MEM% bytes. Exiting...
        exit /b 1
    )
)

echo [+] Clean Environment Confirmed. Proceeding with payload...
