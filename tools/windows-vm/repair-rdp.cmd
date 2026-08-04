@echo off
REM repair-rdp.cmd — Offline RDP repair for installed Windows
REM
REM Runs automatically from WinPE via winpeshl.ini.
REM No keyboard input required.
REM
REM Writes a diagnostic log to the FAT disk (if present) for review.

setlocal enabledelayedexpansion

REM --- Find a writable volume for diagnostics ---
set "DIAG="
for %%d in (C D E F G H I J K) do (
    if exist "%%d:\repair-rdp-done.flag" set "DIAG=%%d:"
)
if not defined DIAG (
    for %%d in (C D E F G H I J K) do (
        if exist "%%d:\Autounattend.xml" set "DIAG=%%d:"
    )
)
if defined DIAG set "DIAG=%DIAG%\repair-rdp.log"

if defined DIAG echo === REPAIR-RDP START === > "%DIAG%" 2>nul

REM --- Step 1: Detect offline Windows volume ---
set "WINROOT="
for %%d in (C D E F G H I J K) do (
    if not "%%d:"=="X:" (
        if exist "%%d:\Windows\System32\config\SYSTEM" (
            set "WINROOT=%%d:"
        )
    )
)

if not defined WINROOT (
    if defined DIAG echo ERROR: No installed Windows found >> "%DIAG%" 2>nul
    goto :end
)
if defined DIAG echo Windows: %WINROOT% >> "%DIAG%" 2>nul

REM --- Step 2: Load SYSTEM hive ---
reg load HKLM\FARSEE_SYS "%WINROOT%\Windows\System32\config\SYSTEM" >nul 2>&1
if %errorlevel% neq 0 (
    if defined DIAG echo ERROR: Cannot load SYSTEM hive >> "%DIAG%" 2>nul
    goto :end
)
if defined DIAG echo SYSTEM hive loaded >> "%DIAG%" 2>nul

REM --- Step 3: Derive current ControlSet ---
REM reg query returns "0x1" for DWORD. We need "ControlSet001".
REM Strip "0x" prefix, pad to 3 digits.
set "CSNUM="
for /f "tokens=3" %%c in ('reg query "HKLM\FARSEE_SYS\Select" /v Current 2^>nul') do (
    set "CSRAW=%%c"
)
REM Remove "0x" prefix
set "CSNUM=%CSRAW:0x=%"
REM Pad to 3 digits (e.g., "1" -> "001", "10" -> "010")
if 1%CSNUM% LSS 100 set "CSNUM=0%CSNUM%"
if 1%CSNUM% LSS 100 set "CSNUM=0%CSNUM%"
set "CS=ControlSet001"
if defined DIAG echo ControlSet: %CS% >> "%DIAG%" 2>nul

REM --- Step 4: Preserve values before mutation ---
if defined DIAG echo === BEFORE === >> "%DIAG%" 2>nul
if defined DIAG (
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server" /v fDenyTSConnections >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v fEnableWinStation >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Services\TermService" /v Start >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD >> "%DIAG%" 2>&1
)

REM --- Step 5: Check NetKVM binding evidence ---
if defined DIAG echo === NetKVM === >> "%DIAG%" 2>nul
if defined DIAG (
    dir "%WINROOT%\Windows\System32\DriverStore\FileRepository\netkvm*" /b >> "%DIAG%" 2>&1
    findstr /i "VEN_1AF4" "%WINROOT%\Windows\INF\setupapi.dev.log" >> "%DIAG%" 2>&1
)

REM --- Step 6: Set RDP values ---
REM fDenyTSConnections = 0
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >nul 2>&1

REM Also set the policy key if it exists
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >nul 2>&1

REM RDP-Tcp settings
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v fEnableWinStation /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 3389 /f >nul 2>&1
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\FARSEE_SYS\%CS%\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f >nul 2>&1

REM --- Step 7: TermService Start ---
for /f "tokens=3" %%v in ('reg query "HKLM\FARSEE_SYS\%CS%\Services\TermService" /v Start 2^>nul') do (
    set "TSSTART=%%v"
)
if defined DIAG echo TermService Start before: !TSSTART! >> "%DIAG%" 2>nul
if "!TSSTART!"=="0x4" (
    reg add "HKLM\FARSEE_SYS\%CS%\Services\TermService" /v Start /t REG_DWORD /d 2 /f >nul 2>&1
    if defined DIAG echo TermService changed: 4 -> 2 >> "%DIAG%" 2>nul
)

REM --- Step 8: Check setup state ---
if defined DIAG echo === Setup State === >> "%DIAG%" 2>nul
if defined DIAG (
    reg query "HKLM\FARSEE_SYS\Setup" /v SystemSetupInProgress >> "%DIAG%" 2>&1
    reg query "HKLM\FARSEE_SYS\Setup" /v OOBEInProgress >> "%DIAG%" 2>&1
)

REM --- Step 9: Check Panther logs ---
if defined DIAG echo === Panther === >> "%DIAG%" 2>nul
if defined DIAG (
    if exist "%WINROOT%\Windows\Panther\setupact.log" (
        findstr /i "unattend error fail specialize oobe" "%WINROOT%\Windows\Panther\setupact.log" >> "%DIAG%" 2>&1
    ) else (
        echo No setupact.log >> "%DIAG%" 2>&1
    )
)

REM --- Step 10: Unload hive ---
reg unload HKLM\FARSEE_SYS >nul 2>&1
if defined DIAG echo Hive unloaded >> "%DIAG%" 2>nul

if defined DIAG echo === REPAIR-RDP DONE === >> "%DIAG%" 2>nul

:end
REM Reboot after a short delay
timeout /t 5 /nobreak >nul 2>nul
wpeutil reboot
