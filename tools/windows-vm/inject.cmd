@echo off
REM inject.cmd — VirtIO NetKVM offline driver injection
REM
REM Boot WinPE, open Shift+F10, run this script.
REM Detects installed Windows volume (excludes X:), locates NetKVM on
REM the VirtIO driver CD, runs DISM /Add-Driver, verifies, reboots.
REM All output goes to COM1 (serial).

setlocal enabledelayedexpansion

echo ========================================>\\.\COM1
echo INJECT.CMD NETKVM DRIVER INJECTION > \\.\COM1
echo ========================================>\\.\COM1
echo [%date% %time%] Starting > \\.\COM1

REM --- Step 1: Find the installed Windows volume (not X:) ---
set "WINROOT="
for %%d in (C D E F G H I J K) do (
    if not "%%d:"=="X:" (
        if exist "%%d:\Windows\System32\config\SYSTEM" (
            set "WINROOT=%%d:"
            echo [%date% %time%] Found Windows on !WINROOT! > \\.\COM1
            goto :found_win
        )
    )
)
echo [%date% %time%] ERROR: No installed Windows found > \\.\COM1
goto :eof

:found_win
REM --- Step 2: Find NetKVM/w11/ARM64/netkvm.inf on any drive ---
set "NETKVM_INF="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\NetKVM\w11\ARM64\netkvm.inf" (
        set "NETKVM_INF=%%d:\NetKVM\w11\ARM64\netkvm.inf"
        echo [%date% %time%] Found netkvm.inf: !NETKVM_INF! > \\.\COM1
        goto :found_netkvm
    )
)
echo [%date% %time%] ERROR: netkvm.inf not found on any drive > \\.\COM1
goto :eof

:found_netkvm
REM --- Step 3: DISM /Add-Driver ---
echo [%date% %time%] Running DISM /Add-Driver... > \\.\COM1
dism /Image:!WINROOT!\ /Add-Driver /Driver:!NETKVM_INF! > \\.\COM1 2>&1
set DISM_RC=!errorlevel!
echo [%date% %time%] DISM /Add-Driver exit code: !DISM_RC! > \\.\COM1

REM --- Step 4: Verify with DISM /Get-Drivers ---
echo [%date% %time%] Running DISM /Get-Drivers... > \\.\COM1
dism /Image:!WINROOT!\ /Get-Drivers /All > \\.\COM1 2>&1
echo [%date% %time%] DISM /Get-Drivers exit code: !errorlevel! > \\.\COM1

REM --- Step 5: Check for netkvm in driver list ---
dism /Image:!WINROOT!\ /Get-Drivers /All 2>nul | findstr /i "netkvm" > \\.\COM1 2>&1
echo [%date% %time%] netkvm search done > \\.\COM1

echo ========================================>\\.\COM1
echo INJECT.CMD COMPLETE > \\.\COM1
echo DISM_RC=!DISM_RC! > \\.\COM1
echo Ready for reboot. > \\.\COM1
echo ========================================>\\.\COM1

REM Reboot
wpeutil reboot
