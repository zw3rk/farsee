@echo off
REM SPDX-License-Identifier: Apache-2.0
REM f.cmd — WinPE deployment orchestrator
REM
REM Called from the WinPE command prompt (Shift+F10) after WinPE loads.
REM Locates the Windows ISO, stops the attended Setup instance, and launches
REM setup.exe with the unattend answer file.
REM
REM All state transitions go to COM1 (serial) for headless monitoring.

setlocal enabledelayedexpansion

echo ======================================== > \\.\COM1
echo F.CMD DEPLOYMENT STARTED > \\.\COM1
echo ======================================== > \\.\COM1

REM --- Locate Autounattend.xml on our own volume ---
set "ANSWER_DIR="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\Autounattend.xml" (
        set "ANSWER_DIR=%%d:"
        echo [%date% %time%] Found Autounattend.xml on !ANSWER_DIR! > \\.\COM1
        goto :found_answer
    )
)
echo [%date% %time%] ERROR: Autounattend.xml not found on any drive > \\.\COM1
goto :eof

:found_answer
REM --- Locate the Windows ISO (sources\install.wim) ---
set "WIN_MEDIA="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\sources\install.wim" (
        set "WIN_MEDIA=%%d:"
        echo [%date% %time%] Found install.wim on !WIN_MEDIA! > \\.\COM1
        goto :found_wim
    )
)
echo [%date% %time%] ERROR: sources\install.wim not found on any drive > \\.\COM1
goto :eof

:found_wim
REM --- Stop the already-running attended Setup instance ---
echo [%date% %time%] Stopping attended Setup instance... > \\.\COM1
taskkill /f /im setup.exe 2>nul
taskkill /f /im wpeinit.exe 2>nul

REM Wait for processes to terminate
timeout /t 3 /nobreak >nul

REM --- Launch unattended Setup ---
echo [%date% %time%] Launching setup.exe /unattend:!ANSWER_DIR!\Autounattend.xml > \\.\COM1
echo [%date% %time%] Windows media: !WIN_MEDIA! > \\.\COM1

REM Run setup.exe with explicit unattend file
!WIN_MEDIA!\setup.exe /unattend:!ANSWER_DIR!\Autounattend.xml

echo [%date% %time%] setup.exe exited with code !errorlevel! > \\.\COM1
echo ======================================== > \\.\COM1
echo F.CMD FINISHED > \\.\COM1
echo ======================================== > \\.\COM1
