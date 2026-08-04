@echo off
REM collect.cmd — WinPE diagnostic log collector
REM
REM Emits key Panther and wpeinit logs to COM1 (serial) for diagnosis
REM when Setup does not progress. Used from the WinPE command prompt.

echo ======================================== > \\.\COM1
echo COLLECT.CMD DIAGNOSTIC LOGS > \\.\COM1
echo ======================================== > \\.\COM1
echo [%date% %time%] Collecting diagnostic logs > \\.\COM1
echo. > \\.\COM1

REM --- Volume listing ---
echo --- VOLUME LISTING --- > \\.\COM1
echo list volume > X:\vol.txt
diskpart /s X:\vol.txt > \\.\COM1 2>&1
echo. > \\.\COM1

REM --- setuperr.log ---
echo --- X:\Windows\Panther\setuperr.log --- > \\.\COM1
if exist "X:\Windows\Panther\setuperr.log" (
    type "X:\Windows\Panther\setuperr.log" > \\.\COM1 2>&1
) else (
    echo [not found] > \\.\COM1
)
echo. > \\.\COM1

REM --- setupact.log (unattend/error/fail lines only) ---
echo --- setupact.log (filtered) --- > \\.\COM1
if exist "X:\Windows\Panther\setupact.log" (
    findstr /i "unattend error fail warn answer" "X:\Windows\Panther\setupact.log" > \\.\COM1 2>&1
) else (
    echo [not found] > \\.\COM1
)
echo. > \\.\COM1

REM --- wpeinit.log ---
echo --- X:\Windows\System32\wpeinit.log --- > \\.\COM1
if exist "X:\Windows\System32\wpeinit.log" (
    type "X:\Windows\System32\wpeinit.log" > \\.\COM1 2>&1
) else (
    echo [not found] > \\.\COM1
)
echo. > \\.\COM1

REM --- Check for Autounattend.xml on all drives ---
echo --- Autounattend.xml discovery --- > \\.\COM1
for %%d in (D E F G H I J K) do (
    if exist "%%d:\Autounattend.xml" (
        echo Found: %%d:\Autounattend.xml > \\.\COM1
    )
)
echo. > \\.\COM1

REM --- Check for install.wim ---
echo --- install.wim discovery --- > \\.\COM1
for %%d in (D E F G H I J K) do (
    if exist "%%d:\sources\install.wim" (
        echo Found: %%d:\sources\install.wim > \\.\COM1
    )
)
echo. > \\.\COM1

echo ======================================== > \\.\COM1
echo COLLECT.CMD DONE > \\.\COM1
echo ======================================== > \\.\COM1
