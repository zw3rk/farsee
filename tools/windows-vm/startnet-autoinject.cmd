@echo off
REM SPDX-License-Identifier: Apache-2.0
wpeinit

REM Check if Windows is already installed
set "WINROOT="
for %%d in (C D E F G H I J K) do (
    if not "%%d:"=="X:" (
        if exist "%%d:\Windows\System32\config\SYSTEM" (
            set "WINROOT=%%d:"
        )
    )
)

if defined WINROOT (
    echo === PHASE 2: INJECT === > \\.\COM1
    echo Windows on %WINROOT% > \\.\COM1
    
    REM Find NetKVM
    set "NETKVM="
    for %%d in (D E F G H I J K) do (
        if exist "%%d:\NetKVM\w11\ARM64\netkvm.inf" (
            set "NETKVM=%%d:\NetKVM\w11\ARM64\netkvm.inf"
        )
    )
    
    if defined NETKVM (
        echo NetKVM: %NETKVM% > \\.\COM1
        dism /Image:%WINROOT%\ /Add-Driver /Driver:%NETKVM% > \\.\COM1 2>&1
        echo DISM RC: %errorlevel% > \\.\COM1
        dism /Image:%WINROOT%\ /Get-Drivers /All > \\.\COM1 2>&1
        echo === INJECT DONE === > \\.\COM1
        wpeutil reboot
    ) else (
        echo NetKVM not found > \\.\COM1
    )
) else (
    echo === PHASE 1: INSTALL === > \\.\COM1
    REM Find answer file and run setup
    set "ANSWER="
    for %%d in (D E F G H I J K) do (
        if exist "%%d:\Autounattend.xml" (
            set "ANSWER=%%d:\Autounattend.xml"
        )
    )
    REM Find Windows ISO
    set "SETUP="
    for %%d in (D E F G H I J K) do (
        if exist "%%d:\setup.exe" (
            set "SETUP=%%d:"
        )
    )
    if defined SETUP (
        if defined ANSWER (
            echo Setup: %SETUP% Answer: %ANSWER% > \\.\COM1
            %SETUP%\setup.exe /unattend:%ANSWER%
        ) else (
            echo No answer file, running setup.exe default > \\.\COM1
            %SETUP%\setup.exe
        )
    ) else (
        echo No setup.exe found > \\.\COM1
    )
)
