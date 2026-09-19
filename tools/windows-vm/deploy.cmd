@echo off
REM SPDX-License-Identifier: Apache-2.0
REM deploy.cmd — Direct WIM deployment fallback (no Setup GUI)
REM
REM Used when setup.exe /unattend fails. Provisions the disk directly
REM using DiskPart + DISM + BCDBoot, then copies an unattend.xml into
REM the offline Windows for the specialize/oobe passes.
REM
REM All state transitions go to COM1 (serial).

setlocal enabledelayedexpansion

echo ======================================== > \\.\COM1
echo DEPLOY.CMD DIRECT WIM DEPLOYMENT > \\.\COM1
echo ======================================== > \\.\COM1

REM --- Locate install.wim ---
set "WIN_MEDIA="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\sources\install.wim" (
        set "WIN_MEDIA=%%d:"
        echo [%date% %time%] Found install.wim on !WIN_MEDIA! > \\.\COM1
        goto :found_wim
    )
)
echo [%date% %time%] ERROR: install.wim not found > \\.\COM1
goto :eof

:found_wim
REM --- Locate Autounattend.xml ---
set "ANSWER_DIR="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\Autounattend.xml" (
        set "ANSWER_DIR=%%d:"
        echo [%date% %time%] Found Autounattend.xml on !ANSWER_DIR! > \\.\COM1
        goto :found_answer
    )
)
echo [%date% %time%] ERROR: Autounattend.xml not found > \\.\COM1
goto :eof

:found_answer
REM --- Locate VirtIO driver media ---
set "DRV_MEDIA="
for %%d in (D E F G H I J K) do (
    if exist "%%d:\vioscsi\2k22\arm64\vioscsi.inf" (
        set "DRV_MEDIA=%%d:"
        echo [%date% %time%] Found VirtIO drivers on !DRV_MEDIA! > \\.\COM1
        goto :found_drv
    )
    if exist "%%d:\NetKVM\2k22\arm64\netkvm.inf" (
        set "DRV_MEDIA=%%d:"
        echo [%date% %time%] Found VirtIO drivers on !DRV_MEDIA! > \\.\COM1
        goto :found_drv
    )
)
echo [%date% %time%] WARNING: VirtIO driver media not found, skipping driver injection > \\.\COM1
set "DRV_MEDIA="

:found_drv
REM --- Step 1: Partition disk 0 ---
echo [%date% %time%] Step 1: DiskPart partitioning disk 0 > \\.\COM1

(
    echo select disk 0
    echo clean
    echo convert gpt
    echo create partition efi size=500
    echo format quick fs=fat32 label="System"
    echo assign letter=S
    echo create partition msr size=128
    echo create partition primary
    echo format quick fs=ntfs label="Windows"
    echo assign letter=W
) > X:\diskpart_script.txt

diskpart /s X:\diskpart_script.txt > \\.\COM1 2>&1
echo [%date% %time%] DiskPart exit code: !errorlevel! > \\.\COM1

REM --- Step 2: Apply WIM image ---
echo [%date% %time%] Step 2: DISM Apply-Image index 1 to W: > \\.\COM1
dism /Apply-Image /ImageFile:!WIN_MEDIA!\sources\install.wim /Index:1 /ApplyDir:W:\ > \\.\COM1 2>&1
echo [%date% %time%] DISM Apply-Image exit code: !errorlevel! > \\.\COM1

REM --- Step 3: Inject VirtIO network driver ---
if defined DRV_MEDIA (
    echo [%date% %time%] Step 3: Injecting NetKVM driver > \\.\COM1
    dism /Image:W:\ /Add-Driver /Driver:!DRV_MEDIA!\NetKVM /Recurse > \\.\COM1 2>&1
    echo [%date% %time%] DISM Add-Driver exit code: !errorlevel! > \\.\COM1
) else (
    echo [%date% %time%] Step 3: Skipped (no driver media) > \\.\COM1
)

REM --- Step 4: Copy unattend.xml for specialize/oobe passes ---
echo [%date% %time%] Step 4: Copying unattend.xml to W:\Windows\Panther\ > \\.\COM1
mkdir W:\Windows\Panther 2>nul
copy !ANSWER_DIR!\Autounattend.xml W:\Windows\Panther\unattend.xml > \\.\COM1 2>&1

REM --- Step 5: Install SetupComplete.cmd ---
echo [%date% %time%] Step 5: Writing SetupComplete.cmd > \\.\COM1
mkdir W:\Windows\Setup\Scripts 2>nul
(
    echo @echo off
    echo reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    echo reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
    echo net localgroup "Remote Desktop Users" TestAdmin /add
    echo powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Set-LocalUser -Name 'TestAdmin' -PasswordNeverExpires $true"
    echo powercfg /change standby-timeout-ac 0
    echo echo SETUPCOMPLETE_DONE > \\.\COM1
) > W:\Windows\Setup\Scripts\SetupComplete.cmd

REM --- Step 6: BCDBoot ---
echo [%date% %time%] Step 6: BCDBoot UEFI > \\.\COM1
W:\Windows\System32\bcdboot W:\Windows /s S: /f UEFI > \\.\COM1 2>&1
echo [%date% %time%] BCDBoot exit code: !errorlevel! > \\.\COM1

echo ======================================== > \\.\COM1
echo DEPLOY.CMD COMPLETE > \\.\COM1
echo Ready for reboot. Remove ISO media and reboot. > \\.\COM1
echo ======================================== > \\.\COM1
