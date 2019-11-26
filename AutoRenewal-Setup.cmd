@setlocal DisableDelayedExpansion
@set uivr=v36
@echo off
:: change to 0 to keep configured KMS cache upon removal (recommended only if you plan to reinstall)
set ClearKMSCache=1

:: change to 1 to enable debug mode
set _Debug=0

:: change to 1 to suppress any output
set Silent=0

:: change to 1 to redirect output to a text file, works only with Silent=1
set Logger=0

:: ###################################################################
:: # NORMALLY THERE IS NO NEED TO CHANGE ANYTHING BELOW THIS COMMENT #
:: ###################################################################

set KMS_IP=172.16.0.2
set KMS_Port=1688
set KMS_Emulation=1
set Unattend=0

set ForceIns=0
set ForceRem=0
set "_args=%*"
if not defined _args goto :NoProgArgs
if "%~1"=="" set "_args="&goto :NoProgArgs

set _args=%_args:"=%
for %%A in (%_args%) do (
if /i "%%A"=="/d" (set _Debug=1
) else if /i "%%A"=="/u" (set Unattend=1
) else if /i "%%A"=="/s" (set Silent=1
) else if /i "%%A"=="/l" (set Logger=1
) else if /i "%%A"=="/i" (set ForceIns=1&set ForceRem=0
) else if /i "%%A"=="/r" (set ForceIns=0&set ForceRem=1
) else if /i "%%A"=="/k" (set ClearKMSCache=0
)
)
if %ForceIns% EQU 1 set Unattend=1
if %ForceRem% EQU 1 set Unattend=1

:NoProgArgs
if %Silent% EQU 1 set Unattend=1
set "_run=nul"
if %Logger% EQU 1 set _run="%~dpn0_Silent.log"

set "SysPath=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\reg.exe" (set "SysPath=%SystemRoot%\Sysnative")
set "Path=%SysPath%;%SystemRoot%;%SysPath%\Wbem;%SysPath%\WindowsPowerShell\v1.0\"
set "_err===== ERROR ===="
set "_psc=powershell -noprofile -exec bypass -c"
set "_buf={$H=get-host;$W=$H.ui.rawui;$B=$W.buffersize;$B.height=300;$W.buffersize=$B;}"
set "xOS=x64"
if /i %PROCESSOR_ARCHITECTURE%==x86 (if not defined PROCESSOR_ARCHITEW6432 (
  set "xOS=x86"
  )
)

reg query HKU\S-1-5-19 1>nul 2>nul || goto :E_Admin

set "_temp=%SystemRoot%\Temp"
set "_log=%~dpn0"
set "_work=%~dp0"
if "%_work:~-1%"=="\" set "_work=%_work:~0,-1%"
for /f "skip=2 tokens=2*" %%a in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v Desktop') do call set "_dsk=%%b"
if exist "%SystemDrive%\Users\Public\Desktop\desktop.ini" set "_dsk=%SystemDrive%\Users\Public\Desktop"
setlocal EnableDelayedExpansion

if %_Debug% EQU 0 (
  set "_Nul1=1>nul"
  set "_Nul2=2>nul"
  set "_Nul6=2^>nul"
  set "_Nul3=1>nul 2>nul"
  set "_Pause=pause >nul"
  if %Unattend% EQU 1 set "_Pause="
  if %Silent% EQU 0 (call :Begin) else (call :Begin >!_run! 2>&1)
) else (
  set "_Nul1="
  set "_Nul2="
  set "_Nul6="
  set "_Nul3="
  set "_Pause="
  copy /y nul "!_work!\#.rw" 1>nul 2>nul && (if exist "!_work!\#.rw" del /f /q "!_work!\#.rw") || (set "_log=!_dsk!\%~n0")
  if %Silent% EQU 0 (
  echo.
  echo Running in Debug Mode...
  if not defined _args (echo The window will be closed when finished) else (echo please wait...)
  echo.
  echo writing debug log to:
  echo "!_log!_Debug.log"
  )
  @echo on
  @prompt $G
  @call :Begin >"!_log!_tmp.log" 2>&1 &cmd /u /c type "!_log!_tmp.log">"!_log!_Debug.log"&del "!_log!_tmp.log"
)
@color 07
@title %ComSpec%
@echo off
@exit /b

:Begin
if %_Debug% EQU 1 if defined _args echo %_args%
set "_wApp=55c92734-d682-4d71-983e-d6ec3f16059f"
set "_oApp=0ff1ce15-a989-479d-af46-f275c6370663"
set "_oA14=59a52881-a989-479d-af46-f275c6370663"
set "IFEO=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
set "OSPP=SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform"
set "SPPk=SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
set _Hook="%SysPath%\SppExtComObjHook.dll"
set w7inf=%SystemRoot%\Migration\WTR\KMS_VL_ALL.inf
set "_TaskEx=\Microsoft\Windows\SoftwareProtectionPlatform\SvcTrigger"
set "_TaskOs=\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
set "line3=____________________________________________________________"
for /f "tokens=6 delims=[]. " %%G in ('ver') do set winbuild=%%G
set SSppHook=0
for /f %%A in ('dir /b /ad %SysPath%\spp\tokens\skus') do (
  if %winbuild% GEQ 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*GVLK*.xrm-ms" set SSppHook=1
  if %winbuild% LSS 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*VLKMS*.xrm-ms" set SSppHook=1
  if %winbuild% LSS 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*VL-BYPASS*.xrm-ms" set SSppHook=1
)
set OsppHook=1
sc query osppsvc %_Nul3%
if %errorlevel% equ 1060 set OsppHook=0

if %winbuild% GEQ 9200 (
  set OSType=Win8
  set SppVer=SppExtComObj.exe
) else if %winbuild% GEQ 7600 (
  set OSType=Win7
  set SppVer=sppsvc.exe
) else (
  goto :UnsupportedVersion
)
if %OSType% EQU Win8 reg query "%IFEO%\sppsvc.exe" %_Nul3% && (
reg delete "%IFEO%\sppsvc.exe" /f %_Nul3%
call :StopService sppsvc
)

color 07
if %Unattend% EQU 0 title Auto Renewal Setup %uivr%
if %Silent% EQU 0 if %_Debug% EQU 0 mode con cols=100 lines=28

if %ForceIns% EQU 1 goto :inst
if %ForceRem% EQU 1 goto :remv
if exist %_Hook% dir /b /al %_Hook% %_Nul3% || goto :remv
reg query "%IFEO%\%SppVer%" /v KMS_Emulation %_Nul3% && goto :remv
reg query "%IFEO%\osppsvc.exe" /v KMS_Emulation %_Nul3% && goto :remv
if not exist "!_work!\bin\%xOS%.dll" goto :E_DLL

:inst
echo.
if %_Debug% NEQ 0 goto :pinst
if %Unattend% NEQ 0 (
echo Mode: Installation
goto :pinst
)
choice /C YN /N /M "Local KMS Emulator will be installed on your computer. Continue? [y/n]: "
if errorlevel 2 exit /b
:pinst
echo.
echo %line3%
call :StopService sppsvc
if %OsppHook% NEQ 0 call :StopService osppsvc
if %winbuild% GEQ 9600 (
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /f /v NoGenTicket /t REG_DWORD /d 1 %_Nul3%
  WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ExclusionPath="%SystemRoot%\System32\SppExtComObjHook.dll" %_Nul3% && set "AddExc= and Windows Defender exclusion"
)
echo.
echo Adding File%AddExc%...
echo %SystemRoot%\System32\SppExtComObjHook.dll
for %%# in (SppExtComObjHookAvrf.dll,SppExtComObjHook.dll,SppExtComObjPatcher.dll,SppExtComObjPatcher.exe) do if exist "%SysPath%\%%#" (
  del /f /q "%SysPath%\%%#" %_Nul3%
)
copy /y "!_work!\bin\%xOS%.dll" %_Hook% %_Nul3% || (echo Failed&goto :TheEnd)
echo.
echo Adding Registry Keys...
if %SSppHook% NEQ 0 call :CreateIFEOEntry %SppVer%
call :CreateIFEOEntry osppsvc.exe
if %OSType% EQU Win7 (
call :CreateIFEOEntry SppExtComObj.exe
if %SSppHook% NEQ 0 if not exist %w7inf% (
  echo.&echo Adding migration fail-safe...&echo %w7inf%
  if not exist "%SystemRoot%\Migration\WTR" md "%SystemRoot%\Migration\WTR"
  (
  echo [WTR]
  echo Name="KMS_VL_ALL"
  echo.
  echo [WTR.W8]
  echo NotifyUser="No"
  echo.
  echo [System.Registry]
  echo "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe [*]"
  )>%w7inf%
  )
)
if %OSType% EQU Win8 call :CreateTask
if not exist "!_work!\Activate.cmd" (
echo %line3%
echo.
echo %_err%
echo Activate.cmd is missing, skipping activation...
goto :einst
)
if %Silent% EQU 0 if %_Debug% EQU 0 (
%_Nul3% %_psc% "&%_buf%"
)
echo.
echo %line3%
set "_para=/u"
if %_Debug% EQU 1 set "_para=!_para! /d"
if %Silent% EQU 1 set "_para=!_para! /s"
if %Logger% EQU 1 set "_para=!_para! /l"
cmd.exe /c ""!_work!\Activate.cmd" !_para!"
if %Unattend% EQU 0 title Auto Renewal Setup %uivr%
:einst
echo %line3%
echo.
echo Done.
echo Make sure to exclude this file in the Antivirus protection.
echo %SystemRoot%\System32\SppExtComObjHook.dll
goto :TheEnd

:remv
echo.
if %_Debug% NEQ 0 goto :premv
if %Unattend% NEQ 0 (
echo Mode: Removal
goto :premv
)
choice /C YN /N /M "Local KMS Emulator will be removed from your computer. Continue? [y/n]: "
if errorlevel 2 exit /b
:premv
echo.
echo %line3%
call :StopService sppsvc
if %OsppHook% NEQ 0 call :StopService osppsvc
if %winbuild% GEQ 9600 (
  reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /f %_Nul3%
  WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Remove ExclusionPath="%SystemRoot%\System32\SppExtComObjHook.dll" %_Nul3% && set "RemExc= and Windows Defender exclusions"
)
echo.
echo Removing Files%RemExc%...
for %%# in (SppExtComObjHookAvrf.dll,SppExtComObjHook.dll,SppExtComObjPatcher.dll,SppExtComObjPatcher.exe) do if exist "%SysPath%\%%#" (
  echo %SystemRoot%\System32\%%#
  del /f /q "%SysPath%\%%#"
)
if exist %w7inf% (
	echo %w7inf%
	del /f /q %w7inf%
)
echo.
echo Removing Registry Keys...
for %%# in (SppExtComObj.exe,sppsvc.exe,osppsvc.exe) do reg query "%IFEO%\%%#" %_Nul3% && (
  call :RemoveIFEOEntry %%#
)
if %OSType% EQU Win8 schtasks /query /tn "%_TaskEx%" %_Nul3% && (
echo.
echo Removing Schedule Task...
echo %_TaskEx%
schtasks /delete /f /tn "%_TaskEx%" %_Nul3%
)
if %ClearKMSCache% EQU 1 (
echo.
echo Clearing KMS Cache...
call :cKMS SoftwareLicensingProduct SoftwareLicensingService %_Nul3%
if %OsppHook% NEQ 0 call :cKMS OfficeSoftwareProtectionProduct OfficeSoftwareProtectionService %_Nul3%
call :cREG %_Nul3%
)
echo.
echo %line3%
echo.
echo Done.
goto :TheEnd

:StopService
sc query %1 | find /i "STOPPED" %_Nul1% || net stop %1 /y %_Nul3%
sc query %1 | find /i "STOPPED" %_Nul1% || sc stop %1 %_Nul3%
goto :eof

:CreateIFEOEntry
echo [%IFEO%\%1]
reg delete "%IFEO%\%1" /f /v Debugger %_Nul3%
reg add "%IFEO%\%1" /f /v VerifierDlls /t REG_SZ /d "SppExtComObjHook.dll" %_Nul3% || (echo Failed&del /f /q %_Hook%&goto :TheEnd)
reg add "%IFEO%\%1" /f /v GlobalFlag /t REG_DWORD /d 256 %_Nul3%
reg add "%IFEO%\%1" /f /v KMS_Emulation /t REG_DWORD /d %KMS_Emulation% %_Nul3%
if /i %1 EQU osppsvc.exe (
reg add "HKLM\%OSPP%" /f /v KeyManagementServiceName /t REG_SZ /d %KMS_IP% %_Nul3%
reg add "HKLM\%OSPP%" /f /v KeyManagementServicePort /t REG_SZ /d %KMS_Port% %_Nul3%
)
goto :eof

:RemoveIFEOEntry
echo [%IFEO%\%1]
if /i %1 NEQ osppsvc.exe (
reg delete "%IFEO%\%1" /f %_Nul3%
goto :eof
)
if %OsppHook% EQU 0 (
reg delete "%IFEO%\%1" /f %_Nul3%
)
if %OsppHook% NEQ 0 for %%A in (Debugger,VerifierDlls,GlobalFlag,KMS_Emulation,KMS_ActivationInterval,KMS_RenewalInterval,Office2010,Office2013,Office2016,Office2019) do reg delete "%IFEO%\%1" /f /v %%A %_Nul3%
goto :eof

:CreateTask
schtasks /query /tn "%_TaskEx%" %_Nul3% || (
  schtasks /query /tn "%_TaskOs%" %_Nul3% && (
    schtasks /query /tn "%_TaskOs%" /xml >"!_temp!\SvcTrigger.xml"
    schtasks /create /tn "%_TaskEx%" /xml "!_temp!\SvcTrigger.xml" /f %_Nul3%
    schtasks /change /tn "%_TaskEx%" /enable %_Nul3%
    del /f /q "!_temp!\SvcTrigger.xml" %_Nul3%
  )
)
schtasks /query /tn "%_TaskEx%" %_Nul3% || (
  if exist "!_work!\bin\SvcTrigger.xml" schtasks /create /tn "%_TaskEx%" /xml "!_work!\bin\SvcTrigger.xml" /f %_Nul3%
)
schtasks /query /tn "%_TaskEx%" %_Nul3% && (
echo.
echo Adding Schedule Task...
echo %_TaskEx%
)
goto :eof

:cKMS
set spp=%1
set sps=%2
for /f "tokens=2 delims==" %%G in ('"wmic path %spp% where (Description like '%%KMSCLIENT%%') get ID /VALUE" %_Nul6%') do (set app=%%G&call :cAPP)
for /f "tokens=2 delims==" %%A in ('"wmic path %sps% get Version /VALUE"') do set ver=%%A
wmic path %sps% where version='%ver%' call ClearKeyManagementServiceMachine
wmic path %sps% where version='%ver%' call ClearKeyManagementServicePort
wmic path %sps% where version='%ver%' call DisableKeyManagementServiceDnsPublishing 1
wmic path %sps% where version='%ver%' call DisableKeyManagementServiceHostCaching 1
goto :eof

:cAPP
wmic path %spp% where ID='%app%' call ClearKeyManagementServiceMachine
wmic path %spp% where ID='%app%' call ClearKeyManagementServicePort
goto :eof

:cREG
reg delete "HKLM\%SPPk%\%_wApp%" /f
reg delete "HKLM\%SPPk%\%_oApp%" /f
reg delete "HKLM\%SPPk%" /f /v KeyManagementServiceName
reg delete "HKLM\%SPPk%" /f /v KeyManagementServicePort
reg delete "HKU\S-1-5-20\%SPPk%\%_wApp%" /f
reg delete "HKU\S-1-5-20\%SPPk%\%_oApp%" /f
reg delete "HKLM\%OSPP%\%_oA14%" /f
reg delete "HKLM\%OSPP%\%_oApp%" /f
reg delete "HKLM\%OSPP%" /f /v KeyManagementServiceName
reg delete "HKLM\%OSPP%" /f /v KeyManagementServicePort
if %OsppHook% EQU 0 (
reg delete "HKLM\%OSPP%" /f
reg delete "HKU\S-1-5-20\%OSPP%" /f
)
goto :eof

:E_Admin
echo %_err%
echo This script requires administrator privileges.
echo To do so, right-click on this script and select 'Run as administrator'
echo.
echo Press any key to exit.
if %_Debug% EQU 1 goto :eof
if %Unattend% EQU 1 goto :eof
pause >nul
goto :eof

:E_DLL
echo %_err%
echo Required file bin\%xOS%.dll is not found.
echo Verify that Antivirus protection is OFF or the current folder is excluded.
goto :TheEnd

:UnsupportedVersion
echo %_err%
echo Unsupported OS version Detected.
echo Project is supported only for Windows 7/8/8.1/10 and their Server equivalent.
:TheEnd
echo.
if %Unattend% EQU 0 echo Press any key to exit.
%_Pause%
goto :eof