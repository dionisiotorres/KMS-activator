@echo off
cd /d "%~dp0"
if exist "Win32\*.dll" if exist "x64\*.dll" (
echo.
echo Notice:
echo DLL files already present
echo.
echo press any key to exit.
pause >nul
exit /b
)
if exist "..\bin\mingw32-make.exe" set "_make=..\bin\mingw32-make.exe"
for %%i in (mingw32-make.exe) do @if NOT "%%~$PATH:i"=="" set "_make=mingw32-make.exe"
if not defined _make (
echo.
echo Error:
echo could not detect mingw32-make.exe presence.
echo.
echo place this folder inside mingw32 or mingw64 folder before running compile.cmd
echo.
echo press any key to exit.
pause >nul
exit /b
)
if exist pch.hpp.gch\ rmdir /s /q pch.hpp.gch\
if exist Win32\ rmdir /s /q Win32\
if exist x64\ rmdir /s /q x64\
mkdir pch.hpp.gch
mkdir Win32
mkdir x64
@prompt $G
@echo on
%_make%
@set errcode=%errorlevel%
@echo off
if %errcode%==0 if exist "pch.hpp.gch\*.gch" rmdir /s /q pch.hpp.gch\
echo.
echo press any key to exit.
pause >nul
exit /b
