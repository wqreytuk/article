@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~1"=="" goto usage
if "%~2"=="" goto usage

REM Arguments (quotes stripped automatically)
set "SRC=%~1"
set "DST=%~2"

REM Normalize forward slashes using delayed expansion
set "SRC=!SRC:/=\!"
set "DST=!DST:/=\!"

REM Copy file
if exist "!DST!\" (
    copy /Y "!SRC!" "!DST!" >nul
) else (
    copy /Y "!SRC!" "!DST!" >nul
)

if errorlevel 1 (
    echo cp: failed to copy "!SRC!" to "!DST!"
    exit /b 1
)

exit /b 0

:usage
echo Usage: cp source destination
exit /b 1
