@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~1"=="" goto usage
if "%~2"=="" goto usage

REM Arguments (quotes stripped)
set "SRC=%~1"
set "DST=%~2"

REM Normalize forward slashes safely
set "SRC=!SRC:/=\!"
set "DST=!DST:/=\!"

REM Move with overwrite (/Y)
if exist "!DST!\" (
    move /Y "!SRC!" "!DST!" >nul
) else (
    move /Y "!SRC!" "!DST!" >nul
)

if errorlevel 1 (
    echo mv: failed to move "!SRC!" to "!DST!"
    exit /b 1
)

exit /b 0

:usage
echo Usage: mv source destination
exit /b 1
