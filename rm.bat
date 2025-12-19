@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~1"=="" goto usage

set RECURSE=0

REM Check for -r
if "%~1"=="-r" (
    set RECURSE=1
    shift
)

if "%~1"=="" goto usage

REM Normalize path
set "TARGET=%~1"
set "TARGET=%TARGET:/=\%"

REM Remove quotes
set "TARGET=%TARGET:"=%"

REM Handle recursive delete
if "%RECURSE%"=="1" (
    if exist "%TARGET%\" (
        rmdir /S /Q "%TARGET%"
    ) else (
        del /F /Q "%TARGET%" >nul 2>&1
    )
) else (
    if exist "%TARGET%\" (
        echo rm: %TARGET% is a directory
        echo Try 'rm -r %TARGET%'
        exit /b 1
    ) else (
        del /F /Q "%TARGET%" >nul 2>&1
    )
)

if errorlevel 1 (
    echo rm: failed to remove "%TARGET%"
    exit /b 1
)

exit /b 0

:usage
echo Usage:
echo   rm file
echo   rm -r directory
exit /b 1
