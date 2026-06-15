@echo off
chcp 65001 >nul 2>&1
title SiteMonitor - Launcher

set "EXE=SiteMonitor.exe"

:: Check if the executable exists in release folder
if exist "%~dp0target\release\%EXE%" (
    goto :run_release
)

:: If not found, check if it exists in debug folder
if exist "%~dp0target\debug\%EXE%" (
    goto :run_debug
)

:: Try to build using cargo if cargo is installed
where cargo >nul 2>&1
if %errorlevel%==0 (
    echo Building SiteMonitor in Release mode...
    cargo build --release
    if %errorlevel%==0 (
        goto :run_release
    )
)

echo.
echo [ERROR] %EXE% not found!
echo Please make sure Rust is installed and build the project:
echo   cargo build --release
echo.
pause
exit /b 1

:run_release
start "" "%~dp0target\release\%EXE%" %*
exit /b 0

:run_debug
start "" "%~dp0target\debug\%EXE%" %*
exit /b 0
