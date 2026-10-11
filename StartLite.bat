@echo off
chcp 65001 >nul 2>&1
title SiteMonitor Lite - Launcher

set "EXE=SiteMonitorLite.exe"

:: Check if the executable exists in release folder
if exist "%~dp0target\release\%EXE%" (
    goto :run_release
)

:: Try to build using cargo if cargo is installed
where cargo >nul 2>&1
if errorlevel 1 goto :try_debug
echo Building SiteMonitorLite in Release mode...
pushd "%~dp0"
cargo build --release --bin SiteMonitorLite
if errorlevel 1 (
    popd
    goto :build_failed
)
popd
goto :run_release

:try_debug
if exist "%~dp0target\debug\%EXE%" goto :run_debug

:build_failed
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
