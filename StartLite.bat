@echo off
chcp 65001 >nul 2>&1
title SiteMonitor Lite - Launcher

:: ============================================================
::  SiteMonitor Lite Launcher
::  Checks for .NET 8 Runtime and installs it automatically
:: ============================================================

set "EXE=SiteMonitorLite.exe"
set "DOTNET_VERSION=8"
set "RUNTIME_URL=https://aka.ms/dotnet/8.0/dotnet-runtime-win-x64.exe"
set "INSTALLER_EXE=%TEMP%\dotnet-runtime-8-install.exe"

:: --- Check if .NET 8 runtime is available ---
dotnet --list-runtimes 2>nul | findstr /C:"Microsoft.NETCore.App %DOTNET_VERSION%." >nul 2>&1
if %errorlevel%==0 (
    goto :run
)

:: --- dotnet command might not exist at all ---
where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    goto :install
)

:: --- dotnet exists but .NET 8 runtime is missing ---
dotnet --list-runtimes 2>nul | findstr /C:"Microsoft.NETCore.App %DOTNET_VERSION%." >nul 2>&1
if %errorlevel% neq 0 (
    goto :install
)

:run
echo [OK] .NET %DOTNET_VERSION% Runtime found.
echo Starting %EXE%...
echo.

if exist "%~dp0%EXE%" (
    start "" "%~dp0%EXE%" %*
    exit /b 0
)
if exist "%~dp0bin\Release\net8.0\%EXE%" (
    start "" "%~dp0bin\Release\net8.0\%EXE%" %*
    exit /b 0
)
if exist "%~dp0bin\Debug\net8.0\%EXE%" (
    start "" "%~dp0bin\Debug\net8.0\%EXE%" %*
    exit /b 0
)

echo [ERROR] %EXE% not found!
echo Build the project first: dotnet build SiteMonitorLite.csproj -c Release
pause
exit /b 1

:install
echo ============================================================
echo   .NET %DOTNET_VERSION% Runtime is not installed.
echo   It is required to run SiteMonitor Lite.
echo ============================================================
echo.

choice /C YN /M "Install .NET %DOTNET_VERSION% Runtime automatically? (Y/N)"
if %errorlevel%==2 (
    echo.
    echo You can install it manually from:
    echo https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

echo.
echo Downloading .NET %DOTNET_VERSION% Runtime installer...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { " ^
    "   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
    "   $ProgressPreference = 'SilentlyContinue'; " ^
    "   Invoke-WebRequest -Uri '%RUNTIME_URL%' -OutFile '%INSTALLER_EXE%' -UseBasicParsing; " ^
    "   Write-Host '[OK] Download complete.' " ^
    "} catch { " ^
    "   Write-Host '[ERROR] Download failed:' $_.Exception.Message; " ^
    "   exit 1 " ^
    "}"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to download .NET Runtime installer.
    echo Please install manually: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

echo.
echo Installing .NET %DOTNET_VERSION% Runtime...
echo (Administrator privileges may be required)
echo.

"%INSTALLER_EXE%" /install /quiet /norestart

if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Silent install returned code %errorlevel%.
    echo Trying interactive install...
    "%INSTALLER_EXE%" /install /norestart
)

del "%INSTALLER_EXE%" >nul 2>&1

echo.
echo Verifying installation...
timeout /t 2 /nobreak >nul

set "PATH=%PATH%;%ProgramFiles%\dotnet;%LOCALAPPDATA%\Microsoft\dotnet"

dotnet --list-runtimes 2>nul | findstr /C:"Microsoft.NETCore.App %DOTNET_VERSION%." >nul 2>&1
if %errorlevel%==0 (
    echo [OK] .NET %DOTNET_VERSION% Runtime installed successfully!
    echo.
    goto :run
) else (
    echo.
    echo [WARNING] Could not verify .NET %DOTNET_VERSION% installation.
    echo You may need to restart your terminal or PC.
    echo Attempting to launch anyway...
    echo.
    goto :run
)
