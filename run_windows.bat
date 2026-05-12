@echo off
REM RECON-X | run_windows.bat
REM Description: Run RECON-X from a Windows virtual environment.

SETLOCAL ENABLEDELAYEDEXPANSION
SET SCRIPT_DIR=%~dp0
SET VENV_PY=%SCRIPT_DIR%\.venv\Scripts\python.exe
SET RECON_CMD=%SCRIPT_DIR%\.venv\Scripts\recon-x.exe

PUSHD "%SCRIPT_DIR%"
IF EXIST "%RECON_CMD%" (
    "%RECON_CMD%" %*
    SET EXITCODE=%ERRORLEVEL%
    POPD
    EXIT /B %EXITCODE%
)

IF EXIST "%VENV_PY%" (
    "%VENV_PY%" -m cli.main %*
    SET EXITCODE=%ERRORLEVEL%
    POPD
    EXIT /B %EXITCODE%
)
POPD

ECHO [ERROR] No Windows virtual environment found at "%SCRIPT_DIR%\.venv".
ECHO Run setup_windows.ps1 first to create and install dependencies.
EXIT /B 1
