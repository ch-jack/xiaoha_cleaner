@echo off
setlocal
set "SCRIPT=%~dp0xiaoha-cleaner.py"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%SCRIPT%" %*
    exit /b %errorlevel%
)

where python >nul 2>nul
if %errorlevel%==0 (
    python "%SCRIPT%" %*
    exit /b %errorlevel%
)

echo Python 3.7 or newer was not found.
exit /b 9009
