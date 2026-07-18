@echo off
setlocal
set "SCRIPT=%~dp0xiaoha-cleaner.py"

where py >nul 2>nul
if errorlevel 1 goto try_python
py -3 "%SCRIPT%" %*
exit /b %errorlevel%

:try_python
where python >nul 2>nul
if errorlevel 1 goto missing_python
python "%SCRIPT%" %*
exit /b %errorlevel%

:missing_python
echo Python 3.7 or newer was not found.
exit /b 9009
