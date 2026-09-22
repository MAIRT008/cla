@echo off
rem Unified log collector for AI Environmental Steward. Usage: collect-logs.cmd -Preview ^| -Export -CaseId E57
rem Runs the bundled Windows PowerShell 5.1 script; the execution policy override applies to this process only.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-logs.ps1" %*
exit /b %ERRORLEVEL%
