@echo off
:: JARVIS PRIME - Self-elevating launcher
:: Double-click this to start everything with admin rights

net session >nul 2>&1
if %errorLevel% == 0 goto :run
echo Requesting Administrator privileges...
powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
powershell -ExecutionPolicy Bypass -File "%~dp0jarvis-prime-launcher.ps1" %*
