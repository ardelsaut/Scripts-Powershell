@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system" && (
    goto :gotAdmin
) || (
    echo Requesting administrative privileges...
    echo.
    set "batchPath=%~0"
    set "batchArgs=%*"
    setlocal DisableDelayedExpansion
    set "batchArgs=%batchArgs:"=\"%"
    set "batchArgs=%batchArgs:>=^>%"
    set "batchCmd=cmd.exe /c ""%batchPath%" %batchArgs% & pause"""
    echo %batchCmd% > "%temp%\runAsAdmin.cmd"
    start /wait "" "%temp%\runAsAdmin.cmd"
    del "%temp%\runAsAdmin.cmd" >nul 2>&1
    exit /b
)
:gotAdmin

set regFile=%temp%\powershell_policy.reg

echo Windows Registry Editor Version 5.00 >> %regFile%
echo. >> %regFile%
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell] >> %regFile%
echo "ExecutionPolicy"="Unrestricted" >> %regFile%

regedit /s %regFile%

del %regFile%
