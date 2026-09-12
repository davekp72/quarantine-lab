@echo off
rem Copied to C:\Windows\Setup\Scripts\SetupComplete.cmd via $OEM$.
rem Runs as SYSTEM after Setup. Keep built-in Administrator enabled for lab guest control.
set LOG=C:\Users\Public\setupcomplete.log
echo %DATE% %TIME% SetupComplete start>>"%LOG%"
net user Administrator /active:yes>>"%LOG%" 2>&1
echo %DATE% %TIME% SetupComplete done>>"%LOG%"
exit /b 0
