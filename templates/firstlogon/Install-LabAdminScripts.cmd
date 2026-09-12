@echo off
rem specialize: copy scripts off setup media while the DVD is still attached.
mkdir C:\Windows\Setup\Scripts 2>nul
mkdir C:\Users\Public\Quarantine 2>nul
set LOG=C:\Users\Public\install-labadmin-scripts.log
echo %DATE% %TIME% start>>"%LOG%"
net user Administrator /active:yes>>"%LOG%" 2>&1
for %%D in (D E F C A) do (
  if exist "%%D:\Quarantine\Finish-LabAdmin.ps1" (
    copy /y "%%D:\Quarantine\Finish-LabAdmin.ps1" C:\Windows\Setup\Scripts\Finish-LabAdmin.ps1>>"%LOG%"
    copy /y "%%D:\Quarantine\SetupComplete.cmd" C:\Windows\Setup\Scripts\SetupComplete.cmd>>"%LOG%"
    copy /y "%%D:\Invoke-QuarantineFirstLogon.ps1" C:\Windows\Setup\Scripts\Invoke-QuarantineFirstLogon.ps1>>"%LOG%"
    xcopy /y /e /i "%%D:\Quarantine" C:\Users\Public\Quarantine\>>"%LOG%"
    echo copied from %%D:>>"%LOG%"
  )
)
exit /b 0
