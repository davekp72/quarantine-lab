@echo off
REM Harmless Quarantine Lab workflow test (agent inbox + payload exec).
REM Standard-user safe: profile files + HKCU\Environment only (no HKCU\Software, no HKLM).

setlocal EnableExtensions
set "STAMP=%DATE% %TIME%"
set "OUTDIR=%USERPROFILE%\Desktop\QuarantineLabTest"
set "DLDIR=%USERPROFILE%\Downloads\QuarantineLabTest"

mkdir "%OUTDIR%" 2>nul
mkdir "%DLDIR%" 2>nul

echo QuarantineLabTest marker > "%OUTDIR%\marker.txt"
echo created=%STAMP%>> "%OUTDIR%\marker.txt"
echo user=%USERNAME%>> "%OUTDIR%\marker.txt"
echo computer=%COMPUTERNAME%>> "%OUTDIR%\marker.txt"

echo hello-from-agent-workflow > "%OUTDIR%\note-1.txt"
echo second-file > "%DLDIR%\note-2.txt"
copy /Y "%OUTDIR%\marker.txt" "%DLDIR%\marker-copy.txt" >nul

REM User-writable HKCU only (Environment). Avoids HKCU\Software / HKLM.
reg add "HKCU\Environment" /v QuarantineLabTest /t REG_SZ /d "agent-workflow-ok" /f >nul
reg add "HKCU\Environment" /v QuarantineLabTestAt /t REG_SZ /d "%STAMP%" /f >nul

echo.
echo [QuarantineLabTest] OK
echo   Files:  %OUTDIR%
echo           %DLDIR%
echo   Reg:    HKCU\Environment  QuarantineLabTest*
echo.
endlocal
exit /b 0
