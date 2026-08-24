@echo off
REM ============================================================================
REM  Tropico widescreen patch -- installer (Windows)
REM
REM  Plain batch on purpose. This package's one risky component is a DLL that does
REM  IAT hooking and VirtualProtect; that is unavoidable and justified, so every
REM  other part is deliberately the most boring thing that works. PowerShell was
REM  rejected because -ExecutionPolicy Bypass is the malware-delivery pattern
REM  antivirus looks for by name. See docs/.../2026-08-23-windows-package-options.md
REM
REM  There is no art generation here and no Python. The proxy builds the UI art at
REM  launch, from the player's own archives, for whatever resolution the display
REM  turns out to be -- about a second, once per resolution.
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "SRC=tropico-patch"
set "MARK=tropico_fix (binkw32 proxy)"

echo.
echo   Tropico widescreen patch
echo   ------------------------
echo.

REM ---------------------------------------------------------------- preflight
REM Checked by name and up front. Without this the failure is a copy error three
REM steps in, which tells the player nothing about what they did wrong.
if not exist "Tropico.EXE" (
  echo   PROBLEM: Tropico.EXE is not in this folder.
  echo.
  echo   This ZIP must be extracted INTO your Tropico folder -- the one that
  echo   already contains Tropico.EXE -- and install.bat run from there.
  echo   Extracting it somewhere else and copying files in by hand will not work.
  goto :fail
)
if not exist "data" (
  echo   PROBLEM: there is no data\ folder here, so this is not a Tropico install.
  goto :fail
)
if not exist "%SRC%\binkw32.dll" (
  echo   PROBLEM: %SRC%\binkw32.dll is missing.
  echo.
  echo   Extract the WHOLE ZIP, keeping its folder structure. Some unzip tools
  echo   flatten folders; this one needs %SRC%\ to survive.
  goto :fail
)
if not exist "%SRC%\tropico-fix.ini" (
  echo   PROBLEM: %SRC%\tropico-fix.ini is missing. Extract the whole ZIP.
  goto :fail
)

REM ------------------------------------------- preserve the real binkw32.dll
REM  THE ONE STEP THAT CAN DESTROY SOMETHING, AND IT IS NOT RECOVERABLE.
REM
REM  If binkw32.dll is already our proxy and we copy it over binkw32_orig.dll, the
REM  real Bink is gone for good and every movie in the game with it. That is not
REM  hypothetical: it is what a second run of a naive installer does, and an
REM  earlier draft of THIS file did it -- caught by testing the case rather than
REM  by reading the code.
REM
REM  WHY THIS IS SIZE-BASED AND NOT A STRING SEARCH. The obvious check is
REM  `findstr /C:` for the proxy's marker string. Measured under wine's cmd:
REM  findstr cannot search a binary at all there (it returns "not found" for a
REM  file that plainly contains the string), and `fc /b` reports two completely
REM  different DLLs as identical. Both are Wine reimplementations and both may
REM  well behave on real Windows -- but a guard against irreversible data loss
REM  cannot rest on a tool whose behaviour we were unable to confirm.
REM
REM  So the gate is the file SIZE, via cmd's own %~zA, which needs no external
REM  program and was verified to report true sizes. It is written as REFUSE
REM  UNLESS CLEARLY SAFE: the only thing we will ever back up is a file that is
REM  exactly the Bink we know.
REM
REM  291328 is measured, not assumed -- the GOG and Steam editions ship a
REM  byte-identical binkw32.dll (same sha256, same size). A different edition
REM  will be refused rather than guessed at, and told exactly what to do.
set "BINK_SIZE=291328"

if exist "binkw32_orig.dll" (
  echo   - binkw32_orig.dll is already here; leaving it untouched
) else (
  if not exist "binkw32.dll" (
    echo   PROBLEM: binkw32.dll is missing from your game folder.
    echo   Verify or reinstall the game, then run this again.
    goto :fail
  )
  set "SZ="
  for %%A in ("binkw32.dll") do set "SZ=%%~zA"
  set "PSZ="
  for %%A in ("%SRC%\binkw32.dll") do set "PSZ=%%~zA"

  if "!SZ!"=="!PSZ!" (
    echo   PROBLEM: binkw32.dll here is ALREADY the patch, but binkw32_orig.dll
    echo   is missing -- so the original Bink is not on disk to preserve.
    goto :norestore
  )
  REM  Belt and braces. Ignored where findstr cannot read binaries, which is
  REM  exactly why it is not the only gate.
  findstr /C:tropico_fix "binkw32.dll" >nul 2>&1
  if not errorlevel 1 (
    echo   PROBLEM: binkw32.dll here appears to be an older build of the patch,
    echo   and binkw32_orig.dll is missing -- the original Bink is not on disk.
    goto :norestore
  )
  if not "!SZ!"=="%BINK_SIZE%" (
    echo   PROBLEM: binkw32.dll is !SZ! bytes; the Bink this patch knows is
    echo   %BINK_SIZE% bytes on both the GOG and Steam editions.
    echo.
    echo   Refusing to touch it rather than guess. Either verify your game files
    echo   and run this again, or -- if you are certain that file is the real
    echo   Bink -- copy it to binkw32_orig.dll yourself and re-run install.bat,
    echo   which will then leave your copy alone.
    goto :fail
  )
  copy /y "binkw32.dll" "binkw32_orig.dll" >nul
  if errorlevel 1 goto :norestore
echo.
echo   Nothing has been changed. Restore the original binkw32.dll first:
echo     GOG   - reinstall, or use GOG Galaxy's "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
echo.
echo   Then run install.bat again.
goto :fail

:copyfail
  REM  Post-condition, checked rather than trusted: if what we just wrote is not
  REM  the size of the real Bink, remove it. A backup that is silently wrong is
  REM  worse than no backup, because it will be restored one day.
  set "BSZ="
  for %%A in ("binkw32_orig.dll") do set "BSZ=%%~zA"
  if not "!BSZ!"=="%BINK_SIZE%" (
    del /q "binkw32_orig.dll" >nul 2>&1
    echo   PROBLEM: the backup did not come out the right size. It has been
    echo   removed, and nothing else was changed.
    goto :fail
  )
  echo   - preserved the original binkw32.dll as binkw32_orig.dll
)

REM ------------------------------------------------------- install the proxy
copy /y "%SRC%\binkw32.dll" "binkw32.dll" >nul
if errorlevel 1 goto :norestore
echo.
echo   Nothing has been changed. Restore the original binkw32.dll first:
echo     GOG   - reinstall, or use GOG Galaxy's "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
echo.
echo   Then run install.bat again.
goto :fail

:copyfail
REM Verified rather than assumed: a copy that silently half-succeeded would leave
REM a DLL the game cannot load, and the symptom is a launch failure with no clue.
REM By size, not `fc /b` -- measured, wine's fc calls two different DLLs identical,
REM so it would have verified nothing at all.
set "ISZ="
for %%A in ("binkw32.dll") do set "ISZ=%%~zA"
set "PSZ2="
for %%A in ("%SRC%\binkw32.dll") do set "PSZ2=%%~zA"
if not "!ISZ!"=="!PSZ2!" (
  echo   PROBLEM: binkw32.dll was copied but does not match the source.
  echo   Antivirus software sometimes quarantines it mid-copy. Check yours,
  echo   then run this again.
  goto :fail
)
echo   - installed binkw32.dll and verified it

REM ---------------------------------------------------------------- the ini
REM  Never overwritten. It holds the player's preferences, and an upgrade that
REM  silently reset them would be a worse bug than anything it fixed.
if exist "tropico-fix.ini" (
  echo   - tropico-fix.ini already exists; your settings are kept
) else (
  copy /y "%SRC%\tropico-fix.ini" "tropico-fix.ini" >nul
  if errorlevel 1 goto :norestore
echo.
echo   Nothing has been changed. Restore the original binkw32.dll first:
echo     GOG   - reinstall, or use GOG Galaxy's "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
echo.
echo   Then run install.bat again.
goto :fail

:copyfail
  echo   - wrote tropico-fix.ini
)

REM ------------------------------------------------------- ask for fresh art
REM  The proxy regenerates whenever data\ARTSET-MODE.txt disagrees with the mode
REM  it is about to use, so deleting the marker is how an install asks for a
REM  rebuild. Cheap, and it is the only thing that makes a reinstall notice.
if exist "data\ARTSET-MODE.txt" del /q "data\ARTSET-MODE.txt" >nul 2>&1

REM  Upgrading from a version that staged art per monitor: that whole subsystem
REM  is gone and the sets are dead weight -- 226 MB for three modes on a
REM  development box. Removed only now, once the proxy that replaces them is
REM  already in place.
if exist "artsets" (
  rmdir /s /q "artsets" >nul 2>&1
  echo   - removed the old staged art sets ^(artwork is built at launch now^)
)

echo.
echo   Done. Start Tropico the way you normally do.
echo.
echo   The first time you play at a new screen resolution, the patch spends
echo   about a second building the interface artwork for it, from your own
echo   game files. After that it starts straight away.
echo.
goto :end

:norestore
echo.
echo   Nothing has been changed. Restore the original binkw32.dll first:
echo     GOG   - reinstall, or use GOG Galaxy's "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
echo.
echo   Then run install.bat again.
goto :fail

:copyfail
echo.
echo   PROBLEM: a file could not be copied.
echo.
echo   The usual causes, in order of likelihood:
echo     - the game is running. Close it and try again.
echo     - antivirus software blocked it. See READ-ME-FIRST.txt.
echo     - the game is in a protected folder (Program Files). Right-click
echo       install.bat and choose "Run as administrator".
goto :fail

:fail
echo.
echo   Nothing was changed.
echo.
pause
exit /b 1

:end
pause
exit /b 0
