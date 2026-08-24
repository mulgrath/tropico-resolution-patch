@echo off
REM ============================================================================
REM  Tropico widescreen patch -- uninstaller (Windows)
REM
REM  Puts the game back as it was: the original binkw32.dll returns, and every
REM  file the patch generated is removed BY MANIFEST.
REM
REM  BY MANIFEST AND NEVER BY WILDCARD. A del over data\*.i16 would also delete
REM  the artwork the game itself ships loose, and that is not recoverable without
REM  reinstalling the game. The patch writes down exactly what it created; this
REM  removes exactly that and nothing else.
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "MARK=tropico_fix (binkw32 proxy)"
set /a NART=0

echo.
echo   Tropico widescreen patch -- uninstall
echo   ------------------------------------
echo.

if not exist "Tropico.EXE" (
  echo   PROBLEM: Tropico.EXE is not in this folder, so this is not the place
  echo   the patch was installed. Nothing was changed.
  goto :fail
)

REM -------------------------------------------------- restore the real binkw32
REM  Refuse if the backup is itself the proxy. Restoring that would leave a proxy
REM  forwarding to a proxy -- the game would fail to start and the real Bink
REM  would still be missing, with the uninstaller having reported success.
if exist "binkw32_orig.dll" (
  findstr /M /C:"%MARK%" "binkw32_orig.dll" >nul 2>&1
  if not errorlevel 1 (
    echo   PROBLEM: binkw32_orig.dll is the PATCH, not the original Bink.
    echo   Refusing to restore it -- that would leave the game unable to start.
    echo.
    echo   Restore binkw32.dll from your game installer instead:
    echo     GOG   - reinstall, or GOG Galaxy "Verify / Repair"
    echo     Steam - Properties, Installed Files, "Verify integrity of game files"
    goto :fail
  )
  copy /y "binkw32_orig.dll" "binkw32.dll" >nul
  if errorlevel 1 (
    echo   PROBLEM: could not restore binkw32.dll. Is the game running?
    goto :fail
  )
  echo   - restored the original binkw32.dll
  REM  binkw32_orig.dll is left in place ON PURPOSE. It is the only copy of the
  REM  real Bink on disk that we know to be good; deleting it to look tidy would
  REM  mean a failed copy above leaves the player with nothing. Reinstalling the
  REM  patch later finds it and reuses it.
) else (
  echo   - no binkw32_orig.dll here; leaving binkw32.dll alone
)

REM ------------------------------------------------- remove the generated art
if exist "data\ARTSET-MANIFEST.txt" (
  for /f "usebackq delims=" %%f in ("data\ARTSET-MANIFEST.txt") do (
    if exist "data\%%f" (
      del /q "data\%%f" >nul 2>&1
      set /a NART+=1
    )
  )
  del /q "data\ARTSET-MANIFEST.txt" >nul 2>&1
)
if exist "data\ARTSET-STATIC.txt" (
  for /f "usebackq delims=" %%f in ("data\ARTSET-STATIC.txt") do (
    if exist "data\%%f" (
      del /q "data\%%f" >nul 2>&1
      set /a NART+=1
    )
  )
  del /q "data\ARTSET-STATIC.txt" >nul 2>&1
)
if !NART! GTR 0 (
  echo   - removed !NART! generated artwork file^(s^)
) else (
  echo   - no generated artwork to remove
)

if exist "data\ARTSET-MODE.txt" del /q "data\ARTSET-MODE.txt" >nul 2>&1
if exist "artsets" rmdir /s /q "artsets" >nul 2>&1

REM ------------------------------------------------------------ the leftovers
if exist "tropico-fix.ini" (
  del /q "tropico-fix.ini" >nul 2>&1
  echo   - removed tropico-fix.ini
)
if exist "tropico-fix.log" del /q "tropico-fix.log" >nul 2>&1

echo.
echo   Done. The game is back to how it was.
echo.
echo   Your saved games and TROPICO.CFG were not touched, and neither were the
echo   px*.PK2 archives -- the patch never wrote to any of them.
echo.
echo   You can delete install.bat, uninstall.bat, READ-ME-FIRST.txt and the
echo   tropico-patch folder whenever you like.
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
