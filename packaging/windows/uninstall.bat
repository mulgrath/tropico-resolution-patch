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
REM
REM  Flat control flow, same reason as install.bat: cmd cannot take a label inside
REM  a parenthesised block, and putting the handlers where they were used is what
REM  broke that file.
REM ============================================================================
setlocal enabledelayedexpansion

REM ------------------------------------------------------- find the game
REM  Normally the ZIP was extracted straight into the Tropico folder and the
REM  game is right here. But Windows Explorer's "Extract All" defaults to a
REM  NEW SUBFOLDER named after the archive, so a player who does the obvious
REM  thing -- extract into the Tropico folder -- ends up one level down. That
REM  is the most likely way to get this wrong, so it is handled rather than
REM  reported: look here, then look one level up.
REM
REM  SRC stays pinned to the script's own folder either way. The game folder
REM  becomes the working directory, so every game-relative path below is
REM  written plainly and still resolves.
set "HERE=%~dp0"
set "GAME=%~dp0"
if exist "%GAME%Tropico.EXE" goto :found_game
for %%D in ("%~dp0..") do set "GAME=%%~fD\"
if exist "%GAME%Tropico.EXE" goto :found_game
goto :err_nogame

:found_game
cd /d "%GAME%"

REM  The size of the real Bink, on both the GOG and Steam editions. See the long
REM  comment in install.bat for why every guard in this package is size-based:
REM  under wine's cmd, findstr cannot search a binary and fc /b calls two
REM  different DLLs identical. An earlier version of THIS file guarded the
REM  restore with `findstr /M` on binkw32_orig.dll -- the one check install.bat
REM  documents as untrustworthy, protecting the one step that cannot be undone.
set "BINK_SIZE=291328"
set /a NART=0

echo.
echo   Tropico widescreen patch -- uninstall
echo   ------------------------------------
echo.


REM -------------------------------------------------- restore the real binkw32
REM  Refuse unless the backup is clearly the real thing. Restoring a proxy over
REM  itself would leave a proxy forwarding to a proxy -- the game would fail to
REM  start, the real Bink would still be missing, and the uninstaller would have
REM  reported success.
if not exist "binkw32_orig.dll" goto :no_backup

for %%A in ("binkw32_orig.dll") do set "BSZ=%%~zA"
if not "%BSZ%"=="%BINK_SIZE%" goto :err_badbackup

copy /y "binkw32_orig.dll" "binkw32.dll" >nul
if errorlevel 1 goto :err_restore
echo   - restored the original binkw32.dll
REM  binkw32_orig.dll is left in place ON PURPOSE. It is the only copy of the
REM  real Bink on disk that we know to be good; deleting it to look tidy would
REM  mean a failed copy above leaves the player with nothing. Reinstalling the
REM  patch later finds it and reuses it.
goto :bink_done

:no_backup
echo   - no binkw32_orig.dll here; leaving binkw32.dll alone

:bink_done

REM ------------------------------------------------- remove the generated art
REM  Each name goes through :delart rather than an `if exist ... & set /a` chained
REM  in the loop body. Measured: that form deletes every file correctly but
REM  under-counts, because the `&` does not bind to the `if` the way it reads --
REM  the uninstaller reported 2 files when it had removed 3. A called subroutine
REM  is the boring form that counts what it did.
if not exist "data\ARTSET-MANIFEST.txt" goto :static
for /f "usebackq delims=" %%f in ("data\ARTSET-MANIFEST.txt") do call :delart "%%f"
del /q "data\ARTSET-MANIFEST.txt" >nul 2>&1

:static
if not exist "data\ARTSET-STATIC.txt" goto :art_done
for /f "usebackq delims=" %%f in ("data\ARTSET-STATIC.txt") do call :delart "%%f"
del /q "data\ARTSET-STATIC.txt" >nul 2>&1

:art_done
if !NART! GTR 0 echo   - removed !NART! generated artwork file^(s^)
if !NART! EQU 0 echo   - no generated artwork to remove

if exist "data\ARTSET-MODE.txt" del /q "data\ARTSET-MODE.txt" >nul 2>&1
if exist "artsets" rmdir /s /q "artsets" >nul 2>&1

REM ------------------------------------------------------------ the leftovers
if not exist "tropico-fix.ini" goto :log
del /q "tropico-fix.ini" >nul 2>&1
echo   - removed tropico-fix.ini

:log
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

REM ---------------------------------------------------------------- :delart
REM  Called once per manifest line. %~1 strips the quotes the caller added, so a
REM  name with a space still resolves to one file.
:delart
if not exist "data\%~1" goto :eof
del /q "data\%~1" >nul 2>&1
set /a NART+=1
goto :eof

REM ============================================================================
REM  Failure handlers.
REM ============================================================================

:err_nogame
echo   PROBLEM: Tropico.EXE is not in this folder, so this is not the place
echo   the patch was installed. Nothing was changed.
goto :fail

:err_badbackup
echo   PROBLEM: binkw32_orig.dll is %BSZ% bytes; the real Bink is %BINK_SIZE%.
echo   That file is not the original, so restoring it would leave the game
echo   unable to start. Refusing to touch it.
echo.
echo   Restore binkw32.dll from your game installer instead:
echo     GOG   - reinstall, or GOG Galaxy "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
goto :fail

:err_restore
echo   PROBLEM: could not restore binkw32.dll. Is the game running?
goto :fail

:fail
echo.
pause
exit /b 1
