@echo off
REM ============================================================================
REM  Tropico widescreen patch -- installer (Windows)
REM
REM  Plain batch on purpose. This package's one risky component is a DLL that does
REM  IAT hooking and VirtualProtect; that is unavoidable and justified, so every
REM  other part is deliberately the most boring thing that works. PowerShell was
REM  rejected because -ExecutionPolicy Bypass is the malware-delivery pattern
REM  antivirus looks for by name.
REM
REM  There is no art generation here and no Python. The proxy builds the UI art at
REM  launch, from the player's own archives, for whatever resolution the display
REM  turns out to be -- about a second, once per resolution.
REM
REM  CONTROL FLOW IS FLAT, AND THAT IS NOT A STYLE CHOICE. cmd does not support a
REM  label inside a parenthesised block: the parser takes the whole `( ... )` as
REM  one command, and a `:label` in the middle of it either kills the block or is
REM  silently skipped. An earlier draft of this file put the failure handlers
REM  inside the if-blocks that used them, which duplicated `:copyfail` four times
REM  and left the backup step falling straight through into "nothing was changed"
REM  -- the installer could never succeed. Every branch here is `goto` to a label
REM  at top level, and every handler lives at the bottom. Keep it that way.
REM ============================================================================
setlocal enabledelayedexpansion

REM ------------------------------------------------------- find the game
REM  "Extract into your Tropico folder" is ambiguous in BOTH directions, and both
REM  of them were hit on the first install onto real Windows.
REM
REM  DOWN. On GOG the folder named Tropico is NOT the folder holding Tropico.EXE:
REM  the game sits in an `app` subfolder. Extracting into C:\GOG Games\Tropico --
REM  which is what this package's own instructions used to say -- lands one level
REM  ABOVE the game, and a search that only ever looks upward can never find it.
REM  Observed: "it complained that it couldn't find the .exe. I had to copy the
REM  files into the app folder."
REM
REM  UP. Windows Explorer's "Extract All" defaults to a NEW SUBFOLDER named after
REM  the archive, so extracting into exactly the right folder still lands one
REM  level below it -- and a GUI extractor over an archive that carries its own
REM  top-level folder makes that two.
REM
REM  So look where the answer can actually be: here and in app\, then the same two
REM  questions a few levels up. Bounded and local, deliberately -- no registry, no
REM  Steam library parsing, nothing outside this script's own neighbourhood. It is
REM  the search tools/tropico-common.sh has done on Linux since the identical trap
REM  was hit there; only the Windows half was missing.
REM
REM  BOTH Tropico.EXE and data\ must be present. A folder with one and not the
REM  other is not a game folder, and adopting it would fail several steps later
REM  with a message about something else entirely.
REM
REM  GAME NOW CARRIES NO TRAILING BACKSLASH, unlike the version this replaces, and
REM  is written "%GAME%\..." at every use. Nothing then ends in a backslash
REM  immediately before a closing quote -- the one quoting shape in cmd that
REM  nobody should have to reason about, in a package that had never met real cmd.
REM
REM  SRC stays pinned to the script's own folder either way. The game folder
REM  becomes the working directory, so every game-relative path below is
REM  written plainly and still resolves.
set "HERE=%~dp0"
set "GAME="
call :look "%~dp0."
call :look "%~dp0.."
call :look "%~dp0..\.."
call :look "%~dp0..\..\.."
if not defined GAME goto :err_nogame

:found_game
cd /d "%GAME%"

set "SRC=%HERE%tropico-patch"

REM  291328 is measured, not assumed -- the GOG and Steam editions ship a
REM  byte-identical binkw32.dll (same sha256, same size). A different edition is
REM  refused rather than guessed at, and told exactly what to do.
set "BINK_SIZE=291328"

echo.
echo   Tropico widescreen patch
echo   ------------------------
echo.

REM ---------------------------------------------------------------- preflight
REM  Checked by name and up front. Without this the failure is a copy error three
REM  steps in, which tells the player nothing about what they did wrong.
if not exist "data"                  goto :err_nodata
if not exist "%SRC%\binkw32.dll"     goto :err_noproxy
if not exist "%SRC%\tropico-fix.ini" goto :err_noini

for %%A in ("%SRC%\binkw32.dll") do set "PSZ=%%~zA"

REM ------------------------------------------- preserve the real binkw32.dll
REM  THE ONE STEP THAT CAN DESTROY SOMETHING, AND IT IS NOT RECOVERABLE.
REM
REM  If binkw32.dll is already our proxy and we copy it over binkw32_orig.dll, the
REM  real Bink is gone for good and every movie in the game with it. That is not
REM  hypothetical: it is what a second run of a naive installer does.
REM
REM  WHY THIS IS SIZE-BASED AND NOT A STRING SEARCH. The obvious check is
REM  `findstr /C:` for the proxy's marker string. Measured under wine's cmd:
REM  findstr cannot search a binary at all there (it returns "not found" for a
REM  file that plainly contains the string), and `fc /b` reports two completely
REM  different DLLs as identical. Both are Wine reimplementations and both may
REM  well behave on real Windows -- but a guard against irreversible data loss
REM  cannot rest on a tool whose behaviour we were unable to confirm.
REM
REM  So the gate is the file SIZE, via cmd's own %%~zA, which needs no external
REM  program and was verified to report true sizes. It is written as REFUSE
REM  UNLESS CLEARLY SAFE: the only thing we will ever back up is a file that is
REM  exactly the Bink we know.

if exist "binkw32_orig.dll" goto :have_backup
if not exist "binkw32.dll"  goto :err_nobink

for %%A in ("binkw32.dll") do set "SZ=%%~zA"

REM  Same size as the proxy we are about to install: this is already the patch,
REM  and the real Bink is not on disk to preserve. Tested BEFORE the Bink-size
REM  test, so a future build that happened to be 291328 bytes could never be
REM  mistaken for stock and backed up over the real thing.
if "%SZ%"=="%PSZ%" goto :err_alreadypatched

REM  Belt and braces. Ignored where findstr cannot read binaries, which is
REM  exactly why it is not the only gate.
findstr /C:tropico_fix "binkw32.dll" >nul 2>&1
if not errorlevel 1 goto :err_oldpatch

if not "%SZ%"=="%BINK_SIZE%" goto :err_unknownbink

copy /y "binkw32.dll" "binkw32_orig.dll" >nul
if errorlevel 1 goto :err_copy

REM  Post-condition, checked rather than trusted: if what we just wrote is not
REM  the size of the real Bink, remove it. A backup that is silently wrong is
REM  worse than no backup, because it will be restored one day.
for %%A in ("binkw32_orig.dll") do set "BSZ=%%~zA"
if not "%BSZ%"=="%BINK_SIZE%" goto :err_badbackup
echo   - preserved the original binkw32.dll as binkw32_orig.dll
goto :backup_done

:have_backup
echo   - binkw32_orig.dll is already here; leaving it untouched

:backup_done

REM ------------------------------------------------------- install the proxy
copy /y "%SRC%\binkw32.dll" "binkw32.dll" >nul
if errorlevel 1 goto :err_copy

REM  Verified rather than assumed: a copy that silently half-succeeded would leave
REM  a DLL the game cannot load, and the symptom is a launch failure with no clue.
REM  By size, not `fc /b` -- measured, wine's fc calls two different DLLs
REM  identical, so it would have verified nothing at all.
for %%A in ("binkw32.dll") do set "ISZ=%%~zA"
if not "%ISZ%"=="%PSZ%" goto :err_verify
echo   - installed binkw32.dll and verified it

REM ---------------------------------------------------------------- the ini
REM  Never reset. It holds the player's preferences, and an upgrade that silently
REM  reset them would be a worse bug than anything it fixed. But never left
REM  behind either: an upgrade that kept the old file verbatim hid every setting
REM  the new version added, because the file that documents them was the one
REM  the installer refused to touch. So an existing ini is carried INTO the new
REM  template -- every uncommented setting kept, section by section, every new
REM  key and comment arriving -- by upgrade-ini.bat. If that fails for any
REM  reason the old file stays exactly as it was, and the message says so.
if exist "tropico-fix.ini" goto :ini_upgrade
copy /y "%SRC%\tropico-fix.ini" "tropico-fix.ini" >nul
if errorlevel 1 goto :err_copy
echo   - wrote tropico-fix.ini
goto :ini_done

:ini_upgrade
if not exist "%SRC%\upgrade-ini.bat" goto :ini_kept
if exist "tropico-fix.ini.new" del /q "tropico-fix.ini.new" >nul 2>&1
call "%SRC%\upgrade-ini.bat" "tropico-fix.ini" "%SRC%\tropico-fix.ini" "tropico-fix.ini.new"
if errorlevel 1 goto :ini_kept
if not exist "tropico-fix.ini.new" goto :ini_kept
move /y "tropico-fix.ini.new" "tropico-fix.ini" >nul
if errorlevel 1 goto :ini_kept
echo   - updated tropico-fix.ini; your settings were carried over, new options added
goto :ini_done

:ini_kept
if exist "tropico-fix.ini.new" del /q "tropico-fix.ini.new" >nul 2>&1
echo   - tropico-fix.ini already exists; your settings are kept ^(the new
echo     options could not be merged in -- see tropico-patch\tropico-fix.ini^)

:ini_done

REM ------------------------------------------------------- ask for fresh art
REM  The proxy compares data\ARTSET-MODE.txt against the mode it is about to use
REM  (ag_set_is_current: no marker at all means "not current"), so deleting the
REM  marker is how an install asks for a rebuild. Cheap, and it is the only thing
REM  that makes a reinstall notice.
if exist "data\ARTSET-MODE.txt" del /q "data\ARTSET-MODE.txt" >nul 2>&1

REM  Upgrading from a version that staged art per monitor: that whole subsystem is
REM  gone and the sets are dead weight -- 226 MB for three modes on a development
REM  box. Removed only now, once the proxy that replaces them is already in place.
if not exist "artsets" goto :done
rmdir /s /q "artsets" >nul 2>&1
echo   - removed the old staged art sets ^(artwork is built at launch now^)

:done
echo.
echo   Done. Start Tropico the way you normally do.
echo.
echo   The first time you play at a new screen resolution, the patch spends
echo   about a second building the interface artwork for it, from your own
echo   game files. After that it starts straight away.
echo.
pause
exit /b 0

REM ------------------------------------------------------------------ :look
REM  Sets GAME the first time it finds a game folder and is a no-op afterwards,
REM  so the ORDER OF THE CALLS ABOVE IS THE SEARCH ORDER: nearest first, and the
REM  script's own folder beats anything found by walking up.
REM
REM  `call` to a label at top level, never a label inside a parenthesised block --
REM  see the note at the top of this file for what that costs.
REM
REM  %~f1 resolves the ".." segments the caller passes and strips the trailing
REM  separator, so "%~dp0.." arrives here as a plain absolute path.
:look
if defined GAME goto :eof
set "L=%~f1"
if exist "%L%\Tropico.EXE" if exist "%L%\data" set "GAME=%L%"
if defined GAME goto :eof
if exist "%L%\app\Tropico.EXE" if exist "%L%\app\data" set "GAME=%L%\app"
goto :eof

REM ============================================================================
REM  Failure handlers. All at top level; none reachable by falling through.
REM ============================================================================

:err_nogame
echo   PROBLEM: could not find Tropico near this folder.
echo.
echo   Looked for a folder holding both Tropico.EXE and data\ -- here, in an
echo   "app" subfolder, and in those same two places up to three folders up.
echo.
echo   Move this whole folder into your Tropico installation and run it again.
echo   Extracting it anywhere inside that installation is enough; extracting it
echo   somewhere else entirely, such as Downloads, is not.
echo.
echo   GOG    usually  C:\GOG Games\Tropico\app    ^(the game is inside "app"^)
echo   Steam  usually  C:\Program Files ^(x86^)\Steam\steamapps\common\Tropico
echo           ^(in Steam: right-click the game, Manage, Browse local files^)
goto :fail

:err_nodata
echo   PROBLEM: there is no data\ folder here, so this is not a Tropico install.
goto :fail

:err_noproxy
echo   PROBLEM: %SRC%\binkw32.dll is missing.
echo.
echo   Extract the WHOLE ZIP, keeping its folder structure. Some unzip tools
echo   flatten folders; this one needs %SRC%\ to survive.
goto :fail

:err_noini
echo   PROBLEM: %SRC%\tropico-fix.ini is missing. Extract the whole ZIP.
goto :fail

:err_nobink
echo   PROBLEM: binkw32.dll is missing from your game folder.
echo   Verify or reinstall the game, then run this again.
goto :fail

:err_alreadypatched
echo   PROBLEM: binkw32.dll here is ALREADY the patch, but binkw32_orig.dll
echo   is missing -- so the original Bink is not on disk to preserve.
goto :norestore

:err_oldpatch
echo   PROBLEM: binkw32.dll here appears to be an older build of the patch,
echo   and binkw32_orig.dll is missing -- the original Bink is not on disk.
goto :norestore

:err_unknownbink
echo   PROBLEM: binkw32.dll is %SZ% bytes; the Bink this patch knows is
echo   %BINK_SIZE% bytes on both the GOG and Steam editions.
echo.
echo   Refusing to touch it rather than guess. Either verify your game files
echo   and run this again, or -- if you are certain that file is the real
echo   Bink -- copy it to binkw32_orig.dll yourself and re-run install.bat,
echo   which will then leave your copy alone.
goto :fail

:err_badbackup
del /q "binkw32_orig.dll" >nul 2>&1
echo   PROBLEM: the backup did not come out the right size. It has been
echo   removed, and nothing else was changed.
goto :fail

:err_verify
echo   PROBLEM: binkw32.dll was copied but does not match the source.
echo   Antivirus software sometimes quarantines it mid-copy. Check yours,
echo   then run this again.
goto :fail

:err_copy
echo   PROBLEM: a file could not be copied.
echo.
echo   The usual causes, in order of likelihood:
echo     - the game is running. Close it and try again.
echo     - antivirus software blocked it. See READ-ME-FIRST.txt.
echo     - the game is in a protected folder ^(Program Files^). Right-click
echo       install.bat and choose "Run as administrator".
goto :fail

:norestore
echo.
echo   Nothing has been changed. Restore the original binkw32.dll first:
echo     GOG   - reinstall, or use GOG Galaxy's "Verify / Repair"
echo     Steam - Properties, Installed Files, "Verify integrity of game files"
echo.
echo   Then run install.bat again.
goto :fail

:fail
echo.
echo   Nothing was changed.
echo.
pause
exit /b 1
