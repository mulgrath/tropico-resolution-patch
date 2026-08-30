@echo off
REM ===================================================================
REM  The Windows trip -- FINDINGS 118.
REM
REM  Double-click this. Two probe passes, then the first run of the game
REM  through a substituted DirectDraw device. It names every log and puts
REM  them in one folder to bring back. There is NO file to edit and NO DLL
REM  to rename: the last trip lost two of its five steps to manual ini
REM  edits, so nothing here asks for one.
REM
REM  Nothing below writes your display configuration. The one cost is
REM  called out before it happens, and you get to decline it.
REM ===================================================================
setlocal
cd /d "%~dp0"

set RESULTS=trip-results

if not exist "ddmonprobe.exe" (
  echo.
  echo !! ddmonprobe.exe is not in this folder.
  echo    This file has to sit next to it, in the Tropico game folder.
  echo.
  pause
  exit /b 1
)

if not exist "%RESULTS%" mkdir "%RESULTS%"

echo.
echo ==========================================================
echo  PASS 1 of 2 -- the free one
echo ==========================================================
echo.
echo  Enumerates the display devices and creates them. It takes no
echo  exclusive mode and changes no resolution, so it costs nothing.
echo.
pause

ddmonprobe.exe --dry
if exist "ddmonprobe.log" copy /y "ddmonprobe.log" "%RESULTS%\ddmonprobe_dry.log" >nul

echo.
echo ==========================================================
echo  PASS 2 of 2 -- this one has a cost
echo ==========================================================
echo.
echo  THE COST: the control arm sets your PRIMARY monitor to 640x480
echo  and back. Nothing is saved anywhere and no setting survives the
echo  run -- but Windows reflows the desktop when the resolution drops
echo  and will NOT put your desktop icons back afterwards.
echo.
echo  It stays because without the control every other result is
echo  unreadable: a DirectDraw error on the second monitor means
echo  nothing unless the identical call on the primary worked in the
echo  same run.
echo.
echo  WATCH YOUR MONITORS during the last phase of each arm. Each one
echo  fills the screen with a named colour and holds it, and writes
echo  which colour on which device to the log BEFORE showing it. No
echo  API reports which physical panel the photons reached, so what
echo  you see IS the measurement. Note the order, for example:
echo.
echo      RED on DISPLAY1, then GREEN on DISPLAY1 again, then BLUE on ...
echo.
echo  Press Ctrl+C now if you would rather stop with pass 1 only.
echo.
pause

ddmonprobe.exe
if exist "ddmonprobe.log" copy /y "ddmonprobe.log" "%RESULTS%\ddmonprobe_real.log" >nul

echo.
echo ==========================================================
echo  STEP 3 -- the one that matters: DeviceSelect in the game
echo ==========================================================
echo.
echo  The probe proved DirectDraw can be pointed at a monitor. This is
echo  the first time Tropico itself renders through one. The ini is
echo  edited for you and put back afterwards.
echo.
echo  WHAT TO WATCH, in this order:
echo    1. does the game open on the monitor you LAUNCHED IT FROM?
echo    2. is your primary monitor untouched - same resolution, icons
echo       where they were?
echo    3. does the MOUSE agree with the picture - do menu buttons
echo       highlight where the pointer actually is?
echo.
echo  Launch it from the monitor you want to play on. Click Play in
echo  Steam on THAT screen. Reach the main menu, load a map, quit.
echo.
choice /c YN /n /m "Run it? [Y/N] "
if errorlevel 2 goto framecount

if not exist "tropico-fix.ini" (
  echo.
  echo !! tropico-fix.ini is not in this folder -- skipping.
  goto framecount
)

copy /y "tropico-fix.ini" "tropico-fix.ini.tripbak" >nul
>>"tropico-fix.ini" echo(
>>"tropico-fix.ini" echo [Display]
>>"tropico-fix.ini" echo DeviceSelect=1

echo.
echo  The ini is set. Launch the game now, then come back and press a key.
echo.
pause

if exist "tropico-fix.log" copy /y "tropico-fix.log" "%RESULTS%\tropico-fix_deviceselect.log" >nul
move /y "tropico-fix.ini.tripbak" "tropico-fix.ini" >nul
echo  ini restored.

:framecount
echo.
echo ==========================================================
echo  OPTIONAL -- the frame counter
echo ==========================================================
echo.
echo  FINDINGS 117 measured the software renderer at 1440p on Linux
echo  under wine, and says plainly that it cannot speak for Windows
echo  players. This closes that, and a LATE-GAME save would close a
echo  second gap it admits: the two-minute city it measured was
echo  trending downward as it grew.
echo.
echo  It costs one game session. This script edits the ini for you and
echo  puts it back afterwards.
echo.
choice /c YN /n /m "Run it? [Y/N] "
if errorlevel 2 goto finish

if not exist "tropico-fix.ini" (
  echo.
  echo !! tropico-fix.ini is not in this folder -- skipping.
  goto finish
)

copy /y "tropico-fix.ini" "tropico-fix.ini.tripbak" >nul
>>"tropico-fix.ini" echo(
>>"tropico-fix.ini" echo [FrameCount]
>>"tropico-fix.ini" echo Enable=1

echo.
echo  The ini is set. Now:
echo    1. launch Tropico from Steam
echo    2. load a save -- a LATE-GAME one if you have it
echo    3. play a couple of minutes with the camera over terrain
echo    4. quit the game
echo.
echo  Then come back here and press a key.
echo.
pause

if exist "tropico-fix.log" copy /y "tropico-fix.log" "%RESULTS%\tropico-fix_framecount.log" >nul
move /y "tropico-fix.ini.tripbak" "tropico-fix.ini" >nul
echo  ini restored.

:finish
echo.
echo ==========================================================
echo  Done. Everything to bring back is in:
echo.
echo      %~dp0%RESULTS%
echo.
dir /b "%RESULTS%"
echo.
echo  Plus one thing no file can hold: which PHYSICAL monitor lit up,
echo  and in what colour order, during pass 2.
echo ==========================================================
echo.
pause
endlocal
