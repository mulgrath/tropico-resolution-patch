@echo off
REM ============================================================================
REM  upgrade-ini.bat OLD TEMPLATE OUT
REM
REM  Carry a player's settings into a new tropico-fix.ini template. Called by
REM  install.bat when a tropico-fix.ini already exists; nothing else runs it.
REM
REM  AN UPGRADE MUST NOT RESET SETTINGS, AND MUST NOT HIDE NEW ONES EITHER.
REM  Keeping the old file verbatim did the first and failed the second: a player
REM  who installed 1.4 never saw the keys 1.5 added, because the file that
REM  documents them was the one the installer refused to touch. So the template
REM  is the shape and the old file supplies the values: every uncommented
REM  Key=Value in the old file replaces the matching line in the template,
REM  section by section (Enable means different things under [WorldFix] and
REM  [Text]), and everything else in the template -- comments, new keys -- comes
REM  through as written.
REM
REM  Keys the template does not know are kept INSIDE their section: Windows
REM  reads only the first section of a given name, so a second [Display] at the
REM  end of the file would be ignored and the setting lost without a word.
REM  Whole sections the template lacks are appended.
REM
REM  Plain batch, like install.bat, and for the same reason: PowerShell with
REM  -ExecutionPolicy Bypass is the pattern antivirus looks for by name.
REM
REM  HOW THE LINES ARE READ. `for /f` skips lines starting with ";" unless told
REM  otherwise -- which in an ini is most of the file -- so eol= is set to a
REM  space, which no line here starts with. It also skips EMPTY lines and cannot
REM  be told not to, so the blank lines are put back by rule: one before every
REM  section header, and one before a comment that follows a key. That is the
REM  template's own layout, and the test is that an empty old file reproduces
REM  the template exactly. (findstr /n, the usual trick, is not implemented by
REM  Wine's findstr, and a routine that cannot be tested off Windows is one that
REM  ships untested.)
REM
REM  Old values live in variables named OLD_<Section>_<Key>. Sections and keys
REM  in this ini are letters and digits only, so the name cannot be ambiguous.
REM ============================================================================
setlocal enabledelayedexpansion
set "OLD=%~1"
set "TPL=%~2"
set "OUT=%~3"
if not exist "%OLD%" exit /b 1
if not exist "%TPL%" exit /b 1
if exist "%OUT%" del /q "%OUT%" >nul 2>&1

set "SEC="
for /f "usebackq eol= delims=" %%L in ("%OLD%") do (
  set "L=%%L"
  call :old_line
)

set "SEC="
set "ANY="
set "PREVKEY="
for /f "usebackq eol= delims=" %%L in ("%TPL%") do (
  set "L=%%L"
  call :tpl_line
)
call :flush

REM  Sections the old file has and the template does not.
for /f "tokens=1* delims==" %%A in ('set OLDSEC_ 2^>nul') do (
  set "VAR=%%A"
  set "S=!VAR:OLDSEC_=!"
  if not defined SEEN_!S! (
    >>"%OUT%" echo(
    >>"%OUT%" echo([!S!]
    set "SEC=!S!"
    set "PREVKEY="
    call :flush
  )
)

if not exist "%OUT%" exit /b 1
exit /b 0

REM ------------------------------------------------------------ :old_line
REM  Remember every uncommented Key=Value of the old file, under its section.
:old_line
if "!L:~0,1!"=="[" (
  set "SEC=!L:~1!"
  set "SEC=!SEC:]=!"
  set "OLDSEC_!SEC!=1"
  goto :eof
)
if not defined SEC goto :eof
if "!L:~0,1!"==";" goto :eof
for /f "tokens=1* delims==" %%A in ("!L!") do (
  set "K=%%A"
  set "V=%%B"
)
if "!K!"=="!L!" goto :eof
if not "!K: =!"=="!K!" goto :eof
if not defined V goto :eof
if not defined OLD_!SEC!_!K! set "OLD_!SEC!_!K!=!V!"
goto :eof

REM ------------------------------------------------------------ :tpl_line
REM  Write the template line, or the old value where the old file set that key.
:tpl_line
if "!L:~0,1!"=="[" (
  call :flush
  set "SEC=!L:~1!"
  set "SEC=!SEC:]=!"
  set "SEEN_!SEC!=1"
  if defined ANY >>"%OUT%" echo(
  >>"%OUT%" echo(!L!
  set "ANY=1"
  set "PREVKEY="
  goto :eof
)
set "K=!L!"
if "!K:~0,1!"==";" set "K=!K:~1!"
for /f "tokens=1* delims==" %%A in ("!K!") do set "K1=%%A"
if "!K1!"=="!K!" goto :tpl_plain
if not "!K1: =!"=="!K1!" goto :tpl_plain
if not defined SEC goto :tpl_key
if not defined OLD_!SEC!_!K1! goto :tpl_key
for %%A in ("OLD_!SEC!_!K1!") do >>"%OUT%" echo(!K1!=!%%~A!
set "USED_!SEC!_!K1!=1"
set "ANY=1"
set "PREVKEY=1"
goto :eof
:tpl_key
>>"%OUT%" echo(!L!
set "ANY=1"
set "PREVKEY=1"
goto :eof
:tpl_plain
if "!L:~0,1!"==";" if defined PREVKEY >>"%OUT%" echo(
>>"%OUT%" echo(!L!
set "ANY=1"
set "PREVKEY="
goto :eof

REM --------------------------------------------------------------- :flush
REM  The old file's keys under SEC that the template never mentioned.
:flush
if not defined SEC goto :eof
set "HDR="
for /f "tokens=1* delims==" %%A in ('set OLD_%SEC%_ 2^>nul') do (
  set "VAR=%%A"
  set "KEY=!VAR:OLD_%SEC%_=!"
  if not defined USED_%SEC%_!KEY! (
    if not defined HDR (
      if defined PREVKEY >>"%OUT%" echo(
      >>"%OUT%" echo(; kept from your previous tropico-fix.ini
      set "HDR=1"
    )
    >>"%OUT%" echo(!KEY!=%%B
    set "USED_%SEC%_!KEY!=1"
    set "ANY=1"
    set "PREVKEY=1"
  )
)
goto :eof
