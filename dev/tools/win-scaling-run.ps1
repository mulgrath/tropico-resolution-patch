param(
  [string]$Tag,
  [string]$GameDir = 'C:\GOG Games\Tropico\app',
  [string]$ProbeExe = 'C:\GOG Games\Tropico\dpiprobe.exe',
  [string]$OutDir = '',
  [string]$ExpectUnaware = '2048 x 1152',
  [int[]]$ShotAt = @(6, 22, 40),
  [int]$EscAt = 10,
  [int]$KillAt = 46,
  [switch]$Steam,
  [string]$SteamAppId = '33520',
  [int]$ModulesAt = 0,
  [string]$Exe = '',
  [hashtable]$Env = @{},
  [int]$SetRel = 1,
  [int]$ClickAt = 0,
  [int[]]$ClickXY = @(0, 0),
  [int[]]$KeyAt = @(),
  [string]$Key = '{F2}',
  [int]$ReapplyAt = 0,
  [switch]$FullShots,
  [switch]$Leave
)
# -FullShots saves the captures at 1:1 instead of half size (a 4K frame is 6-8 MB):
# the only way to compare glyphs (FINDINGS 131).
# -ReapplyAt N sets the scale again, step -SetRel, N seconds after launch: the
# scripted scale drops at the game's own mode switch (FINDINGS 128.4), so a mode
# smaller than the scaled desktop is otherwise always photographed at 100%. With
# it, the dpi in each later line says whether the desktop was scaled when the frame
# was drawn.
# -SetRel is the scale step re-applied when the probe finds the desktop drifted
# (1 = 125%, 4 = 200% on a monitor whose recommended scale is 100%); pair it with
# -ExpectUnaware. -ClickAt N clicks the left button at -ClickXY (screen pixels in the
# display mode running at that moment) -- enough to press a menu item. -KeyAt N sends
# -Key (SendKeys syntax, F2 by default: the settings dialog, reachable only inside a
# map) at each listed time; list it twice a couple of seconds apart if a press is
# missed, the way the rig's driver retries (FINDINGS 129). -Leave skips the kill so
# the game stays up for a person to look at.
# -Env sets variables in this process before a direct launch, so the child inherits
# them. The Steam client hands its games `__COMPAT_LAYER=... HighDpiAware`
# (FINDINGS 128.4) and the stub relaunches through Steam unless SteamAppId is
# present, so a genuinely unaware Steam-edition run is: direct launch, -Env
# @{ SteamAppId='33520'; SteamGameId='33520'; SteamClientLaunch='1' }, nothing else.
foreach ($k in $Env.Keys) { Set-Item -Path "Env:$k" -Value $Env[$k] }
# -Exe names the executable when it is not $GameDir\Tropico.EXE (a renamed copy,
# which has no path-keyed compatibility entries); the process name follows it.
if (-not $Exe) { $Exe = Join-Path $GameDir 'Tropico.EXE' }
$ProcName = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
# One unattended Windows scaling run (FINDINGS 128): verify the desktop is scaled,
# launch the game from a focused window on the primary, photograph the panel at fixed
# times, record the game window's rectangle in panel pixels and the live display
# mode, kill the game, and probe the scale again.
#
#   win-scaling-run.ps1 -Tag G2 -GameDir 'C:\GOG Games\Tropico\app'
#   win-scaling-run.ps1 -Tag S1 -Steam -GameDir '...\steamapps\common\Tropico'
#
# The ini and the DLL are whatever is in $GameDir: put them in place first, and
# read the log block back afterwards. The intro is skipped with ESC when the game
# takes it. Needs probes/dpiprobe.c built as $ProbeExe (TESTING trap 8).
if (-not $OutDir) { $OutDir = Join-Path $GameDir 'scaling-trip' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory $OutDir | Out-Null }
$sig = @'
using System; using System.Runtime.InteropServices;
public static class W {
  [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr c);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern IntPtr FindWindowA(string cls, string title);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern bool EnumDisplaySettingsA(string dev, int i, byte[] dm);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDpiAwarenessContext(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetAwarenessFromDpiAwarenessContext(IntPtr c);
  [DllImport("shcore.dll")] public static extern int GetProcessDpiAwareness(IntPtr hProcess, out int value);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, IntPtr extra);
  [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
  [DllImport("shcore.dll")] public static extern int GetDpiForMonitor(IntPtr m, int type, out uint x, out uint y);
}
[StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
'@
Add-Type -TypeDefinition $sig
[void][W]::SetProcessDpiAwarenessContext([IntPtr](-4))
Add-Type -AssemblyName System.Windows.Forms
$shot = Join-Path $PSScriptRoot 'win-screenshot.ps1'
$dpi  = Join-Path $PSScriptRoot 'win-dpi-scale.ps1'
function Probe { $u = cmd /c "`"$ProbeExe`" < NUL"; ($u | Select-String 'SM_CXSCREEN' | Select-Object -First 1).Line.Trim() }
function GameRect {
  $h = [W]::FindWindowA('Tropico', $null)
  if ($h -eq [IntPtr]::Zero) {
    $p = Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) { $h = $p.MainWindowHandle }
  }
  if ($h -eq [IntPtr]::Zero) { return 'no Tropico window' }
  $r = New-Object RECT; [void][W]::GetWindowRect($h, [ref]$r)
  $fg = [W]::GetForegroundWindow()
  $dm = New-Object byte[] 220; [System.BitConverter]::GetBytes([int16]220).CopyTo($dm, 36)   # dmSize
  $mode = 'mode ?'
  if ([W]::EnumDisplaySettingsA('\\.\DISPLAY1', -1, $dm)) { $mode = "DISPLAY1 mode now $([System.BitConverter]::ToInt32($dm,108))x$([System.BitConverter]::ToInt32($dm,112))" }
  # The window's own DPI awareness, read from outside: 0 unaware, 1 system, 2 per-monitor.
  # This is what the compositor scales by, whatever the log says (TESTING trap 8).
  $aw = [W]::GetAwarenessFromDpiAwarenessContext([W]::GetWindowDpiAwarenessContext($h))
  $names = @('UNAWARE', 'SYSTEM_AWARE', 'PER_MONITOR_AWARE')
  # The PROCESS-level value beside the window's: a window more aware than its process
  # means a thread-level SetThreadDpiAwarenessContext by something inside the process.
  $pv = -1; $pr = Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($pr) { [void][W]::GetProcessDpiAwareness($pr.Handle, [ref]$pv) }
  $pName = if ($pv -ge 0) { $names[$pv] } else { '?' }
  # The monitor's effective DPI at this moment, read by this per-monitor-aware process
  # (96 = 100%, 120 = 125%): whether the scale was still on when the frame was drawn,
  # since it drifts across the game's own mode switch (FINDINGS 128.4). No new process
  # and no focus change, so it is safe to read while the game is fullscreen.
  $dx = [uint32]0; $dy = [uint32]0
  [void][W]::GetDpiForMonitor([W]::MonitorFromWindow($h, 2), 0, [ref]$dx, [ref]$dy)
  $scale = [int][math]::Round($dx * 100 / 96)
  return "Tropico window ($($r.L),$($r.T))-($($r.R),$($r.B)) = $($r.R-$r.L)x$($r.B-$r.T) panel px, foreground=$($fg -eq $h), window awareness=$($names[$aw]), process awareness=$pName; $mode; monitor dpi now $dx ($scale%)"
}
[void][W]::SetCursorPos(1280, 720)
# THE SCALE MUST BE VERIFIED AT LAUNCH (TESTING trap 8): a scripted 125% drifts back
# to 100% on a mode switch and sometimes on its own, and an unverified run measures
# nothing.
$p = Probe
if ($p -notmatch [regex]::Escape($ExpectUnaware)) {
  "[$Tag] scale drifted ($p) -- re-applying step $SetRel above recommended"
  & $dpi -Device '\\.\DISPLAY1' -SetRel $SetRel | Out-Null; Start-Sleep -Seconds 3
  $p = Probe
  if ($p -notmatch [regex]::Escape($ExpectUnaware)) { "[$Tag] ABORT: unaware probe still reads $p"; exit 1 }
}
"[$Tag] unaware probe at launch: $p"
$t0 = Get-Date
if ($Steam) { Start-Process "steam://rungameid/$SteamAppId" } else { Start-Process -FilePath $Exe -WorkingDirectory $GameDir }
"[$Tag] launched at $($t0.ToString('HH:mm:ss'))"
$events = @()
foreach ($s in $ShotAt) { $events += @{ t = $s; k = 'shot' } }
$events += @{ t = $EscAt; k = 'esc' }
if (-not $Leave) { $events += @{ t = $KillAt; k = 'kill' } }
if ($ClickAt -gt 0) { $events += @{ t = $ClickAt; k = 'click' } }
foreach ($s in $KeyAt) { $events += @{ t = $s; k = 'key' } }
if ($ReapplyAt -gt 0) { $events += @{ t = $ReapplyAt; k = 'reapply' } }
function ModeWH {
  $dm = New-Object byte[] 220; [System.BitConverter]::GetBytes([int16]220).CopyTo($dm, 36)
  if ([W]::EnumDisplaySettingsA('\\.\DISPLAY1', -1, $dm)) { return @([System.BitConverter]::ToInt32($dm,108), [System.BitConverter]::ToInt32($dm,112)) }
  return @(2560, 1440)
}
# -ModulesAt N lists every DLL in the game process that is not from the Windows
# directory: the way to see an injector (the Steam overlay, or anything else that
# could have set DPI awareness before DllMain -- TESTING trap 8).
if ($ModulesAt -gt 0) { $events += @{ t = $ModulesAt; k = 'mods' } }
foreach ($e in ($events | Sort-Object { $_.t })) {
  $wait = $e.t - ((Get-Date) - $t0).TotalSeconds
  if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
  switch ($e.k) {
    'shot' { $f = Join-Path $OutDir "$Tag-t$($e.t).png"; $wh = ModeWH; & $shot -Out $f -W $wh[0] -H $wh[1] -Full:$FullShots | Out-Null; "[$Tag] t=$($e.t)s $(GameRect) -> $f" }
    'click' { [void][W]::SetCursorPos($ClickXY[0], $ClickXY[1]); Start-Sleep -Milliseconds 300; [W]::mouse_event(2, 0, 0, 0, [IntPtr]::Zero); Start-Sleep -Milliseconds 80; [W]::mouse_event(4, 0, 0, 0, [IntPtr]::Zero); "[$Tag] t=$($e.t)s clicked at $($ClickXY[0]),$($ClickXY[1])" }
    'esc'  { try { [System.Windows.Forms.SendKeys]::SendWait('{ESC}') } catch {}; "[$Tag] t=$($e.t)s sent ESC; $(GameRect)" }
    'key'  { try { [System.Windows.Forms.SendKeys]::SendWait($Key) } catch {}; "[$Tag] t=$($e.t)s sent $Key; $(GameRect)" }
    'reapply' { $rc = & $dpi -Device '\\.\DISPLAY1' -SetRel $SetRel; Start-Sleep -Seconds 2; "[$Tag] t=$($e.t)s re-applied scale step $SetRel ($(($rc | Select-String 'rc=') -replace '^\s+','')); $(GameRect)" }
    'kill' { $g = Get-Process -Name $ProcName -ErrorAction SilentlyContinue; if ($g) { $g | Stop-Process -Force; "[$Tag] t=$($e.t)s killed pid $($g.Id)" } else { "[$Tag] t=$($e.t)s game already gone" } }
    'mods' {
      # A 32-bit PowerShell, because a 64-bit process sees only the WoW64 shims of a
      # 32-bit game. Full paths, with the Windows directory filtered out.
      $ps32 = 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
      $lines = & $ps32 -NoProfile -Command "(Get-Process -Name '$ProcName' -ErrorAction SilentlyContinue | Select-Object -First 1).Modules | ForEach-Object { '{0} @ {1:x8}' -f `$_.FileName, `$_.BaseAddress.ToInt64() }" 2>$null
      $all = @($lines | Where-Object { $_ })
      $foreign = @($all | Where-Object { $_ -notlike 'C:\Windows\*' -and $_ -notmatch '\\data2\\miles\\' })
      "[$Tag] t=$($e.t)s $($all.Count) modules in the process; not from C:\Windows: " + ($foreign -join ' ')
      # And the environment it was given, for a __COMPAT_LAYER or anything Steam/DPI.
      $envScript = Join-Path $PSScriptRoot 'win-procenv.ps1'
      $envLines = & $ps32 -NoProfile -ExecutionPolicy Bypass -File $envScript -ProcessName $ProcName -Match '(?i)compat|steam|dpi|^path=' 2>&1
      "[$Tag] t=$($e.t)s environment: " + (($envLines | ForEach-Object { "$_" }) -join ' | ')
    }
  }
}
Start-Sleep -Seconds 2
"[$Tag] done; processes named $ProcName now: $((Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Measure-Object).Count); unaware probe after: $(Probe)"
