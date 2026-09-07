param([string]$ProcessName = 'Tropico', [string]$Match = '')
# Read another process's environment block and parent pid from its PEB. RUN THIS
# UNDER THE 32-BIT POWERSHELL for a 32-bit game (the PEB offsets below are the
# 32-bit ones): C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe.
# Why: a parent can hand a child `__COMPAT_LAYER`, which overrides the registry
# AppCompat layers for that process alone -- invisible from any registry key
# (FINDINGS 128.4, TESTING trap 8).
$sig = @'
using System; using System.Runtime.InteropServices;
public static class PE32 {
  [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr h, int cls, byte[] info, int len, out int ret);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
}
'@
Add-Type -TypeDefinition $sig
$p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { "no process named $ProcessName"; exit 1 }
$h = $p.Handle
$pbi = New-Object byte[] 24; $ret = 0
[void][PE32]::NtQueryInformationProcess($h, 0, $pbi, 24, [ref]$ret)
$peb = [BitConverter]::ToInt32($pbi, 4); $ppid = [BitConverter]::ToInt32($pbi, 20)
$parent = Get-Process -Id $ppid -ErrorAction SilentlyContinue
"pid $($p.Id) parent $ppid ($(if ($parent) { $parent.ProcessName } else { 'gone' }))"
function ReadPtr([long]$addr) { $b = New-Object byte[] 4; $n = 0; [void][PE32]::ReadProcessMemory($h, [IntPtr]$addr, $b, 4, [ref]$n); return [BitConverter]::ToInt32($b, 0) }
$pp  = ReadPtr ($peb + 0x10)      # PEB.ProcessParameters
$env = ReadPtr ($pp + 0x48)       # RTL_USER_PROCESS_PARAMETERS.Environment
$chunks = New-Object System.Collections.Generic.List[byte]
$off = 0
while ($off -lt 1MB) {
  $b = New-Object byte[] 4096; $n = 0
  if (-not [PE32]::ReadProcessMemory($h, [IntPtr]($env + $off), $b, 4096, [ref]$n) -or $n -le 0) { break }
  $chunks.AddRange($b); $off += 4096
  $s = [System.Text.Encoding]::Unicode.GetString($chunks.ToArray())
  if ($s.IndexOf("`0`0") -ge 0) { break }
}
$s = [System.Text.Encoding]::Unicode.GetString($chunks.ToArray())
$s = $s.Substring(0, [Math]::Max(0, $s.IndexOf("`0`0")))
$vars = $s -split "`0" | Where-Object { $_ }
"$($vars.Count) environment variables"
if ($Match) { $vars | Where-Object { $_ -match $Match } } else { $vars }
