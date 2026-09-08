param([string]$Device = '\\.\DISPLAY1', [int]$SetRel = [int]::MinValue)
# Read or set a monitor's display scale on Windows, through the DisplayConfig
# device-info calls the Settings app uses (FINDINGS 128.4).
#
#   win-dpi-scale.ps1                         read every monitor
#   win-dpi-scale.ps1 -SetRel 1               DISPLAY1 one step above its recommended scale (100% -> 125%)
#   win-dpi-scale.ps1 -SetRel 0               back to the recommended scale
#
# -SetRel is relative to the monitor's recommended scale, the way Windows stores
# it. THE SCALE DRIFTS: a value set this way fell back to the recommended one
# across a display-mode switch and once on its own, while the registry still held
# the new value. Verify with probes/dpiprobe.exe before every launch
# (win-scaling-run.ps1 does). Raw buffers throughout: the struct marshalling
# returned error 31 for every device-info call.
$sig = @'
using System; using System.Runtime.InteropServices;
public static class DC2 {
  [DllImport("user32.dll")] public static extern int GetDisplayConfigBufferSizes(uint flags, out uint nPath, out uint nMode);
  [DllImport("user32.dll")] public static extern int QueryDisplayConfig(uint flags, ref uint nPath, IntPtr paths, ref uint nMode, IntPtr modes, IntPtr topo);
  [DllImport("user32.dll")] public static extern int DisplayConfigGetDeviceInfo(IntPtr p);
  [DllImport("user32.dll")] public static extern int DisplayConfigSetDeviceInfo(IntPtr p);
}
'@
Add-Type -TypeDefinition $sig
$M = [System.Runtime.InteropServices.Marshal]
$scales = @(100,125,150,175,200,225,250,300,350,400,450,500)
$nP = 0; $nM = 0
[void][DC2]::GetDisplayConfigBufferSizes(2, [ref]$nP, [ref]$nM)      # QDC_ONLY_ACTIVE_PATHS
$pb = $M::AllocHGlobal(72 * $nP); $mb = $M::AllocHGlobal(64 * $nM)
$r = [DC2]::QueryDisplayConfig(2, [ref]$nP, $pb, [ref]$nM, $mb, [IntPtr]::Zero)
if ($r -ne 0) { throw "QueryDisplayConfig $r" }
function Header([IntPtr]$buf, [int]$size, [int]$type, [int]$low, [int]$high, [int]$id) {
  for ($k = 0; $k -lt $size; $k += 4) { $M::WriteInt32([IntPtr]([long]$buf + $k), 0) }
  $M::WriteInt32($buf, $type); $M::WriteInt32([IntPtr]([long]$buf+4), $size)
  $M::WriteInt32([IntPtr]([long]$buf+8), $low); $M::WriteInt32([IntPtr]([long]$buf+12), $high)
  $M::WriteInt32([IntPtr]([long]$buf+16), $id)
}
for ($i = 0; $i -lt $nP; $i++) {
  $base = [long]$pb + 72 * $i                                         # DISPLAYCONFIG_PATH_INFO
  $low = $M::ReadInt32([IntPtr]$base); $high = $M::ReadInt32([IntPtr]($base + 4)); $id = $M::ReadInt32([IntPtr]($base + 8))
  $nb = $M::AllocHGlobal(84); Header $nb 84 1 $low $high $id          # GET_SOURCE_NAME
  [void][DC2]::DisplayConfigGetDeviceInfo($nb)
  $name = $M::PtrToStringUni([IntPtr]([long]$nb+20))
  $g = $M::AllocHGlobal(32); Header $g 32 -3 $low $high $id           # GET_DPI_SCALE (undocumented)
  [void][DC2]::DisplayConfigGetDeviceInfo($g)
  $min = $M::ReadInt32([IntPtr]([long]$g+20)); $cur = $M::ReadInt32([IntPtr]([long]$g+24)); $max = $M::ReadInt32([IntPtr]([long]$g+28))
  $recIdx = -$min
  "$name : minRel=$min curRel=$cur maxRel=$max -> current $($scales[$recIdx + $cur])% (recommended $($scales[$recIdx])%)"
  if ($name -eq $Device -and $SetRel -ne [int]::MinValue) {
    $s = $M::AllocHGlobal(24); Header $s 24 -4 $low $high $id         # SET_DPI_SCALE (undocumented)
    $M::WriteInt32([IntPtr]([long]$s+20), $SetRel)
    $rs = [DC2]::DisplayConfigSetDeviceInfo($s)
    "  set $Device rel=$SetRel -> rc=$rs (0 = ok)"
  }
}
