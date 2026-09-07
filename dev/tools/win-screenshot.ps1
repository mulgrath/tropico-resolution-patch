param([string]$Out, [int]$X = 0, [int]$Y = 0, [int]$W = 2560, [int]$H = 1440)
# Photograph a region of the Windows desktop in PANEL pixels and save it at half
# size. The process declares per-monitor DPI awareness first so CopyFromScreen is
# not virtualized; that is what makes a corner-only frame (FINDINGS 128.3) visible
# in the capture instead of being scaled back into place.
$sig = @'
using System; using System.Runtime.InteropServices;
public static class Dpi { [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr ctx); }
'@
Add-Type -TypeDefinition $sig
[void][Dpi]::SetProcessDpiAwarenessContext([IntPtr](-4))     # PER_MONITOR_AWARE_V2
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap $W, $H
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($X, $Y, 0, 0, $bmp.Size)
$g.Dispose()
$small = New-Object System.Drawing.Bitmap $bmp, ([int]($W/2)), ([int]($H/2))
$small.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$small.Dispose(); $bmp.Dispose()
"saved $Out"
