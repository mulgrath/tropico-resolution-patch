param([string]$Out, [int]$X = 0, [int]$Y = 0, [int]$W = 2560, [int]$H = 1440, [switch]$Full)
# Photograph a region of the Windows desktop in PANEL pixels and save it at half
# size, or at 1:1 with -Full. Half size is enough for the shape of a frame (whole,
# or a corner); a glyph can only be judged at 1:1, since a pixel-doubled font
# halved is exactly its 1080p bitmap again (FINDINGS 131). The process declares
# per-monitor DPI awareness first so CopyFromScreen is not virtualized; that is
# what makes a corner-only frame (FINDINGS 128.3) visible in the capture instead
# of being scaled back into place.
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
if ($Full) {
  $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
} else {
  $small = New-Object System.Drawing.Bitmap $bmp, ([int]($W/2)), ([int]($H/2))
  $small.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
  $small.Dispose()
}
$bmp.Dispose()
"saved $Out"
