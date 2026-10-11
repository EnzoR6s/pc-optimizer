#Requires -Version 5.1
<#
    PC Optimizer - installer
    Installs to C:\Program Files\PC Optimizer, builds PC Optimizer.exe (with the
    neon icon), adds Desktop + Start menu shortcuts and an entry in
    Settings > Apps so it can be uninstalled like any other app.
    Run it again any time to update. The app's own updater runs it with -Silent.
#>
param([switch]$Silent, [switch]$Tray)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"")
    if ($Silent) { $a += '-Silent' }
    if ($Tray) { $a += '-Tray' }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a } catch {}
    exit
}

Add-Type -AssemblyName PresentationFramework
# Give the app its own taskbar identity so it shows the PC Optimizer icon, not PowerShell's
$AppUserModelId = 'PCOptimizer.App'
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PCOpt
{
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct PropKey { public Guid fmtid; public uint pid; }

    [StructLayout(LayoutKind.Explicit)]
    public struct PropVar
    {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(8)] public IntPtr p;
        [FieldOffset(16)] public IntPtr pad;
    }

    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPropStore
    {
        [PreserveSig] int GetCount(out uint c);
        [PreserveSig] int GetAt(uint i, out PropKey k);
        [PreserveSig] int GetValue(ref PropKey k, out PropVar v);
        [PreserveSig] int SetValue(ref PropKey k, ref PropVar v);
        [PreserveSig] int Commit();
    }

    public static class AppId
    {
        static readonly Guid Fmt = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
        static readonly Guid IidStore = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99");

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SetCurrentProcessExplicitAppUserModelID(string id);
        [DllImport("shell32.dll")]
        static extern int SHGetPropertyStoreForWindow(IntPtr hwnd, ref Guid riid, out IPropStore store);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHGetPropertyStoreFromParsingName(string path, IntPtr bc, int flags, ref Guid riid, out IPropStore store);

        static void Set(IPropStore s, uint pid, string val)
        {
            PropKey k = new PropKey(); k.fmtid = Fmt; k.pid = pid;
            PropVar v = new PropVar(); v.vt = 31; v.p = Marshal.StringToCoTaskMemUni(val);
            try { s.SetValue(ref k, ref v); } finally { Marshal.FreeCoTaskMem(v.p); }
        }

        public static void ForProcess(string id) { SetCurrentProcessExplicitAppUserModelID(id); }

        public static void ForWindow(IntPtr hwnd, string id, string exe, string icon, string name)
        {
            Guid g = IidStore; IPropStore s;
            if (SHGetPropertyStoreForWindow(hwnd, ref g, out s) != 0 || s == null) return;
            try
            {
                Set(s, 5, id);
                if (!String.IsNullOrEmpty(exe))
                {
                    Set(s, 2, "\"" + exe + "\"");
                    Set(s, 4, name);
                    Set(s, 3, icon);
                }
                s.Commit();
            }
            finally { Marshal.ReleaseComObject(s); }
        }

        public static void ForShortcut(string lnk, string id)
        {
            Guid g = IidStore; IPropStore s;
            if (SHGetPropertyStoreFromParsingName(lnk, IntPtr.Zero, 2, ref g, out s) != 0 || s == null) return;
            try { Set(s, 5, id); s.Commit(); }
            finally { Marshal.ReleaseComObject(s); }
        }
    }
}
'@ -ErrorAction Stop
    [PCOpt.AppId]::ForProcess($AppUserModelId)
} catch {}

function Say([string]$text, [string]$icon = 'Information') { [void][System.Windows.MessageBox]::Show($text, 'PC Optimizer Setup', 'OK', $icon) }

$version = '4.3.0'
$src     = $PSScriptRoot
$dest    = Join-Path $env:ProgramFiles 'PC Optimizer'
$exe     = Join-Path $dest 'PC Optimizer.exe'
$ico     = Join-Path $dest 'PC_Optimizer.ico'
$files   = 'PC_Optimizer.ps1', 'PC_Optimizer.ico', 'Uninstall.ps1'

foreach ($f in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $src $f))) {
        Say "Can't find $f.`n`nUnzip the whole PC Optimizer folder first, then run Install PC Optimizer.bat again." 'Error'
        exit 1
    }
}

try {
    # 1. Close a running copy so files can be replaced
    Get-Process -Name 'PC Optimizer' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'PC_Optimizer\.ps1' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 600

    # 2. Copy the app into Program Files (only admins can change files there)
    [void](New-Item -ItemType Directory -Path $dest -Force)
    foreach ($f in $files) { Copy-Item -LiteralPath (Join-Path $src $f) -Destination $dest -Force }
    Get-ChildItem -LiteralPath $dest -File | Unblock-File -ErrorAction SilentlyContinue

    # 3. Build PC Optimizer.exe (small launcher with the icon, always runs as admin)
    $manifest = Join-Path $env:TEMP 'pcopt.manifest'
    @'
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="4.0.0.0" name="PCOptimizer.App" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
'@ | Set-Content -LiteralPath $manifest -Encoding UTF8

    $code = @'
using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("PC Optimizer")]
[assembly: AssemblyProduct("PC Optimizer")]
[assembly: AssemblyDescription("PC Optimizer")]
[assembly: AssemblyVersion("4.3.0.0")]
[assembly: AssemblyFileVersion("4.3.0.0")]

namespace PCOptimizer
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            string script = Path.Combine(dir, "PC_Optimizer.ps1");
            if (!File.Exists(script))
            {
                MessageBox.Show("PC_Optimizer.ps1 is missing. Run the installer again.", "PC Optimizer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
            string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            // only simple switches like -StartInTray / -AutoClean are passed through
            string extra = "";
            foreach (string a in args)
            {
                bool simple = a.Length > 1 && a.Length < 32 && a[0] == '-';
                for (int i = 1; simple && i < a.Length; i++) { if (!char.IsLetter(a[i])) simple = false; }
                if (simple) extra += " " + a;
            }
            ProcessStartInfo psi = new ProcessStartInfo(ps, "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"" + script + "\"" + extra);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = dir;
            try { Process.Start(psi); }
            catch (Exception ex)
            {
                MessageBox.Show("Couldn't start PC Optimizer:\n\n" + ex.Message, "PC Optimizer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
            return 0;
        }
    }
}
'@
    $built = $false; $buildErr = ''
    try {
        if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
        $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
        $cp = New-Object System.CodeDom.Compiler.CompilerParameters
        $cp.GenerateExecutable = $true
        $cp.GenerateInMemory = $false
        $cp.OutputAssembly = $exe
        $cp.IncludeDebugInformation = $false
        [void]$cp.ReferencedAssemblies.Add('System.dll')
        [void]$cp.ReferencedAssemblies.Add('System.Windows.Forms.dll')
        $cp.CompilerOptions = "/target:winexe /optimize+ /win32icon:`"$ico`" /win32manifest:`"$manifest`""
        $res = $prov.CompileAssemblyFromSource($cp, $code)
        if ($res.Errors.HasErrors) { $buildErr = ($res.Errors | Where-Object { -not $_.IsWarning } | ForEach-Object { $_.ErrorText }) -join '; ' }
        $built = Test-Path -LiteralPath $exe
    } catch { $buildErr = $_.Exception.Message }
    Remove-Item -LiteralPath $manifest -Force -ErrorAction SilentlyContinue

    # 4. Shortcuts (Desktop + Start menu)
    $ws = New-Object -ComObject WScript.Shell
    $links = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PC Optimizer.lnk'),
        (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'PC Optimizer.lnk')
    )
    foreach ($lnk in $links) {
        if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force }
        $sc = $ws.CreateShortcut($lnk)
        if ($built) {
            $sc.TargetPath = $exe
            $sc.IconLocation = "$exe,0"
        } else {
            $sc.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$dest\PC_Optimizer.ps1`""
            $sc.IconLocation = "$ico,0"
            $sc.WindowStyle = 7
        }
        $sc.WorkingDirectory = $dest
        $sc.Description = 'PC Optimizer'
        $sc.Save()
        if (-not $built) { $b = [IO.File]::ReadAllBytes($lnk); $b[0x15] = $b[0x15] -bor 0x20; [IO.File]::WriteAllBytes($lnk, $b) }
        # same taskbar ID as the app window, so the taskbar uses this icon
        try { [PCOpt.AppId]::ForShortcut($lnk, $AppUserModelId) } catch {}
    }

    # 5. Settings > Apps entry (so it uninstalls like a normal app)
    $uk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCOptimizer'
    [void](New-Item -Path $uk -Force)
    $sizeKb = [int](((Get-ChildItem -LiteralPath $dest -File | Measure-Object Length -Sum).Sum) / 1KB)
    $displayIcon = "$ico"; if ($built) { $displayIcon = "$exe,0" }
    $vals = @{
        DisplayName     = 'PC Optimizer'
        DisplayVersion  = $version
        Publisher       = 'PC Optimizer'
        DisplayIcon     = $displayIcon
        InstallLocation = $dest
        UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest\Uninstall.ps1`""
        InstallDate     = (Get-Date -Format 'yyyyMMdd')
    }
    foreach ($k in $vals.Keys) { New-ItemProperty -Path $uk -Name $k -Value $vals[$k] -PropertyType String -Force | Out-Null }
    foreach ($k in 'NoModify', 'NoRepair') { New-ItemProperty -Path $uk -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }
    New-ItemProperty -Path $uk -Name 'EstimatedSize' -Value $sizeKb -PropertyType DWord -Force | Out-Null

    # 6. Old portable-version leftovers
    Remove-Item -Path 'HKCU:\Software\PCOptimizerApp' -Recurse -Force -ErrorAction SilentlyContinue

    # 7. Scheduled tasks (start with Windows / weekly clean) keep pointing at the right launcher
    try {
        foreach ($t in @(Get-ScheduledTask -TaskPath '\PC Optimizer\' -ErrorAction SilentlyContinue)) {
            $arg = [string]$t.Actions[0].Arguments
            $sw = ''; if ($arg -match '-StartInTray') { $sw = '-StartInTray' } elseif ($arg -match '-AutoClean') { $sw = '-AutoClean' }
            if ($built -and $sw) { Set-ScheduledTask -TaskPath '\PC Optimizer\' -TaskName $t.TaskName -Action (New-ScheduledTaskAction -Execute $exe -Argument $sw -WorkingDirectory $dest) | Out-Null }
        }
    } catch {}

    $msg = "PC Optimizer $version is installed.`n`nOpen it from the Desktop icon or the Start menu."
    if (-not $built) { $msg += "`n`n(The .exe couldn't be built, so the shortcuts start it directly instead. It works the same.`nReason: $buildErr)" }
    if (-not $Silent) { Say $msg }

    if ($built) { if ($Tray) { Start-Process -FilePath $exe -ArgumentList '-StartInTray' } else { Start-Process -FilePath $exe } } else { Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$dest\PC_Optimizer.ps1`"") }
} catch {
    Say "Install failed:`n`n$($_.Exception.Message)" 'Error'
    exit 1
}
