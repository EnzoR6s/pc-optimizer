#Requires -Version 5.1
<#
    PC OPTIMIZER  (app version)
    Installed by Setup.ps1 into Program Files and started by "PC Optimizer.exe".
    Every change is written to Logs\changes.log in the app folder. That folder is
    locked to your Windows account (plus Administrators/SYSTEM) and every line is
    encrypted with Windows DPAPI, so only your account can read it - in the app.
#>
param(
    [switch]$StartInTray,   # used by "Start with Windows"
    [switch]$AutoClean      # used by the weekly auto-clean task (no window)
)

$AppVersion = '4.2.0'

# ---------------------------------------------------------------
#  Admin + STA check (relaunch if needed)
# ---------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSta   = [Threading.Thread]::CurrentThread.ApartmentState -eq 'STA'
if (-not $isAdmin -or -not $isSta) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"")
    if ($StartInTray) { $argList += '-StartInTray' }
    if ($AutoClean) { $argList += '-AutoClean' }
    try {
        if (-not $isAdmin) { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList }
        else { Start-Process -FilePath 'powershell.exe' -ArgumentList $argList }
    } catch {}
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# Hide the console window behind the app
try {
    Add-Type -Name Win -Namespace Native -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);'
    [void][Native.Win]::ShowWindow([Native.Win]::GetConsoleWindow(), 0)
} catch {}

Add-Type -AssemblyName System.Security

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

# ---------------------------------------------------------------
#  Secure log: <app folder>\Logs, locked down + encrypted
# ---------------------------------------------------------------
$desktop    = [Environment]::GetFolderPath('Desktop')
$logDir     = Join-Path $PSScriptRoot 'Logs'
$logFile    = Join-Path $logDir 'changes.log'
$crashFile  = Join-Path $logDir 'crash.txt'
$logEntropy = [Text.Encoding]::UTF8.GetBytes('PCOptimizer-changelog-v1')

function Protect-LogDir {
    if (-not (Test-Path -LiteralPath $logDir)) { [void](New-Item -ItemType Directory -Path $logDir -Force) }
    # Only you, Administrators and SYSTEM. No inherited access, so other users get nothing.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($sid in @($me, 'S-1-5-18', 'S-1-5-32-544')) {
        $id = New-Object System.Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inh, $prop, 'Allow')))
    }
    Set-Acl -LiteralPath $logDir -AclObject $acl
    try { (Get-Item -LiteralPath $logDir -Force).Attributes = 'Directory, Hidden' } catch {}
}
try { Protect-LogDir } catch {}

function Write-SecureLog([string]$m) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    $enc = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($line), $logEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser))
    for ($i = 0; $i -lt 5; $i++) { try { [IO.File]::AppendAllText($logFile, $enc + "`r`n"); break } catch { Start-Sleep -Milliseconds 40 } }
}

function Read-SecureLog {
    if (-not (Test-Path -LiteralPath $logFile)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in [IO.File]::ReadAllLines($logFile)) {
        if (-not $l.Trim()) { continue }
        try { $out.Add([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($l), $logEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser))) }
        catch { $out.Add('[locked line - written by a different Windows account]') }
    }
    return $out.ToArray()
}

trap {
    try { ("[{0}]`r`n{1}`r`n{2}`r`n" -f (Get-Date), ($_ | Out-String), $_.ScriptStackTrace) | Out-File -FilePath $crashFile -Append } catch {}
    try { [void][System.Windows.MessageBox]::Show("PC Optimizer crashed:`n`n$($_.Exception.Message)`n`nDetails were saved to crash.txt in the app's Logs folder.", 'PC Optimizer', 'OK', 'Error') } catch {}
    exit 1
}

# Settings file (in Program Files, so only admins can change it)
$cfgFile = Join-Path $PSScriptRoot 'config.json'
function Load-Config {
    $d = [pscustomobject]@{ UpdateRepo = ''; AutoCheckUpdates = $true; CloseToTray = $true; CleanDay = 'Sunday'; CleanTime = '03:00'; LastPreset = '' }
    if (Test-Path -LiteralPath $cfgFile) {
        try {
            $j = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
            foreach ($p in $d.PSObject.Properties.Name) { if ($null -ne $j.$p) { $d.$p = $j.$p } }
        } catch {}
    }
    return $d
}
function Save-Config { try { $script:cfg | ConvertTo-Json | Set-Content -LiteralPath $cfgFile -Encoding UTF8 } catch {} }
$script:cfg = Load-Config

# One copy at a time (a second launch just brings the first one to the front)
$script:ShowEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::AutoReset, 'Global\PCOptimizerShow')
if (-not $AutoClean) {
    $script:AppMutex = New-Object System.Threading.Mutex($false, 'Global\PCOptimizerApp')
    $gotMutex = $false
    try { $gotMutex = $script:AppMutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $gotMutex = $true }
    if (-not $gotMutex) {
        if (-not $StartInTray) { [void]$script:ShowEvent.Set() }
        exit
    }
}

# ---------------------------------------------------------------
#  Shared state between the window and background workers
# ---------------------------------------------------------------
$sync = [hashtable]::Synchronized(@{})
$sync.Running      = $true
$sync.Busy         = $false
$sync.Current      = ''
$sync.TaskName     = ''
$sync.RpDone       = $false
$sync.RpSkip       = $false
$sync.AskContinue  = $null
$sync.ForceRefresh = $false
$sync.PingSeq      = 0
$sync.Ping         = $null
$sync.Results      = [hashtable]::Synchronized(@{})
$queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'

# ---------------------------------------------------------------
#  UI layout (XAML)
# ---------------------------------------------------------------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PC Optimizer" Width="1340" Height="880" MinWidth="1120" MinHeight="740"
        WindowStyle="None" AllowsTransparency="True" Background="Transparent"
        ResizeMode="CanResizeWithGrip" WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" Foreground="#ECEEFB">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#171B30"/>
    <SolidColorBrush x:Key="Side" Color="#1C2140"/>
    <SolidColorBrush x:Key="Card" Color="#232949"/>
    <SolidColorBrush x:Key="CardHi" Color="#2C335A"/>
    <SolidColorBrush x:Key="Muted" Color="#8B91B7"/>
    <LinearGradientBrush x:Key="Accent" StartPoint="0,0" EndPoint="1,1">
      <GradientStop Color="#8C7BFF" Offset="0"/>
      <GradientStop Color="#FF4F9A" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="Neon" StartPoint="0,0" EndPoint="1,0">
      <GradientStop Color="#33E6FF" Offset="0"/>
      <GradientStop Color="#8C7BFF" Offset="0.5"/>
      <GradientStop Color="#FF4F9A" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="IconGrad" StartPoint="0,0" EndPoint="1,1">
      <GradientStop Color="#B79BFF" Offset="0"/>
      <GradientStop Color="#FF6FA8" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="ArcA" StartPoint="0,1" EndPoint="1,0">
      <GradientStop Color="#33E6FF" Offset="0"/>
      <GradientStop Color="#8C7BFF" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="ArcB" StartPoint="0,1" EndPoint="1,0">
      <GradientStop Color="#8C7BFF" Offset="0"/>
      <GradientStop Color="#FF4F9A" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="ChartFill" StartPoint="0,0" EndPoint="0,1">
      <GradientStop Color="#998C7BFF" Offset="0"/>
      <GradientStop Color="#008C7BFF" Offset="1"/>
    </LinearGradientBrush>
    <FontFamily x:Key="Icons">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>

    <Style x:Key="CardStyle" TargetType="Border">
      <Setter Property="Background" Value="{StaticResource Card}"/>
      <Setter Property="CornerRadius" Value="18"/>
      <Setter Property="Padding" Value="22"/>
      <Setter Property="Margin" Value="8"/>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Ico" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource Icons}"/>
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Foreground" Value="{StaticResource IconGrad}"/>
    </Style>

    <Style x:Key="Nav" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="Margin" Value="0,4"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="nav"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="b" CornerRadius="12" Padding="14,10" Background="Transparent">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="{StaticResource Icons}" FontSize="16" VerticalAlignment="Center" Foreground="{TemplateBinding Foreground}"/>
                <ContentPresenter Margin="14,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="{StaticResource CardHi}"/>
                <Setter Property="Foreground" Value="#ECEEFB"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="b" Property="Background" Value="{StaticResource Accent}"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Seg" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#C9CCE6"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Margin" Value="4"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="plan"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="b" CornerRadius="12" Padding="10,11" Background="{StaticResource CardHi}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#39416E"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="b" Property="Background" Value="{StaticResource Accent}"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Tile" TargetType="Button">
      <Setter Property="Foreground" Value="#ECEEFB"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Margin" Value="6"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" CornerRadius="16" Background="{StaticResource CardHi}" Padding="8">
              <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock x:Name="ic" Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="{StaticResource Icons}" FontSize="28" HorizontalAlignment="Center" Foreground="{StaticResource IconGrad}"/>
                <ContentPresenter Margin="0,10,0,0" HorizontalAlignment="Center"/>
              </StackPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="{StaticResource Accent}"/>
                <Setter TargetName="ic" Property="Foreground" Value="White"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="b" Property="Opacity" Value="0.8"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Pill" TargetType="Button">
      <Setter Property="Foreground" Value="#ECEEFB"/>
      <Setter Property="Background" Value="{StaticResource CardHi}"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Margin" Value="0,0,8,8"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" CornerRadius="10" Background="{TemplateBinding Background}" Padding="14,8">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Opacity" Value="0.8"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="b" Property="Opacity" Value="0.6"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PillAccent" TargetType="Button" BasedOn="{StaticResource Pill}">
      <Setter Property="Background" Value="{StaticResource Accent}"/>
      <Setter Property="Foreground" Value="White"/>
    </Style>

    <Style x:Key="WinBtn" TargetType="Button">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Width="38" Height="32" CornerRadius="8" Background="Transparent">
              <TextBlock Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="{StaticResource Icons}" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="{TemplateBinding Foreground}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="{StaticResource CardHi}"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Link" TargetType="Button">
      <Setter Property="Foreground" Value="#FF6FA8"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <ContentPresenter/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Thin" TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/>
      <Setter Property="Maximum" Value="100"/>
      <Setter Property="Background" Value="{StaticResource CardHi}"/>
      <Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" CornerRadius="3" Background="{TemplateBinding Background}"/>
              <Border x:Name="PART_Indicator" CornerRadius="3" Background="{TemplateBinding Foreground}" HorizontalAlignment="Left"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Chk" TargetType="CheckBox">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Border x:Name="box" Width="22" Height="22" CornerRadius="6" Background="#1C2140" BorderBrush="#5A6190" BorderThickness="1.5">
              <TextBlock x:Name="mark" Text="&#xE73E;" FontFamily="{StaticResource Icons}" FontSize="12" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="box" Property="Background" Value="{StaticResource Accent}"/>
                <Setter TargetName="box" Property="BorderThickness" Value="0"/>
                <Setter TargetName="mark" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="8"/>
      <Setter Property="MinWidth" Value="8"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Track x:Name="PART_Track" IsDirectionReversed="True" Orientation="{TemplateBinding Orientation}">
              <Track.Thumb>
                <Thumb>
                  <Thumb.Template>
                    <ControlTemplate TargetType="Thumb">
                      <Border CornerRadius="4" Background="#3A4170"/>
                    </ControlTemplate>
                  </Thumb.Template>
                </Thumb>
              </Track.Thumb>
            </Track>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <DataTemplate x:Key="RowTpl">
      <DockPanel Margin="0,5">
        <TextBlock DockPanel.Dock="Right" Text="{Binding Detail}" Foreground="#8B91B7" FontSize="12" Margin="12,0,0,0" VerticalAlignment="Center"/>
        <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
      </DockPanel>
    </DataTemplate>
    <DataTemplate x:Key="BarTpl">
      <StackPanel Margin="0,6">
        <DockPanel>
          <TextBlock DockPanel.Dock="Right" Text="{Binding Label}" Foreground="#8B91B7" FontSize="12" Margin="12,0,0,0"/>
          <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
        </DockPanel>
        <ProgressBar Style="{StaticResource Thin}" Value="{Binding Pct, Mode=OneWay}" Margin="0,6,0,0"/>
      </StackPanel>
    </DataTemplate>
    <!-- checkbox row (driver updates, app updates) -->
    <DataTemplate x:Key="CheckTpl">
      <Border Background="#2C335A" CornerRadius="12" Padding="14,10" Margin="0,0,0,8">
        <DockPanel>
          <CheckBox DockPanel.Dock="Left" Style="{StaticResource Chk}" IsChecked="True" Tag="{Binding Id}" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock DockPanel.Dock="Right" Text="{Binding Detail}" Foreground="#8B91B7" FontSize="12" VerticalAlignment="Center" Margin="12,0,0,0"/>
          <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
        </DockPanel>
      </Border>
    </DataTemplate>
    <!-- process row with End button -->
    <DataTemplate x:Key="ProcTpl">
      <DockPanel Margin="0,5">
        <Button DockPanel.Dock="Right" Style="{StaticResource Pill}" Margin="12,0,0,0" Padding="0" Content="End" Tag="{Binding Name}" VerticalAlignment="Center"/>
        <StackPanel VerticalAlignment="Center">
          <DockPanel>
            <TextBlock DockPanel.Dock="Right" Text="{Binding Label}" Foreground="#8B91B7" FontSize="12" Margin="12,0,0,0"/>
            <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
          </DockPanel>
          <ProgressBar Style="{StaticResource Thin}" Value="{Binding Pct, Mode=OneWay}" Margin="0,6,0,0"/>
        </StackPanel>
      </DockPanel>
    </DataTemplate>
    <!-- folder/file row with Open button -->
    <DataTemplate x:Key="OpenTpl">
      <DockPanel Margin="0,5">
        <Button DockPanel.Dock="Right" Style="{StaticResource Pill}" Margin="12,0,0,0" Content="Open" Tag="{Binding Path}" VerticalAlignment="Center"/>
        <StackPanel VerticalAlignment="Center">
          <DockPanel>
            <TextBlock DockPanel.Dock="Right" Text="{Binding Label}" Foreground="#8B91B7" FontSize="12" Margin="12,0,0,0"/>
            <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
          </DockPanel>
          <ProgressBar Style="{StaticResource Thin}" Value="{Binding Pct, Mode=OneWay}" Margin="0,6,0,0"/>
        </StackPanel>
      </DockPanel>
    </DataTemplate>
    <!-- network device row -->
    <DataTemplate x:Key="DevTpl">
      <Border Background="#2C335A" CornerRadius="12" Padding="14,9" Margin="0,0,0,8">
        <DockPanel>
          <Border DockPanel.Dock="Right" Background="{Binding BadgeBg}" CornerRadius="8" Padding="8,3" VerticalAlignment="Center" Margin="10,0,0,0">
            <TextBlock Text="{Binding Badge}" FontSize="11" Foreground="White"/>
          </Border>
          <StackPanel>
            <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
            <TextBlock Text="{Binding Sub}" Foreground="#8B91B7" FontSize="12" Margin="0,2,0,0" TextTrimming="CharacterEllipsis"/>
          </StackPanel>
        </DockPanel>
      </Border>
    </DataTemplate>
    <!-- status row with colored dot -->
    <DataTemplate x:Key="StatTpl">
      <DockPanel Margin="0,6">
        <Ellipse DockPanel.Dock="Left" Width="10" Height="10" Fill="{Binding Color}" VerticalAlignment="Center" Margin="0,0,12,0"/>
        <TextBlock DockPanel.Dock="Right" Text="{Binding Detail}" Foreground="#8B91B7" FontSize="12" Margin="12,0,0,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" MaxWidth="420"/>
        <TextBlock Text="{Binding Name}" VerticalAlignment="Center"/>
      </DockPanel>
    </DataTemplate>
    <Style x:Key="Input" TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource CardHi}"/>
      <Setter Property="Foreground" Value="#ECEEFB"/>
      <Setter Property="CaretBrush" Value="#ECEEFB"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="FontSize" Value="13"/>
    </Style>
  </Window.Resources>

  <Grid Margin="16">
    <!-- neon glow behind the window -->
    <Border CornerRadius="22" Background="{StaticResource Bg}">
      <Border.Effect>
        <DropShadowEffect Color="#8C7BFF" BlurRadius="30" ShadowDepth="0" Opacity="0.55"/>
      </Border.Effect>
    </Border>

    <Border CornerRadius="22" Background="{StaticResource Bg}" BorderBrush="{StaticResource Neon}" BorderThickness="1.5" ClipToBounds="True">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="240"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- ================= SIDEBAR ================= -->
        <Border Grid.Column="0" Background="{StaticResource Side}" CornerRadius="21,0,0,21">
          <DockPanel Margin="18,22,18,18">
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="6,0,0,30">
              <Grid Width="42" Height="42">
                <Ellipse Fill="{StaticResource Accent}"/>
                <TextBlock Text="&#xE945;" FontFamily="{StaticResource Icons}" FontSize="20" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Grid>
              <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                <TextBlock Text="PC Optimizer" FontSize="17" FontWeight="SemiBold"/>
                <TextBlock Text="Admin mode" FontSize="12" Foreground="{StaticResource Muted}"/>
              </StackPanel>
            </StackPanel>

            <Border x:Name="UpdBanner" DockPanel.Dock="Bottom" Background="{StaticResource Accent}" CornerRadius="14" Padding="14,10" Margin="0,10,0,0" Visibility="Collapsed">
              <DockPanel>
                <Button x:Name="UpdBannerBtn" DockPanel.Dock="Right" Style="{StaticResource Pill}" Margin="8,0,0,0" Content="Update" Background="#33FFFFFF"/>
                <StackPanel VerticalAlignment="Center">
                  <TextBlock Text="Update ready" FontWeight="SemiBold" Foreground="White" FontSize="13"/>
                  <TextBlock x:Name="UpdBannerText" Text="" Foreground="#E6FFFFFF" FontSize="11"/>
                </StackPanel>
              </DockPanel>
            </Border>

            <Border DockPanel.Dock="Bottom" Background="{StaticResource Card}" CornerRadius="18" Padding="18">
              <StackPanel>
                <TextBlock Text="One-click boost" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock Text="Network + background apps + cleanup + driver check" Style="{StaticResource Lbl}" FontSize="12" Margin="0,6,0,14"/>
                <Button x:Name="RunAllBtn" Style="{StaticResource PillAccent}" Margin="0" Padding="0">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE768;" FontFamily="{StaticResource Icons}" FontSize="12" VerticalAlignment="Center" Foreground="White"/>
                    <TextBlock Text="Run All" Margin="8,0,0,0" FontWeight="SemiBold" Foreground="White"/>
                  </StackPanel>
                </Button>
                <StackPanel Orientation="Horizontal" Margin="0,14,0,0">
                  <Ellipse x:Name="RpDot" Width="8" Height="8" Fill="#5A6190" VerticalAlignment="Center"/>
                  <TextBlock x:Name="RpStatus" Text="No restore point yet" FontSize="12" Foreground="{StaticResource Muted}" Margin="8,0,0,0"/>
                </StackPanel>
              </StackPanel>
            </Border>

            <StackPanel>
              <RadioButton x:Name="NavDash" Style="{StaticResource Nav}" Tag="&#xE80F;" Content="Dashboard" IsChecked="True"/>
              <RadioButton x:Name="NavGame" Style="{StaticResource Nav}" Tag="&#xE7FC;" Content="Gaming"/>
              <RadioButton x:Name="NavNet" Style="{StaticResource Nav}" Tag="&#xE774;" Content="Network"/>
              <RadioButton x:Name="NavSys" Style="{StaticResource Nav}" Tag="&#xE770;" Content="System"/>
              <RadioButton x:Name="NavTools" Style="{StaticResource Nav}" Tag="&#xEC7A;" Content="Tools"/>
              <RadioButton x:Name="NavAct" Style="{StaticResource Nav}" Tag="&#xE81C;" Content="Activity"/>
              <RadioButton x:Name="NavSet" Style="{StaticResource Nav}" Tag="&#xE713;" Content="Settings"/>
            </StackPanel>
          </DockPanel>
        </Border>

        <!-- ================= MAIN ================= -->
        <Grid Grid.Column="1">
          <Grid.RowDefinitions>
            <RowDefinition Height="78"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="56"/>
          </Grid.RowDefinitions>

          <Border x:Name="Header" Grid.Row="0" Background="Transparent" Padding="32,0,14,0">
            <DockPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="0,12,0,0">
                <Button x:Name="MinBtn" Style="{StaticResource WinBtn}" Tag="&#xE921;"/>
                <Button x:Name="CloseBtn" Style="{StaticResource WinBtn}" Tag="&#xE8BB;"/>
              </StackPanel>
              <StackPanel VerticalAlignment="Center">
                <TextBlock x:Name="PageTitle" Text="Dashboard" FontSize="24" FontWeight="SemiBold"/>
                <TextBlock x:Name="PageSub" Text="" FontSize="13" Foreground="{StaticResource Muted}" Margin="0,2,0,0"/>
              </StackPanel>
            </DockPanel>
          </Border>

          <Grid Grid.Row="1">

            <!-- ============ DASHBOARD ============ -->
            <ScrollViewer x:Name="PageDash" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="7*"/>
                  <ColumnDefinition Width="5*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Hello card -->
                <Border Grid.Row="0" Grid.Column="0" Style="{StaticResource CardStyle}" Background="{StaticResource Accent}" Height="232">
                  <Grid>
                    <Grid.RowDefinitions>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <TextBlock x:Name="Hello" Text="Hello!" FontSize="22" FontWeight="SemiBold" Foreground="White"/>
                    <TextBlock Grid.Row="1" Margin="0,6,0,0" Foreground="#E6FFFFFF" FontSize="13" TextWrapping="Wrap" Text="Your PC at a glance. Pick a boost below or hit Run All."/>
                    <UniformGrid Grid.Row="2" Columns="5" VerticalAlignment="Bottom">
                      <StackPanel>
                        <TextBlock Text="&#xE9D9;" FontFamily="{StaticResource Icons}" FontSize="24" Foreground="White"/>
                        <TextBlock x:Name="StCpu" Text="--" FontSize="28" FontWeight="Light" Foreground="White" Margin="0,8,0,0"/>
                        <TextBlock Text="CPU load" FontSize="12" Foreground="#D9FFFFFF"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock Text="&#xE7F4;" FontFamily="{StaticResource Icons}" FontSize="24" Foreground="White"/>
                        <TextBlock x:Name="StRam" Text="--" FontSize="28" FontWeight="Light" Foreground="White" Margin="0,8,0,0"/>
                        <TextBlock Text="RAM in use" FontSize="12" Foreground="#D9FFFFFF"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock Text="&#xE7FC;" FontFamily="{StaticResource Icons}" FontSize="24" Foreground="White"/>
                        <TextBlock x:Name="StGpu" Text="--" FontSize="28" FontWeight="Light" Foreground="White" Margin="0,8,0,0"/>
                        <TextBlock x:Name="StGpuLbl" Text="GPU" FontSize="12" Foreground="#D9FFFFFF"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock Text="&#xEDA2;" FontFamily="{StaticResource Icons}" FontSize="24" Foreground="White"/>
                        <TextBlock x:Name="StDisk" Text="--" FontSize="28" FontWeight="Light" Foreground="White" Margin="0,8,0,0"/>
                        <TextBlock Text="Free on C:" FontSize="12" Foreground="#D9FFFFFF"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock Text="&#xE701;" FontFamily="{StaticResource Icons}" FontSize="24" Foreground="White"/>
                        <TextBlock x:Name="StPing" Text="--" FontSize="28" FontWeight="Light" Foreground="White" Margin="0,8,0,0"/>
                        <TextBlock Text="Ping (1.1.1.1)" FontSize="12" Foreground="#D9FFFFFF"/>
                      </StackPanel>
                    </UniformGrid>
                  </Grid>
                </Border>

                <!-- Gauges -->
                <Border Grid.Row="0" Grid.Column="1" Style="{StaticResource CardStyle}" Height="232" Padding="16,18">
                  <UniformGrid Columns="2">
                    <StackPanel>
                      <TextBlock Text="Memory" Style="{StaticResource CardTitle}" HorizontalAlignment="Center"/>
                      <Grid Width="150" Height="150" Margin="0,6,0,0">
                        <Path x:Name="RamTrack" Stroke="{StaticResource CardHi}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                        <Path x:Name="RamArc" Stroke="{StaticResource ArcA}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                        <Ellipse Width="100" Height="100" Fill="#F4F2FF"/>
                        <TextBlock x:Name="RamPct" Text="--" FontSize="26" FontWeight="Light" Foreground="#2A2F55" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Grid>
                      <TextBlock x:Name="RamSub" Text="" FontSize="12" Foreground="{StaticResource Muted}" HorizontalAlignment="Center"/>
                    </StackPanel>
                    <StackPanel>
                      <TextBlock Text="Disk C:" Style="{StaticResource CardTitle}" HorizontalAlignment="Center"/>
                      <Grid Width="150" Height="150" Margin="0,6,0,0">
                        <Path x:Name="DiskTrack" Stroke="{StaticResource CardHi}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                        <Path x:Name="DiskArc" Stroke="{StaticResource ArcB}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                        <Ellipse Width="100" Height="100" Fill="#F4F2FF"/>
                        <TextBlock x:Name="DiskPct" Text="--" FontSize="26" FontWeight="Light" Foreground="#2A2F55" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Grid>
                      <TextBlock x:Name="DiskSub" Text="" FontSize="12" Foreground="{StaticResource Muted}" HorizontalAlignment="Center"/>
                    </StackPanel>
                  </UniformGrid>
                </Border>

                <!-- Quick action tiles -->
                <Border Grid.Row="1" Grid.Column="0" Style="{StaticResource CardStyle}" Height="282" Padding="16">
                  <DockPanel>
                    <TextBlock DockPanel.Dock="Top" Text="Quick actions" Style="{StaticResource CardTitle}" Margin="6,2,0,8"/>
                    <UniformGrid Rows="2" Columns="4">
                      <Button x:Name="TBoost" Style="{StaticResource Tile}" Tag="&#xE945;" Content="Boost Network"/>
                      <Button x:Name="TKill" Style="{StaticResource Tile}" Tag="&#xE711;" Content="Kill Bloat"/>
                      <Button x:Name="TClean" Style="{StaticResource Tile}" Tag="&#xE74D;" Content="Clean PC"/>
                      <Button x:Name="TRestore" Style="{StaticResource Tile}" Tag="&#xE777;" Content="Restore Point"/>
                      <Button x:Name="TDrivers" Style="{StaticResource Tile}" Tag="&#xE772;" Content="Driver Check"/>
                      <Button x:Name="THealth" Style="{StaticResource Tile}" Tag="&#xE90F;" Content="Health Check"/>
                      <Button x:Name="TReset" Style="{StaticResource Tile}" Tag="&#xE72C;" Content="Reset Network"/>
                      <Button x:Name="TUpdate" Style="{StaticResource Tile}" Tag="&#xE895;" Content="Win Update"/>
                    </UniformGrid>
                  </DockPanel>
                </Border>

                <!-- Live ping chart -->
                <Border Grid.Row="1" Grid.Column="1" Style="{StaticResource CardStyle}" Height="282">
                  <DockPanel>
                    <DockPanel DockPanel.Dock="Top">
                      <TextBlock DockPanel.Dock="Right" Text="last 60 sec" Style="{StaticResource Lbl}" FontSize="12"/>
                      <TextBlock Text="Live ping" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
                      <TextBlock x:Name="PingNow" Text="--" FontSize="34" FontWeight="Light"/>
                      <TextBlock x:Name="PingStats" Text="" Style="{StaticResource Lbl}" FontSize="12" Margin="14,0,0,4" VerticalAlignment="Bottom"/>
                    </StackPanel>
                    <Canvas x:Name="PingCanvas" Margin="0,12,0,0" ClipToBounds="True">
                      <Polygon x:Name="PingFill" Fill="{StaticResource ChartFill}"/>
                      <Polyline x:Name="PingLine" Stroke="#B9A9FF" StrokeThickness="2" StrokeLineJoin="Round"/>
                    </Canvas>
                  </DockPanel>
                </Border>

                <!-- Power plan -->
                <Border Grid.Row="2" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock x:Name="PlanNow" DockPanel.Dock="Right" Text="" Style="{StaticResource Lbl}"/>
                      <TextBlock Text="&#xE7E8;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Power plan" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="Ultimate and High = more speed and more heat. Balanced = Windows default, best on battery." Style="{StaticResource Lbl}" FontSize="12" Margin="0,6,0,10"/>
                    <UniformGrid Columns="3">
                      <RadioButton x:Name="PlanUlt" Style="{StaticResource Seg}" Content="Ultimate"/>
                      <RadioButton x:Name="PlanHigh" Style="{StaticResource Seg}" Content="High Performance"/>
                      <RadioButton x:Name="PlanBal" Style="{StaticResource Seg}" Content="Balanced"/>
                    </UniformGrid>
                  </StackPanel>
                </Border>

                <!-- Connection -->
                <Border Grid.Row="2" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel>
                      <Button x:Name="CnMore" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="Details"/>
                      <TextBlock Text="&#xE839;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Connection" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <Grid Margin="0,12,0,0">
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="80"/>
                        <ColumnDefinition Width="*"/>
                      </Grid.ColumnDefinitions>
                      <Grid.RowDefinitions>
                        <RowDefinition Height="26"/>
                        <RowDefinition Height="26"/>
                      </Grid.RowDefinitions>
                      <TextBlock Text="Adapter" Style="{StaticResource Lbl}"/>
                      <TextBlock x:Name="CnAdapter" Grid.Column="1" Text="..." VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                      <TextBlock Grid.Row="1" Text="DNS" Style="{StaticResource Lbl}"/>
                      <TextBlock x:Name="CnDns" Grid.Row="1" Grid.Column="1" Text="..." VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                    </Grid>
                  </StackPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ GAMING ============ -->
            <ScrollViewer x:Name="PageGame" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- GPU monitor -->
                <Border Grid.Row="0" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock Text="&#xE7FC;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Graphics card" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="GpuName" Text="Detecting..." Style="{StaticResource Lbl}" FontSize="12" Margin="0,4,0,8" TextTrimming="CharacterEllipsis"/>
                    <UniformGrid Columns="2">
                      <StackPanel>
                        <Grid Width="150" Height="150">
                          <Path x:Name="GpuTrack" Stroke="{StaticResource CardHi}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                          <Path x:Name="GpuArc" Stroke="{StaticResource ArcA}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                          <Ellipse Width="100" Height="100" Fill="#F4F2FF"/>
                          <TextBlock x:Name="GpuPct" Text="--" FontSize="26" FontWeight="Light" Foreground="#2A2F55" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Grid>
                        <TextBlock Text="GPU load" FontSize="12" Foreground="{StaticResource Muted}" HorizontalAlignment="Center"/>
                      </StackPanel>
                      <StackPanel>
                        <Grid Width="150" Height="150">
                          <Path x:Name="VramTrack" Stroke="{StaticResource CardHi}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                          <Path x:Name="VramArc" Stroke="{StaticResource ArcB}" StrokeThickness="11" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                          <Ellipse Width="100" Height="100" Fill="#F4F2FF"/>
                          <TextBlock x:Name="VramPct" Text="--" FontSize="26" FontWeight="Light" Foreground="#2A2F55" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Grid>
                        <TextBlock x:Name="VramSub" Text="VRAM" FontSize="12" Foreground="{StaticResource Muted}" HorizontalAlignment="Center"/>
                      </StackPanel>
                    </UniformGrid>
                    <UniformGrid Columns="4" Margin="0,16,0,0">
                      <StackPanel>
                        <TextBlock x:Name="GpuTemp" Text="--" FontSize="22" FontWeight="Light"/>
                        <TextBlock Text="GPU temp" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="GpuClock" Text="--" FontSize="22" FontWeight="Light"/>
                        <TextBlock Text="Core clock" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="GpuPower" Text="--" FontSize="22" FontWeight="Light"/>
                        <TextBlock Text="Power draw" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="CpuTemp" Text="--" FontSize="22" FontWeight="Light"/>
                        <TextBlock Text="CPU temp" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </UniformGrid>
                    <TextBlock x:Name="GpuMonNote" Text="" Style="{StaticResource Lbl}" FontSize="11" Margin="0,10,0,0"/>
                  </StackPanel>
                </Border>

                <!-- Gaming presets -->
                <Border Grid.Row="0" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock Text="&#xE945;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Gaming presets" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="GpVendor" Text="Detecting your graphics card..." Style="{StaticResource Lbl}" FontSize="12" Margin="0,4,0,12"/>
                    <UniformGrid Columns="3">
                      <RadioButton x:Name="GpPerf" Style="{StaticResource Seg}" GroupName="gp" Content="Performance"/>
                      <RadioButton x:Name="GpBal" Style="{StaticResource Seg}" GroupName="gp" Content="Balanced"/>
                      <RadioButton x:Name="GpQual" Style="{StaticResource Seg}" GroupName="gp" Content="Quality"/>
                    </UniformGrid>
                    <Border Background="{StaticResource CardHi}" CornerRadius="12" Padding="14,12" Margin="4,12,4,12">
                      <TextBlock x:Name="GpDesc" TextWrapping="Wrap" FontSize="12.5" LineHeight="20" Text="Pick a preset. It sets your graphics driver and Windows power plan for that style of play. Your original GPU settings are saved first so you can put them back."/>
                    </Border>
                    <WrapPanel Margin="4,0,0,0">
                      <Button x:Name="GpOpenPanel" Style="{StaticResource Pill}" Content="Open graphics control panel"/>
                      <Button x:Name="GpRestore" Style="{StaticResource Pill}" Content="Restore my original GPU settings"/>
                    </WrapPanel>
                  </StackPanel>
                </Border>

                <!-- AMD checklist (only shown for AMD cards) -->
                <Border x:Name="AmdCard" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}" Visibility="Collapsed">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE73E;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock x:Name="AmdTitle" Text="AMD Software checklist" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="AMD doesn't let other apps change these safely, so set them yourself in AMD Software > Gaming > Graphics. It takes about a minute." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <ItemsControl x:Name="AmdList" ItemTemplate="{StaticResource RowTpl}"/>
                  </StackPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ NETWORK ============ -->
            <ScrollViewer x:Name="PageNet" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Adapter info -->
                <Border Grid.Row="0" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,10">
                      <Button x:Name="NetRefresh" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="Refresh"/>
                      <TextBlock Text="&#xE839;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Adapter" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <Grid>
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="100"/>
                        <ColumnDefinition Width="*"/>
                      </Grid.ColumnDefinitions>
                      <Grid.RowDefinitions>
                        <RowDefinition Height="28"/><RowDefinition Height="28"/><RowDefinition Height="28"/><RowDefinition Height="28"/>
                        <RowDefinition Height="28"/><RowDefinition Height="28"/><RowDefinition Height="28"/>
                      </Grid.RowDefinitions>
                      <TextBlock Grid.Row="0" Text="Name" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="1" Text="Device" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="2" Text="Link speed" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="3" Text="IPv4" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="4" Text="Gateway" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="5" Text="DNS" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="6" Text="MAC" Style="{StaticResource Lbl}"/>
                      <TextBlock x:Name="NiAdapter" Grid.Row="0" Grid.Column="1" Text="Loading..." VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                      <TextBlock x:Name="NiDevice" Grid.Row="1" Grid.Column="1" Text="" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                      <TextBlock x:Name="NiSpeed" Grid.Row="2" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                      <TextBlock x:Name="NiIp" Grid.Row="3" Grid.Column="1" Text="" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                      <TextBlock x:Name="NiGw" Grid.Row="4" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                      <TextBlock x:Name="NiDns" Grid.Row="5" Grid.Column="1" Text="" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                      <TextBlock x:Name="NiMac" Grid.Row="6" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                    </Grid>
                  </StackPanel>
                </Border>

                <!-- Wi-Fi -->
                <Border Grid.Row="0" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,10">
                      <TextBlock Text="&#xE701;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Wi-Fi" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="WiSsid" Text="Loading..." FontSize="26" FontWeight="Light" TextTrimming="CharacterEllipsis"/>
                    <DockPanel Margin="0,14,0,0">
                      <TextBlock x:Name="WiSignal" DockPanel.Dock="Right" Text="" Style="{StaticResource Lbl}" Margin="12,0,0,0"/>
                      <TextBlock Text="Signal" Style="{StaticResource Lbl}" Width="100"/>
                      <ProgressBar x:Name="WiBar" Style="{StaticResource Thin}" Value="0" VerticalAlignment="Center"/>
                    </DockPanel>
                    <Grid Margin="0,10,0,0">
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="100"/>
                        <ColumnDefinition Width="*"/>
                      </Grid.ColumnDefinitions>
                      <Grid.RowDefinitions>
                        <RowDefinition Height="28"/><RowDefinition Height="28"/><RowDefinition Height="28"/><RowDefinition Height="28"/>
                      </Grid.RowDefinitions>
                      <TextBlock Grid.Row="0" Text="Radio" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="1" Text="Band" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="2" Text="Channel" Style="{StaticResource Lbl}"/>
                      <TextBlock Grid.Row="3" Text="Link rate" Style="{StaticResource Lbl}"/>
                      <TextBlock x:Name="WiRadio" Grid.Row="0" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                      <TextBlock x:Name="WiBand" Grid.Row="1" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                      <TextBlock x:Name="WiChannel" Grid.Row="2" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                      <TextBlock x:Name="WiRate" Grid.Row="3" Grid.Column="1" Text="" VerticalAlignment="Center"/>
                    </Grid>
                  </StackPanel>
                </Border>

                <!-- DNS switcher -->
                <Border Grid.Row="1" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE774;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="DNS switcher" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="Cloudflare is usually fastest. Quad9 also blocks known malware sites." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,12"/>
                    <WrapPanel>
                      <Button x:Name="DnsCf" Style="{StaticResource Pill}" Content="Cloudflare"/>
                      <Button x:Name="DnsGg" Style="{StaticResource Pill}" Content="Google"/>
                      <Button x:Name="DnsQ9" Style="{StaticResource Pill}" Content="Quad9"/>
                      <Button x:Name="DnsAuto" Style="{StaticResource Pill}" Content="Automatic"/>
                    </WrapPanel>
                    <DockPanel Margin="0,10,0,0">
                      <Button x:Name="DnsTestBtn" DockPanel.Dock="Left" Style="{StaticResource PillAccent}" Content="Run speed test"/>
                      <TextBlock x:Name="DnsNote" Text="" Style="{StaticResource Lbl}" FontSize="12" Margin="4,0,0,8"/>
                    </DockPanel>
                    <ItemsControl x:Name="DnsList" ItemTemplate="{StaticResource BarTpl}"/>
                  </StackPanel>
                </Border>

                <!-- Ping check -->
                <Border Grid.Row="1" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE916;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Where is the lag?" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="Pings your router and the internet 10 times each so you can tell a Wi-Fi problem from an ISP problem." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,14"/>
                    <UniformGrid Columns="2">
                      <StackPanel>
                        <TextBlock Text="Router" Style="{StaticResource Lbl}"/>
                        <TextBlock x:Name="PcRouter" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock x:Name="PcRouterLoss" Text="" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock Text="Internet (1.1.1.1)" Style="{StaticResource Lbl}"/>
                        <TextBlock x:Name="PcNet" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock x:Name="PcNetLoss" Text="" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </UniformGrid>
                    <Border Background="{StaticResource CardHi}" CornerRadius="12" Padding="14,10" Margin="0,16,0,12">
                      <TextBlock x:Name="PcVerdict" Text="Run the check to see where your lag comes from." TextWrapping="Wrap" FontSize="13"/>
                    </Border>
                    <Button x:Name="PingRun" Style="{StaticResource PillAccent}" Content="Run ping check" HorizontalAlignment="Left"/>
                  </StackPanel>
                </Border>

                <!-- Speed test -->
                <Border Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,4">
                      <Button x:Name="SpRun" DockPanel.Dock="Right" Style="{StaticResource PillAccent}" Margin="0" Content="Run speed test"/>
                      <TextBlock Text="&#xE916;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Internet speed test" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="SpNote" Text="Measures download, upload and how much your ping jumps while the connection is busy (bufferbloat). Uses Cloudflare's speed test servers, takes about 20 seconds." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,14"/>
                    <UniformGrid Columns="5">
                      <StackPanel>
                        <TextBlock x:Name="SpDown" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock Text="Download (Mbps)" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="SpUp" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock Text="Upload (Mbps)" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="SpIdle" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock Text="Ping, idle (ms)" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="SpLoaded" Text="--" FontSize="30" FontWeight="Light"/>
                        <TextBlock Text="Ping, busy (ms)" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                      <StackPanel>
                        <TextBlock x:Name="SpGrade" Text="--" FontSize="30" FontWeight="SemiBold" Foreground="{StaticResource IconGrad}"/>
                        <TextBlock Text="Bufferbloat grade" Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </UniformGrid>
                  </StackPanel>
                </Border>

                <!-- Network actions -->
                <Border Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                      <Button x:Name="NetReset" Style="{StaticResource Pill}" Content="Undo network tweaks" Margin="0,0,8,0"/>
                      <Button x:Name="NetBoost" Style="{StaticResource PillAccent}" Content="Boost network" Margin="0"/>
                    </StackPanel>
                    <StackPanel VerticalAlignment="Center">
                      <TextBlock Text="Gaming network tweaks" Style="{StaticResource CardTitle}"/>
                      <TextBlock Text="Flushes DNS, tunes TCP, turns off Nagle and network throttling. A restore point is made first." Style="{StaticResource Lbl}" FontSize="12" Margin="0,4,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ SYSTEM ============ -->
            <ScrollViewer x:Name="PageSys" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Startup apps -->
                <Border Grid.Row="0" Grid.Column="0" Style="{StaticResource CardStyle}" Height="380">
                  <DockPanel>
                    <DockPanel DockPanel.Dock="Top" Margin="0,0,0,4">
                      <Button x:Name="StartupRefresh" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="Refresh"/>
                      <TextBlock Text="&#xE7B5;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Startup apps" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock DockPanel.Dock="Top" Text="Apps that launch when Windows boots. Store apps may only show in Settings." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <Button x:Name="StartupOpen" DockPanel.Dock="Bottom" Style="{StaticResource PillAccent}" Content="Turn some off in Settings" HorizontalAlignment="Left" Margin="0,10,0,0"/>
                    <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                      <ItemsControl x:Name="StartupList" ItemTemplate="{StaticResource RowTpl}" Margin="0,0,10,0"/>
                    </ScrollViewer>
                  </DockPanel>
                </Border>

                <!-- Process manager -->
                <Border Grid.Row="0" Grid.Column="1" Style="{StaticResource CardStyle}" Height="380">
                  <DockPanel>
                    <DockPanel DockPanel.Dock="Top" Margin="0,0,0,8">
                      <Button x:Name="PrRefresh" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="Refresh"/>
                      <TextBlock Text="&#xE9D9;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Processes" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
                      <RadioButton x:Name="PrMem" Style="{StaticResource Seg}" GroupName="pr" Content="Memory" Width="110" IsChecked="True" Margin="0,0,6,0"/>
                      <RadioButton x:Name="PrCpu" Style="{StaticResource Seg}" GroupName="pr" Content="CPU" Width="110" Margin="0"/>
                    </StackPanel>
                    <TextBlock x:Name="PrNote" DockPanel.Dock="Top" Text="Grouped by app. End closes every copy of it. Windows system processes are hidden so you can't break anything." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,6"/>
                    <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                      <ItemsControl x:Name="PrList" ItemTemplate="{StaticResource ProcTpl}" Margin="0,0,10,0"/>
                    </ScrollViewer>
                  </DockPanel>
                </Border>

                <!-- Drivers -->
                <Border Grid.Row="1" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE772;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Drivers" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="DrvNote" Text="Run a check to find broken devices and your oldest third-party drivers." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <TextBlock Text="PROBLEM DEVICES" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,4,0,2"/>
                    <ItemsControl x:Name="DrvList" ItemTemplate="{StaticResource RowTpl}"/>
                    <TextBlock Text="OLDEST DRIVERS" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,12,0,2"/>
                    <ItemsControl x:Name="DrvOldList" ItemTemplate="{StaticResource RowTpl}"/>
                    <WrapPanel Margin="0,14,0,0">
                      <Button x:Name="DrvRun" Style="{StaticResource PillAccent}" Content="Check drivers"/>
                      <Button x:Name="DrvUpdates" Style="{StaticResource Pill}" Content="Optional updates"/>
                    </WrapPanel>
                    <TextBlock Text="For GPU drivers use the NVIDIA App or AMD Adrenalin." Style="{StaticResource Lbl}" FontSize="12"/>
                  </StackPanel>
                </Border>

                <!-- Driver updates (online) -->
                <Border Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE896;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Driver updates (online)" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="DuNote" Text="Searches Windows Update for newer drivers for your hardware and keeps only the newest one per device. Untick anything you don't want, then install. A restore point is made first." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,12"/>
                    <ItemsControl x:Name="DuList">
                      <ItemsControl.ItemTemplate>
                        <DataTemplate>
                          <Border Background="#2C335A" CornerRadius="12" Padding="14,10" Margin="0,0,0,8">
                            <DockPanel>
                              <CheckBox DockPanel.Dock="Left" Style="{StaticResource Chk}" IsChecked="True" Tag="{Binding Id}" VerticalAlignment="Center" Margin="0,0,14,0"/>
                              <TextBlock DockPanel.Dock="Right" Text="{Binding Detail}" Foreground="#8B91B7" FontSize="12" VerticalAlignment="Center" Margin="12,0,0,0"/>
                              <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
                            </DockPanel>
                          </Border>
                        </DataTemplate>
                      </ItemsControl.ItemTemplate>
                    </ItemsControl>
                    <WrapPanel Margin="0,6,0,0">
                      <Button x:Name="DuScan" Style="{StaticResource PillAccent}" Content="Search for driver updates"/>
                      <Button x:Name="DuInstall" Style="{StaticResource Pill}" Content="Install selected" IsEnabled="False"/>
                    </WrapPanel>
                    <TextBlock Text="GRAPHICS CARD" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,14,0,6"/>
                    <TextBlock Text="Windows Update often lags behind on GPU drivers. For the newest one, get it straight from the maker." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,8"/>
                    <ItemsControl x:Name="GpuList">
                      <ItemsControl.ItemTemplate>
                        <DataTemplate>
                          <Border Background="#2C335A" CornerRadius="12" Padding="14,10" Margin="0,0,0,8">
                            <DockPanel>
                              <Button DockPanel.Dock="Right" Style="{StaticResource PillAccent}" Margin="12,0,0,0" Content="{Binding Btn}" Tag="{Binding Url}"/>
                              <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
                                <TextBlock Text="{Binding Detail}" Foreground="#8B91B7" FontSize="12" Margin="0,2,0,0"/>
                              </StackPanel>
                            </DockPanel>
                          </Border>
                        </DataTemplate>
                      </ItemsControl.ItemTemplate>
                    </ItemsControl>
                  </StackPanel>
                </Border>

                <!-- Health -->
                <Border Grid.Row="1" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE90F;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Full health check" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="Repairs the Windows image (DISM), fixes corrupted system files (SFC), then scans your drive. Takes 10-20 minutes. You can keep using your PC." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,14"/>
                    <Border Background="{StaticResource CardHi}" CornerRadius="12" Padding="14,10" Margin="0,0,0,14">
                      <TextBlock x:Name="HealthStatus" Text="Not run this session." TextWrapping="Wrap" FontSize="13"/>
                    </Border>
                    <Button x:Name="HealthRun" Style="{StaticResource PillAccent}" Content="Run health check" HorizontalAlignment="Left"/>
                  </StackPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ TOOLS ============ -->
            <ScrollViewer x:Name="PageTools" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- App updates (winget) -->
                <Border Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xE895;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Update your apps" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="WgNote" Text="Finds outdated apps (Chrome, Discord, Steam and anything else winget knows) and updates them quietly." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,12"/>
                    <ScrollViewer MaxHeight="320" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                      <ItemsControl x:Name="WgList" ItemTemplate="{StaticResource CheckTpl}" Margin="0,0,10,0"/>
                    </ScrollViewer>
                    <WrapPanel Margin="0,6,0,0">
                      <Button x:Name="WgCheck" Style="{StaticResource PillAccent}" Content="Check for app updates"/>
                      <Button x:Name="WgUpdate" Style="{StaticResource Pill}" Content="Update selected" IsEnabled="False"/>
                    </WrapPanel>
                  </StackPanel>
                </Border>

                <!-- Disk space -->
                <Border Grid.Row="1" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock Text="&#xEDA2;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="What's eating my drive?" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="DsNote" Text="Pick where to look. Shows the biggest folders inside it and the biggest single files." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <WrapPanel Margin="0,0,0,6">
                      <Button x:Name="DsC" Style="{StaticResource PillAccent}" Content="Whole C: drive"/>
                      <Button x:Name="DsUser" Style="{StaticResource Pill}" Content="My user folder"/>
                      <Button x:Name="DsPick" Style="{StaticResource Pill}" Content="Pick a folder..."/>
                    </WrapPanel>
                    <TextBlock Text="BIGGEST FOLDERS" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,6,0,2"/>
                    <ItemsControl x:Name="DsList" ItemTemplate="{StaticResource OpenTpl}"/>
                    <TextBlock Text="BIGGEST FILES" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,12,0,2"/>
                    <ItemsControl x:Name="DsFiles" ItemTemplate="{StaticResource OpenTpl}"/>
                  </StackPanel>
                </Border>

                <!-- LAN scanner -->
                <Border Grid.Row="1" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <Button x:Name="LanScan" DockPanel.Dock="Right" Style="{StaticResource PillAccent}" Margin="0" Content="Scan network"/>
                      <TextBlock Text="&#xE968;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Devices on my network" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="LanNote" Text="Finds everything on your home network with its IP, MAC address and maker." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <ScrollViewer MaxHeight="520" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                      <ItemsControl x:Name="LanList" ItemTemplate="{StaticResource DevTpl}" Margin="0,0,10,0"/>
                    </ScrollViewer>
                  </StackPanel>
                </Border>

                <!-- Security check -->
                <Border Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock x:Name="SecScore" DockPanel.Dock="Right" Text="" FontSize="22" FontWeight="SemiBold" Foreground="{StaticResource IconGrad}"/>
                      <TextBlock Text="&#xEA18;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Security check" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock x:Name="SecNote" Text="Checks antivirus, firewall, risky settings, open ports and pending Windows updates. Read-only - it doesn't change anything." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,10"/>
                    <Grid>
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="3*"/>
                        <ColumnDefinition Width="2*"/>
                      </Grid.ColumnDefinitions>
                      <ItemsControl x:Name="SecList" ItemTemplate="{StaticResource StatTpl}" Margin="0,0,20,0"/>
                      <StackPanel Grid.Column="1">
                        <TextBlock Text="LISTENING ON YOUR NETWORK" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,6,0,2"/>
                        <ItemsControl x:Name="SecPorts" ItemTemplate="{StaticResource RowTpl}"/>
                      </StackPanel>
                    </Grid>
                    <WrapPanel Margin="0,12,0,0">
                      <Button x:Name="SecRun" Style="{StaticResource PillAccent}" Content="Run security check"/>
                      <Button x:Name="SecScan" Style="{StaticResource Pill}" Content="Defender quick scan"/>
                      <Button x:Name="SecOpen" Style="{StaticResource Pill}" Content="Open Windows Security"/>
                    </WrapPanel>
                  </StackPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ SETTINGS ============ -->
            <ScrollViewer x:Name="PageSet" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <Grid Margin="16,0,16,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- App behaviour -->
                <Border Grid.Row="0" Grid.Column="0" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,14">
                      <TextBlock Text="&#xE713;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="App" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <DockPanel Margin="0,0,0,14">
                      <CheckBox x:Name="SetTray" DockPanel.Dock="Left" Style="{StaticResource Chk}" Margin="0,0,14,0" VerticalAlignment="Top"/>
                      <StackPanel>
                        <TextBlock Text="Close button hides to the tray"/>
                        <TextBlock Text="Keeps it running next to the clock. Right-click the tray icon to quit." Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </DockPanel>
                    <DockPanel Margin="0,0,0,14">
                      <CheckBox x:Name="SetStartup" DockPanel.Dock="Left" Style="{StaticResource Chk}" Margin="0,0,14,0" VerticalAlignment="Top"/>
                      <StackPanel>
                        <TextBlock Text="Start with Windows"/>
                        <TextBlock Text="Opens quietly in the tray when you sign in. No admin prompt." Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </DockPanel>
                    <DockPanel>
                      <CheckBox x:Name="SetAutoUpd" DockPanel.Dock="Left" Style="{StaticResource Chk}" Margin="0,0,14,0" VerticalAlignment="Top"/>
                      <StackPanel>
                        <TextBlock Text="Check for updates when the app opens"/>
                        <TextBlock Text="Only checks. You choose when to install." Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </DockPanel>
                  </StackPanel>
                </Border>

                <!-- Weekly auto-clean -->
                <Border Grid.Row="0" Grid.Column="1" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,14">
                      <TextBlock Text="&#xE74D;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Weekly auto-clean" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <DockPanel Margin="0,0,0,14">
                      <CheckBox x:Name="SetClean" DockPanel.Dock="Left" Style="{StaticResource Chk}" Margin="0,0,14,0" VerticalAlignment="Top"/>
                      <StackPanel>
                        <TextBlock Text="Run Clean PC automatically every week"/>
                        <TextBlock Text="Temp files, update cache, thumbnails and Recycle Bin. Runs in the background while you're signed in; if your PC is off it runs next time." Style="{StaticResource Lbl}" FontSize="12"/>
                      </StackPanel>
                    </DockPanel>
                    <TextBlock Text="DAY" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,0,0,4"/>
                    <UniformGrid x:Name="SetDays" Columns="7">
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Mon" Tag="Monday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Tue" Tag="Tuesday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Wed" Tag="Wednesday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Thu" Tag="Thursday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Fri" Tag="Friday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Sat" Tag="Saturday" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="cday" Content="Sun" Tag="Sunday" Margin="2"/>
                    </UniformGrid>
                    <TextBlock Text="TIME" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,10,0,4"/>
                    <UniformGrid x:Name="SetTimes" Columns="3">
                      <RadioButton Style="{StaticResource Seg}" GroupName="ctime" Content="3 AM" Tag="03:00" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="ctime" Content="Noon" Tag="12:00" Margin="2"/>
                      <RadioButton Style="{StaticResource Seg}" GroupName="ctime" Content="8 PM" Tag="20:00" Margin="2"/>
                    </UniformGrid>
                    <TextBlock x:Name="SetCleanNote" Text="" Style="{StaticResource Lbl}" FontSize="12" Margin="0,10,0,0"/>
                  </StackPanel>
                </Border>

                <!-- Updates -->
                <Border Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Style="{StaticResource CardStyle}">
                  <StackPanel>
                    <DockPanel Margin="0,0,0,6">
                      <TextBlock x:Name="SetVer" DockPanel.Dock="Right" Text="" Style="{StaticResource Lbl}"/>
                      <TextBlock Text="&#xE896;" Style="{StaticResource Ico}" Margin="0,0,10,0"/>
                      <TextBlock Text="Updates" Style="{StaticResource CardTitle}"/>
                    </DockPanel>
                    <TextBlock Text="New versions are pulled from your GitHub repo. Every file is checked against its SHA-256 hash and the code is test-read before anything is replaced. If something goes wrong, your current version stays." Style="{StaticResource Lbl}" FontSize="12" Margin="0,0,0,12"/>
                    <TextBlock Text="GITHUB REPO (owner/name)" FontSize="11" Foreground="{StaticResource Muted}" Margin="0,0,0,4"/>
                    <DockPanel Margin="0,0,0,12">
                      <Button x:Name="SetRepoSave" DockPanel.Dock="Right" Style="{StaticResource Pill}" Margin="8,0,0,0" Content="Save"/>
                      <TextBox x:Name="SetRepo" Style="{StaticResource Input}"/>
                    </DockPanel>
                    <Border Background="{StaticResource CardHi}" CornerRadius="12" Padding="14,10" Margin="0,0,0,12">
                      <TextBlock x:Name="SetUpdStatus" Text="Not checked yet." TextWrapping="Wrap" FontSize="13"/>
                    </Border>
                    <WrapPanel>
                      <Button x:Name="SetUpdCheck" Style="{StaticResource Pill}" Content="Check for updates"/>
                      <Button x:Name="SetUpdNow" Style="{StaticResource PillAccent}" Content="Update now" Visibility="Collapsed"/>
                    </WrapPanel>
                  </StackPanel>
                </Border>
              </Grid>
            </ScrollViewer>

            <!-- ============ ACTIVITY ============ -->
            <Grid x:Name="PageAct" Visibility="Collapsed" Margin="24,0,24,8">
              <Border Background="{StaticResource Card}" CornerRadius="18" Padding="20">
                <DockPanel>
                  <DockPanel DockPanel.Dock="Top" Margin="0,0,0,12">
                    <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
                      <RadioButton x:Name="ActTabLive" Style="{StaticResource Seg}" GroupName="acttab" Content="Live output" Width="130" IsChecked="True" Margin="0,0,6,0"/>
                      <RadioButton x:Name="ActTabLog" Style="{StaticResource Seg}" GroupName="acttab" Content="Change log" Width="130" Margin="0"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                      <TextBlock Text="&#xE72E;" Style="{StaticResource Ico}" FontSize="13" Margin="0,0,6,0"/>
                      <TextBlock x:Name="LogLockNote" Text="Log is encrypted and only readable by your Windows account" Style="{StaticResource Lbl}" FontSize="12"/>
                    </StackPanel>
                  </DockPanel>
                  <WrapPanel DockPanel.Dock="Top" Margin="0,0,0,10">
                    <Button x:Name="ActRp" Style="{StaticResource Pill}" Content="Create restore point"/>
                    <Button x:Name="ActRestore" Style="{StaticResource Pill}" Content="Open System Restore (undo)"/>
                    <Button x:Name="ActShortcut" Style="{StaticResource Pill}" Content="Make desktop shortcut"/>
                    <Button x:Name="ActClear" Style="{StaticResource Pill}" Content="Clear output"/>
                    <Button x:Name="ActLogClear" Style="{StaticResource Pill}" Content="Delete change log" Visibility="Collapsed"/>
                  </WrapPanel>
                  <Grid>
                    <TextBox x:Name="ConsoleBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"
                             Background="#12152A" Foreground="#9FEBFF" BorderThickness="0" Padding="14" FontFamily="Consolas" FontSize="13"/>
                    <TextBox x:Name="LogBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Visibility="Collapsed"
                             Background="#12152A" Foreground="#FFC2DF" BorderThickness="0" Padding="14" FontFamily="Consolas" FontSize="13"/>
                  </Grid>
                </DockPanel>
              </Border>
            </Grid>
          </Grid>

          <!-- Status bar -->
          <Border Grid.Row="2" Margin="24,0,24,14" CornerRadius="12" Background="{StaticResource Card}" Padding="16,0">
            <DockPanel>
              <Button x:Name="StatusLink" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="View activity"/>
              <ProgressBar x:Name="BusyBar" DockPanel.Dock="Left" Width="90" Height="4" Foreground="#FF4F9A" Background="#2C335A" BorderThickness="0" Margin="0,0,14,0" Visibility="Collapsed" VerticalAlignment="Center"/>
              <TextBlock x:Name="StatusText" Text="Ready" VerticalAlignment="Center" Foreground="{StaticResource Muted}" FontSize="13" TextTrimming="CharacterEllipsis" Margin="0,0,12,0"/>
            </DockPanel>
          </Border>
        </Grid>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

[xml]$xml = $xaml
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
foreach ($node in $xml.SelectNodes("//*[@*[local-name()='Name']]")) {
    $n = $node.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    if ($n -cmatch '^[A-Z]' -and $n -notmatch '^PART_') { Set-Variable -Name $n -Value $win.FindName($n) -Scope Script }
}

# ---------------------------------------------------------------
#  Code that runs inside background workers
# ---------------------------------------------------------------
$Prelude = @'
$ProgressPreference = 'SilentlyContinue'
function Log([string]$m) { $q.Enqueue($m) }
Add-Type -AssemblyName System.Security
function Note([string]$m) {
    try {
        $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
        $enc = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($line), $logEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser))
        for ($i = 0; $i -lt 5; $i++) { try { [IO.File]::AppendAllText($logFile, $enc + "`r`n"); break } catch { Start-Sleep -Milliseconds 40 } }
    } catch {}
}
function Done([string]$m) { Log ('[+] ' + $m); Note $m }
function Get-FreeMB { [math]::Floor(([IO.DriveInfo]::new($env:SystemDrive)).AvailableFreeSpace / 1MB) }
function RunNative([string]$exe, [string[]]$argList, [switch]$Quiet) {
    & $exe @argList 2>&1 | ForEach-Object {
        if (-not $Quiet) {
            $s = ([string]$_).Replace([string][char]0, '')
            foreach ($part in ($s -split "`r")) {
                $t = $part.TrimEnd()
                if ($t.Trim() -and $t -notmatch '^\s*(\[=|\[ |Progress:|Verification \d+% complete|Stage \d|\d+ percent completed|[-\\|/]\s*$)' -and $t -notmatch '[\u2580-\u259F]') { Log ('    ' + $t) }
            }
        }
    }
    return $LASTEXITCODE
}
function PingStats([string]$target, [int]$count = 4) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $t = @(); $lost = 0
    for ($i = 0; $i -lt $count; $i++) {
        try { $r = $p.Send($target, 1000); if ($r.Status -eq 'Success') { $t += [int]$r.RoundtripTime } else { $lost++ } } catch { $lost++ }
        Start-Sleep -Milliseconds 200
    }
    $p.Dispose()
    $avg = $null; $min = $null; $max = $null
    if ($t.Count) {
        $m = $t | Measure-Object -Average -Minimum -Maximum
        $avg = [math]::Round($m.Average); $min = $m.Minimum; $max = $m.Maximum
    }
    [pscustomobject]@{ Target = $target; Avg = $avg; Min = $min; Max = $max; Lost = $lost; Sent = $count }
}
function Ensure-RP([switch]$NoAsk) {
    if ($sync.RpDone -or $sync.RpSkip) { return $true }
    Log '[*] Creating a System Restore point first (safety net, ~30 sec)...'
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    try { New-ItemProperty -Path $k -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force | Out-Null } catch {}
    $ok = $false; $err = ''
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description 'PC Optimizer' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        $ok = $true
    } catch { $err = $_.Exception.Message }
    Remove-ItemProperty -Path $k -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
    if ($ok) { $sync.RpDone = $true; Done 'Restore point created'; return $true }
    Log "[X] Couldn't create a restore point: $err"
    Note 'Restore point FAILED'
    if (-not $NoAsk) { $sync.AskContinue = $sync.TaskName }
    return $false
}
'@

$TaskWrapTop    = 'try { Log ""; Log ("=== {0}  [{1}] ===" -f $sync.Current, (Get-Date -Format "HH:mm:ss"))'
$TaskWrapBottom = '} catch { Log ("[X] Error: " + $_.Exception.Message) } finally { Log ("--- {0} finished ---" -f $sync.Current); $sync.Busy = $false }'

$Tasks = @{}

$Tasks.network = @'
if (-not (Ensure-RP)) { return }
Log '[*] Flushing DNS cache and stale connections...'
[void](RunNative 'ipconfig.exe' @('/flushdns') -Quiet)
[void](RunNative 'arp.exe' @('-d', '*') -Quiet)
[void](RunNative 'nbtstat.exe' @('-R') -Quiet)
Log '[*] Applying TCP tweaks...'
foreach ($g in 'autotuninglevel=normal', 'rss=enabled', 'ecncapability=disabled', 'timestamps=disabled') {
    [void](RunNative 'netsh.exe' @('int', 'tcp', 'set', 'global', $g) -Quiet)
}
[void](RunNative 'netsh.exe' @('int', 'tcp', 'set', 'heuristics', 'disabled') -Quiet)
Log '[*] Turning off Nagle on each network adapter...'
$n = 0
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
    New-ItemProperty -Path $_.PSPath -Name 'TcpAckFrequency' -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $_.PSPath -Name 'TCPNoDelay' -Value 1 -PropertyType DWord -Force | Out-Null
    $n++
}
Log "    $n adapter entries updated"
Log '[*] Turning off network throttling...'
$mm = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
[void](RunNative 'reg.exe' @('add', $mm, '/v', 'NetworkThrottlingIndex', '/t', 'REG_DWORD', '/d', '0xffffffff', '/f') -Quiet)
[void](RunNative 'reg.exe' @('add', $mm, '/v', 'SystemResponsiveness', '/t', 'REG_DWORD', '/d', '10', '/f') -Quiet)
Done 'Network tweaks applied (TCP globals, Nagle off, throttling off)'
$p = PingStats '1.1.1.1' 4
if ($null -ne $p.Avg) { Log ('    Ping to 1.1.1.1: avg {0} ms (min {1} / max {2})' -f $p.Avg, $p.Min, $p.Max) } else { Log '    Ping test failed - are you online?' }
'@

$Tasks.kill = @'
$names = 'OneDrive', 'Teams', 'ms-teams', 'YourPhone', 'PhoneExperienceHost', 'GameBar', 'GameBarFTServer', 'Widgets', 'WidgetService', 'CompatTelRunner', 'AdobeUpdateService', 'jusched'
$k = 0
foreach ($nm in $names) {
    $p = Get-Process -Name $nm -ErrorAction SilentlyContinue
    if ($p) { $p | Stop-Process -Force -ErrorAction SilentlyContinue; Log "    killed $nm"; Note "Killed $nm"; $k++ }
}
Done "Closed $k background app(s)"
'@

$Tasks.cleanup = @'
$before = Get-FreeMB
Log '[*] Clearing temp folders...'
foreach ($d in @($env:TEMP, "$env:SystemRoot\Temp")) {
    Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
Log '[*] Clearing Windows Update download cache...'
Stop-Service -Name wuauserv, bits -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath "$env:SystemRoot\SoftwareDistribution\Download" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name bits, wuauserv -ErrorAction SilentlyContinue
Log '[*] Clearing thumbnail cache...'
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
Log '[*] Emptying Recycle Bin...'
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
$freed = [math]::Max(0, (Get-FreeMB) - $before)
Done "Cleanup freed about $freed MB"
'@

$Tasks.drivers = @'
Log '[*] Looking for devices with problems...'
$prob = @()
foreach ($d in (Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })) {
    $nm = $d.Name; if (-not $nm) { $nm = $d.DeviceID }
    $det = "Code $($d.ConfigManagerErrorCode)"; if ($d.ConfigManagerErrorCode -eq 22) { $det = 'Disabled' }
    $prob += [pscustomobject]@{ Name = $nm; Detail = $det }
    Log "    $nm  ($det)"
}
if (-not $prob.Count) { Log '    No problem devices - all drivers OK.' }
Log '[*] Finding your oldest third-party drivers...'
$old = @()
foreach ($d in (Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverDate -and $_.DeviceName -and $_.DriverProviderName -and $_.DriverProviderName -notmatch 'Microsoft' } | Sort-Object DriverDate | Select-Object -First 8)) {
    $dt = $d.DriverDate.ToString('yyyy-MM-dd')
    $old += [pscustomobject]@{ Name = $d.DeviceName; Detail = $dt }
    Log "    $($d.DeviceName)  ($dt)"
}
$sync.Results['Drivers'] = [pscustomobject]@{ Problems = $prob; Old = $old }
Done ("Driver check: {0} problem device(s)" -f $prob.Count)
'@

$Tasks.health = @'
Log '--- [1/3] DISM image repair (can sit at 20% or 62% for a while, that is normal) ---'
$e1 = RunNative 'DISM.exe' @('/Online', '/Cleanup-Image', '/RestoreHealth')
Log '--- [2/3] System File Checker ---'
$e2 = RunNative 'sfc.exe' @('/scannow')
Log '--- [3/3] Disk scan (online, no reboot) ---'
$dk = RunNative 'chkdsk.exe' @("$env:SystemDrive", '/scan')
if ($dk -ge 2) {
    Log '    Problems found - scheduling a repair for the next restart...'
    [void](RunNative 'cmd.exe' @('/c', "echo y| chkdsk $env:SystemDrive /f") -Quiet)
    $msg = 'Disk problems found. Repair scheduled - restart your PC to finish it.'
} else {
    $msg = 'DISM and SFC finished, disk looks healthy.'
}
if ($e1 -ne 0) { $msg += " (DISM exit code $e1)" }
$sync.Results['Health'] = ("{0}  Last run {1}." -f $msg, (Get-Date -Format 'h:mm tt'))
Done "Health check: $msg"
'@

$Tasks.netreset = @'
Log '[*] Resetting TCP/IP and Winsock to defaults...'
[void](RunNative 'netsh.exe' @('int', 'tcp', 'reset') -Quiet)
[void](RunNative 'netsh.exe' @('int', 'ip', 'reset') -Quiet)
[void](RunNative 'netsh.exe' @('winsock', 'reset') -Quiet)
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemProperty -Path $_.PSPath -Name 'TcpAckFrequency', 'TCPNoDelay' -ErrorAction SilentlyContinue
}
$mm = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
[void](RunNative 'reg.exe' @('add', $mm, '/v', 'NetworkThrottlingIndex', '/t', 'REG_DWORD', '/d', '10', '/f') -Quiet)
[void](RunNative 'reg.exe' @('add', $mm, '/v', 'SystemResponsiveness', '/t', 'REG_DWORD', '/d', '20', '/f') -Quiet)
Done 'Network settings reset to defaults - RESTART your PC to finish'
'@

$Tasks.restorepoint = @'
$sync.RpDone = $false
if (Ensure-RP -NoAsk) { Log '    Roll back anytime from Activity > Open System Restore.' }
'@

$Tasks.dnsset = @'
$ad = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
if (-not $ad.Count) { Log '[X] No active network adapter found.'; return }
foreach ($a in $ad) {
    if ($dnsServers) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $dnsServers -ErrorAction Stop }
    else { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop }
    Log "    $($a.Name) updated"
}
[void](RunNative 'ipconfig.exe' @('/flushdns') -Quiet)
Done "DNS set to $dnsName"
$sync.ForceRefresh = $true
$sync.Results['NetRefresh'] = $true
'@

$Tasks.driverscan = @'
Log '[*] Searching Windows Update for driver updates (usually 30 sec - 2 min)...'
$sess = New-Object -ComObject Microsoft.Update.Session
$sess.ClientApplicationID = 'PC Optimizer'
$sr = $sess.CreateUpdateSearcher()
$sr.ServerSelection = 2
$res = $sr.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
$all = @()
foreach ($u in $res.Updates) {
    $key = [string]$u.DriverHardwareID; if (-not $key) { $key = [string]$u.DriverModel }; if (-not $key) { $key = $u.Title }
    $all += [pscustomobject]@{ Id = $u.Identity.UpdateID; Title = $u.Title; Class = [string]$u.DriverClass; Key = $key; When = $u.DriverVerDate; MB = [math]::Round($u.MaxDownloadSize / 1MB, 1) }
}
$best = @($all | Group-Object Key | ForEach-Object { $_.Group | Sort-Object When -Descending | Select-Object -First 1 })
$out = @()
foreach ($b in $best) {
    $dt = ''; try { $dt = ([datetime]$b.When).ToString('yyyy-MM-dd') } catch {}
    $cls = $b.Class; if (-not $cls) { $cls = 'Driver' }
    $out += [pscustomobject]@{ Id = $b.Id; Name = $b.Title; Detail = ('{0}  |  {1}  |  {2} MB' -f $cls, $dt, $b.MB) }
    Log ('    {0}  ({1})' -f $b.Title, $dt)
}
if ($all.Count -gt $best.Count) { Log ("    Skipped {0} older duplicate(s) - kept the newest per device." -f ($all.Count - $best.Count)) }
$sync.Results['DriverScan'] = $out
if ($out.Count) { Done ("Found {0} driver update(s)" -f $out.Count) } else { Done 'No driver updates on Windows Update - you are up to date' }
'@

$Tasks.driverinstall = @'
if (-not (Ensure-RP)) { return }
$codes = @{ 0 = 'not started'; 1 = 'in progress'; 2 = 'OK'; 3 = 'OK with errors'; 4 = 'FAILED'; 5 = 'aborted' }
Log '[*] Re-checking Windows Update...'
$sess = New-Object -ComObject Microsoft.Update.Session
$sess.ClientApplicationID = 'PC Optimizer'
$sr = $sess.CreateUpdateSearcher()
$sr.ServerSelection = 2
$res = $sr.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $res.Updates) {
    if ($updateIds -contains $u.Identity.UpdateID) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$coll.Add($u)
    }
}
if ($coll.Count -eq 0) { Log '    Nothing to install - they may already be installed.'; return }
Log ("[*] Downloading {0} driver(s)..." -f $coll.Count)
$dl = $sess.CreateUpdateDownloader(); $dl.Updates = $coll
$dr = $dl.Download()
Log ("    Download: {0}" -f $codes[[int]$dr.ResultCode])
Log '[*] Installing (screen may flicker for display drivers)...'
$ins = $sess.CreateUpdateInstaller(); $ins.Updates = $coll
$ir = $ins.Install()
$okCount = 0
for ($i = 0; $i -lt $coll.Count; $i++) {
    $rc = [int]$ir.GetUpdateResult($i).ResultCode
    if ($rc -eq 2 -or $rc -eq 3) { $okCount++ }
    Log ('    {0}: {1}' -f $coll.Item($i).Title, $codes[$rc])
    Note ('Driver install {0}: {1}' -f $codes[$rc], $coll.Item($i).Title)
}
Done ("Installed {0} of {1} driver update(s)" -f $okCount, $coll.Count)
if ($ir.RebootRequired) { Log '[!] Restart your PC to finish installing.' }
$sync.Results['DriverInstalled'] = $ir.RebootRequired
'@

# ---- NVIDIA driver settings (official NVAPI IDs from github.com/NVIDIA/nvapi) ----
$NvCode = @'
using System;
using System.Runtime.InteropServices;

namespace PCOpt
{
    public sealed class NvSession : IDisposable
    {
        [DllImport("nvapi64.dll", EntryPoint = "nvapi_QueryInterface", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr QI(uint id);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int D0();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DOut(out IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DP(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DPOut(IntPtr a, out IntPtr b);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DGet(IntPtr s, IntPtr p, uint id, IntPtr st);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DSet(IntPtr s, IntPtr p, IntPtr st);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int DRes(IntPtr s, IntPtr p, uint id);

        // NVDRS_SETTING_V1 is pack(4): 12320 bytes, version = size | (1 << 16)
        const int SIZE = 12320;
        const int VER = 0x13020;
        const int OFF_ID = 4100, OFF_TYPE = 4104, OFF_LOC = 4108, OFF_CUR = 8220;
        public const int NOT_FOUND = -160;

        IntPtr s = IntPtr.Zero, prof = IntPtr.Zero;
        DGet get; DSet set; DRes res; DP save; DP destroy;

        static Delegate F(uint id, Type t)
        {
            IntPtr p = QI(id);
            if (p == IntPtr.Zero) throw new Exception("NVAPI function not available (0x" + id.ToString("X8") + ")");
            return Marshal.GetDelegateForFunctionPointer(p, t);
        }
        static void Ok(int r, string what) { if (r != 0) throw new Exception(what + " failed (NVAPI " + r + ")"); }

        public NvSession()
        {
            Ok(((D0)F(0x0150E828, typeof(D0)))(), "NVAPI init");
            Ok(((DOut)F(0x0694D52E, typeof(DOut)))(out s), "Create session");
            Ok(((DP)F(0x375DBD6B, typeof(DP)))(s), "Load settings");
            Ok(((DPOut)F(0xDA8466A0, typeof(DPOut)))(s, out prof), "Get base profile");
            get = (DGet)F(0x73BF8338, typeof(DGet));
            set = (DSet)F(0x577DD202, typeof(DSet));
            res = (DRes)F(0x53F0381E, typeof(DRes));
            save = (DP)F(0xFCBC7E14, typeof(DP));
            destroy = (DP)F(0xDAD9CFF8, typeof(DP));
        }

        IntPtr NewBuf()
        {
            IntPtr b = Marshal.AllocHGlobal(SIZE);
            Marshal.Copy(new byte[SIZE], 0, b, SIZE);
            Marshal.WriteInt32(b, 0, VER);
            return b;
        }

        public int Get(uint id, out int value, out int location)
        {
            IntPtr b = NewBuf();
            try
            {
                int r = get(s, prof, id, b);
                value = Marshal.ReadInt32(b, OFF_CUR);
                location = Marshal.ReadInt32(b, OFF_LOC);
                return r;
            }
            finally { Marshal.FreeHGlobal(b); }
        }

        public void Set(uint id, int value)
        {
            IntPtr b = NewBuf();
            try
            {
                Marshal.WriteInt32(b, OFF_ID, (int)id);
                Marshal.WriteInt32(b, OFF_TYPE, 0);
                Marshal.WriteInt32(b, OFF_CUR, value);
                Ok(set(s, prof, b), "Set setting 0x" + id.ToString("X8"));
            }
            finally { Marshal.FreeHGlobal(b); }
        }

        public void Restore(uint id)
        {
            int r = res(s, prof, id);
            if (r != 0 && r != NOT_FOUND) Ok(r, "Restore setting 0x" + id.ToString("X8"));
        }

        public void Save() { Ok(save(s), "Save settings"); }

        public void Dispose()
        {
            if (s != IntPtr.Zero) { destroy(s); s = IntPtr.Zero; }
        }
    }
}
'@

$NvPresetCommon = @'
$nvIds = [ordered]@{ 'Power management mode' = 0x1057EB71; 'Texture filtering quality' = 0x00CE2691; 'Low latency mode' = 0x007BA09E; 'Threaded optimization' = 0x20C1221E }
$nvText = @{
    'Power management mode'     = @{ 0 = 'Adaptive'; 1 = 'Prefer maximum performance'; 5 = 'Normal' }
    'Texture filtering quality' = @{ 20 = 'High performance'; 10 = 'Performance'; 0 = 'Quality'; -10 = 'High quality' }
    'Low latency mode'          = @{ 0 = 'Off'; 1 = 'On' }
    'Threaded optimization'     = @{ 1 = 'On'; 2 = 'Off' }
}
$bkFile = Join-Path $appDir 'gpu_backup.json'
Add-Type -TypeDefinition $nvCode -ErrorAction Stop
'@

$Tasks.gpupreset = @'
if ($gpuVendor -ne 'NVIDIA') { Done "Gaming preset: $preset (Windows power plan set - finish the AMD/Intel checklist on the Gaming page)"; $sync.Results['GpuPreset'] = $preset; return }
'@ + "`n" + $NvPresetCommon + "`n" + @'
$presets = @{
    Performance = @{ 'Power management mode' = 1; 'Texture filtering quality' = 20;  'Low latency mode' = 1; 'Threaded optimization' = 1 }
    Balanced    = @{ 'Power management mode' = 5; 'Texture filtering quality' = 0;   'Low latency mode' = 1; 'Threaded optimization' = $null }
    Quality     = @{ 'Power management mode' = 1; 'Texture filtering quality' = -10; 'Low latency mode' = 0; 'Threaded optimization' = $null }
}
$nv = New-Object PCOpt.NvSession
try {
    if (-not (Test-Path -LiteralPath $bkFile)) {
        $save = @()
        foreach ($n in $nvIds.Keys) {
            $v = 0; $l = 0
            $r = $nv.Get([uint32]$nvIds[$n], [ref]$v, [ref]$l)
            $save += [pscustomobject]@{ Id = [uint32]$nvIds[$n]; Name = $n; IsDefault = ($r -ne 0 -or $l -ne 0); Value = $v }
        }
        ConvertTo-Json -InputObject $save | Set-Content -LiteralPath $bkFile -Encoding UTF8
        Log '    Saved your original NVIDIA settings first (Restore button puts them back).'
    }
    $p = $presets[$preset]
    foreach ($n in $nvIds.Keys) {
        $id = [uint32]$nvIds[$n]; $val = $p[$n]
        if ($null -eq $val) { $nv.Restore($id); Log "    $n -> driver default" }
        else { $nv.Set($id, [int]$val); Log ("    {0} -> {1}" -f $n, $nvText[$n][[int]$val]) }
    }
    $nv.Save()
} finally { $nv.Dispose() }
Done "NVIDIA Control Panel set to the $preset preset"
$sync.Results['GpuPreset'] = $preset
'@

$Tasks.gpurestore = $NvPresetCommon + "`n" + @'
if (-not (Test-Path -LiteralPath $bkFile)) { Log '    Nothing to restore - no preset has been applied yet.'; return }
$items = @(Get-Content -LiteralPath $bkFile -Raw | ConvertFrom-Json)
$nv = New-Object PCOpt.NvSession
try {
    foreach ($it in $items) {
        if ($it.IsDefault) { $nv.Restore([uint32]$it.Id) } else { $nv.Set([uint32]$it.Id, [int]$it.Value) }
        Log "    $($it.Name) restored"
    }
    $nv.Save()
} finally { $nv.Dispose() }
Remove-Item -LiteralPath $bkFile -Force
Done 'Original NVIDIA settings restored'
$sync.Results['GpuPreset'] = ''
'@

$Tasks.wgupdate = @'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$ok = 0
foreach ($id in $wgIds) {
    Log "[*] Updating $id ..."
    $code = RunNative 'winget.exe' @('upgrade', '--id', $id, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($code -eq 0) { $ok++; Note "Updated app: $id" } else { Log ("    winget finished with code {0}" -f $code) }
}
Done ("App updates: {0} of {1} updated" -f $ok, @($wgIds).Count)
$sync.Results['WingetDone'] = $true
'@

$Tasks.defscan = @'
Log '[*] Running a Microsoft Defender quick scan (usually 2-10 minutes)...'
Start-MpScan -ScanType QuickScan -ErrorAction Stop
$t = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-30) })
if ($t.Count) { Log ("[!] Defender found {0} threat(s) - open Windows Security to review." -f $t.Count) }
Done 'Defender quick scan finished'
'@

$Tasks.update = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$base = "https://raw.githubusercontent.com/$updRepo/main/"
Log "[*] Checking $updRepo ..."
$j = Invoke-RestMethod -Uri ($base + 'version.json') -UseBasicParsing -TimeoutSec 20 -Headers @{ 'Cache-Control' = 'no-cache' }
if (-not ([version]$j.version -gt [version]$curVer)) { Log '    Already up to date.'; return }
$stage = Join-Path $env:TEMP ('PCOptimizerUpdate_' + $j.version)
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
[void](New-Item -ItemType Directory -Path $stage -Force)
$allowed = 'PC_Optimizer.ps1', 'Setup.ps1', 'Uninstall.ps1', 'PC_Optimizer.ico'
foreach ($f in $j.files.PSObject.Properties) {
    $name = $f.Name; $want = ([string]$f.Value).ToUpper()
    if ($allowed -notcontains $name) { throw "Update lists an unexpected file ($name) - stopped for safety." }
    $dst = Join-Path $stage $name
    Invoke-WebRequest -Uri ($base + $name) -OutFile $dst -UseBasicParsing -TimeoutSec 120
    $got = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
    if ($got -ne $want) { throw "Hash check failed for $name - the download was changed or corrupted. Nothing was installed." }
    Log "    $name verified"
}
foreach ($need in $allowed) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $need))) {
        $cur = Join-Path $appDir $need
        if (Test-Path -LiteralPath $cur) { Copy-Item -LiteralPath $cur -Destination $stage } else { throw "Update is missing $need." }
    }
}
foreach ($ps1 in (Get-ChildItem -LiteralPath $stage -Filter *.ps1)) {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($ps1.FullName, [ref]$null, [ref]$errs)
    if ($errs.Count) { throw "$($ps1.Name) has code errors - update skipped." }
}
Done ("Update {0} downloaded and verified - installing now. The app will reopen." -f $j.version)
Start-Sleep -Seconds 2
Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$stage\Setup.ps1`"", '-Silent')
'@

$Tasks.runall = "Log '>>> Step 1 of 4: network'`n" + $Tasks.network +
                "`nLog '>>> Step 2 of 4: background apps'`n" + $Tasks.kill +
                "`nLog '>>> Step 3 of 4: cleanup'`n" + $Tasks.cleanup +
                "`nLog '>>> Step 4 of 4: drivers'`n" + $Tasks.drivers +
                "`nDone 'RUN ALL finished - restart your PC for full effect'"

$TaskTitles = @{
    network = 'Boost network'; kill = 'Kill background apps'; cleanup = 'Clean PC'; drivers = 'Driver check'
    health = 'Health check'; netreset = 'Reset network'; restorepoint = 'Create restore point'
    dnsset = 'Change DNS'; runall = 'Run All'
    driverscan = 'Search driver updates'; driverinstall = 'Install driver updates'
    gpupreset = 'Gaming preset'; gpurestore = 'Restore GPU settings'; wgupdate = 'Update apps'
    defscan = 'Defender quick scan'; update = 'Update PC Optimizer'
}

# Quick read-only jobs (can run alongside a task)
$Quick = @{}

$Quick.netinfo = @'
$a = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
$info = $null
if ($a) {
    $c = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
    $info = [pscustomobject]@{
        Adapter = $a.Name; Device = $a.InterfaceDescription; Speed = $a.LinkSpeed
        IPv4 = (@($c.IPv4Address.IPAddress) -join ', ')
        Gateway = (@($c.IPv4DefaultGateway.NextHop) -join ', ')
        Dns = (@(($c.DNSServer | Where-Object AddressFamily -eq 2).ServerAddresses) -join ', ')
        Mac = $a.MacAddress
    }
}
$sync.Results['NetInfo'] = @($info)
$w = @{}
foreach ($line in (netsh.exe wlan show interfaces 2>$null)) {
    if ($line -match '^\s+([^:]+?)\s*:\s(.+)$') { $key = $Matches[1].Trim(); if (-not $w.ContainsKey($key)) { $w[$key] = $Matches[2].Trim() } }
}
$sync.Results['Wifi'] = $w
'@

$Quick.pingcheck = @'
Log ''
Log '=== Ping check: router vs internet ==='
$gw = @((Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop)[0]
$r = $null
if ($gw) { $r = PingStats $gw 10; Log ('    Router {0}: avg {1} ms, lost {2}/10' -f $gw, $r.Avg, $r.Lost) }
$i = PingStats '1.1.1.1' 10
Log ('    Internet 1.1.1.1: avg {0} ms, lost {1}/10' -f $i.Avg, $i.Lost)
$sync.Results['PingCheck'] = [pscustomobject]@{ Router = $r; Net = $i; Gw = $gw }
'@

$Quick.dnstest = @'
Log ''
Log '=== DNS speed test ==='
$list = [ordered]@{}
$a = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
if ($a) {
    $cur = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)[0]
    if ($cur) { $list["Current ($cur)"] = $cur }
}
$list['Cloudflare'] = '1.1.1.1'; $list['Google'] = '8.8.8.8'; $list['Quad9'] = '9.9.9.9'
$sites = 'google.com', 'youtube.com', 'roblox.com', 'discord.com', 'steampowered.com', 'reddit.com'
$out = @()
foreach ($k in $list.Keys) {
    $ip = $list[$k]; $times = @()
    foreach ($s in $sites) {
        $sw = [Diagnostics.Stopwatch]::StartNew(); $ok = $true
        try { Resolve-DnsName -Name $s -Server $ip -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null } catch { $ok = $false }
        $sw.Stop(); if ($ok) { $times += $sw.Elapsed.TotalMilliseconds }
    }
    $avg = 9999; if ($times.Count) { $avg = [int][math]::Round(($times | Measure-Object -Average).Average) }
    $out += [pscustomobject]@{ Name = $k; Ms = $avg; Pct = 0; Label = '' }
}
$max = ($out | Where-Object { $_.Ms -lt 9999 } | Measure-Object -Property Ms -Maximum).Maximum
if (-not $max) { $max = 1 }
foreach ($o in $out) {
    if ($o.Ms -ge 9999) { $o.Pct = 100; $o.Label = 'failed' }
    else { $o.Pct = [math]::Max(4, [math]::Round($o.Ms / $max * 100)); $o.Label = "$($o.Ms) ms" }
}
$best = $out | Where-Object { $_.Ms -lt 9999 } | Sort-Object Ms | Select-Object -First 1
if ($best) { $best.Label = $best.Label + '  - fastest' }
foreach ($o in $out) { Log ('    {0,-24} {1}' -f $o.Name, $o.Label) }
$sync.Results['DnsTest'] = $out
'@

$Quick.gpu = @'
$items = @()
foreach ($g in (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Basic Display|Remote|Virtual|Parsec|Mirror' })) {
    $url = $null; $btn = 'Get latest driver'
    if ($g.Name -match 'NVIDIA') { $url = 'https://www.nvidia.com/en-us/drivers/'; $btn = 'Get latest from NVIDIA' }
    elseif ($g.Name -match 'AMD|Radeon') { $url = 'https://www.amd.com/en/support/download/drivers.html'; $btn = 'Get latest from AMD' }
    elseif ($g.Name -match 'Intel') { $url = 'https://www.intel.com/content/www/us/en/support/detect.html'; $btn = 'Get latest from Intel' }
    if (-not $url) { continue }
    $dt = ''; try { $dt = ([datetime]$g.DriverDate).ToString('yyyy-MM-dd') } catch {}
    $items += [pscustomobject]@{ Name = $g.Name; Detail = ('Installed driver {0}  ({1})' -f $g.DriverVersion, $dt); Url = $url; Btn = $btn }
}
$sync.Results['Gpu'] = $items
$vend = ''; $gname = ''
foreach ($pref in 'NVIDIA', 'AMD|Radeon', 'Intel') { $hit = @($items | Where-Object { $_.Name -match $pref })[0]; if ($hit) { $gname = $hit.Name; $vend = (($pref -split '\|')[0]); break } }
$sync.Results['GpuVendor'] = [pscustomobject]@{ Vendor = $vend; Name = $gname }
'@

$Quick.speedtest = @'
Add-Type -AssemblyName System.Net.Http
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::DefaultConnectionLimit = 32
$h = New-Object System.Net.Http.HttpClient
$h.Timeout = [TimeSpan]::FromSeconds(40)
$h.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (Windows NT 10.0; Win64; x64) PCOptimizer/4.2')
$pg = New-Object System.Net.NetworkInformation.Ping
function OnePing { try { $r = $pg.Send('1.1.1.1', 800); if ($r.Status -eq 'Success') { return [int]$r.RoundtripTime } } catch {}; return $null }
function Median($a) { $a = @($a | Sort-Object); if (-not $a.Count) { return $null }; return $a[[int][math]::Floor($a.Count / 2)] }
function Run-Phase([string]$kind) {
    $size = 1MB; $bytes = 0.0; $busy = 0.0; $loaded = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 8) {
        $t0 = $sw.Elapsed.TotalSeconds
        $tasks = @()
        $buf = $null; if ($kind -eq 'up') { $buf = New-Object 'byte[]' $size }
        for ($k = 0; $k -lt 4; $k++) {
            if ($kind -eq 'down') { $tasks += $h.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=$size") }
            else { $tasks += $h.PostAsync('https://speed.cloudflare.com/__up', (New-Object System.Net.Http.ByteArrayContent (, $buf))) }
        }
        while (@($tasks | Where-Object { -not $_.IsCompleted }).Count -gt 0) {
            $x = OnePing; if ($null -ne $x) { $loaded += $x }
            if ($sw.Elapsed.TotalSeconds -gt 25) { break }
            Start-Sleep -Milliseconds 100
        }
        $ok = 0
        foreach ($t in $tasks) {
            if ($t.Status -ne 'RanToCompletion') { continue }
            if ($kind -eq 'up') { if ($t.Result.IsSuccessStatusCode) { $ok++ }; $t.Result.Dispose() } else { $ok++ }
        }
        if ($ok -eq 0) { throw "The speed test server didn't answer ($kind)." }
        $bytes += $ok * $size
        $dt = $sw.Elapsed.TotalSeconds - $t0; $busy += $dt
        if ($dt -lt 1.5 -and $size -lt 32MB) { $size *= 4 }
        if ($sw.Elapsed.TotalSeconds -gt 25) { break }
    }
    [pscustomobject]@{ Mbps = [math]::Round($bytes * 8 / [math]::Max($busy, 0.001) / 1e6, 1); Loaded = $loaded }
}
Log ''
Log '=== Internet speed test (Cloudflare) ==='
$idle = @(); for ($n = 0; $n -lt 8; $n++) { $x = OnePing; if ($null -ne $x) { $idle += $x }; Start-Sleep -Milliseconds 150 }
$idleMs = Median $idle
Log ("    Idle ping: {0} ms" -f $idleMs)
$d = Run-Phase 'down'; Log ("    Download: {0} Mbps" -f $d.Mbps)
$u = Run-Phase 'up';   Log ("    Upload: {0} Mbps" -f $u.Mbps)
$loadedMs = Median (@($d.Loaded) + @($u.Loaded))
$grade = '?'
if ($null -ne $loadedMs -and $null -ne $idleMs) {
    $delta = $loadedMs - $idleMs
    if ($delta -le 5) { $grade = 'A+' } elseif ($delta -le 30) { $grade = 'A' } elseif ($delta -le 60) { $grade = 'B' } elseif ($delta -le 200) { $grade = 'C' } elseif ($delta -le 400) { $grade = 'D' } else { $grade = 'F' }
}
Log ("    Busy ping: {0} ms  ->  bufferbloat grade {1}" -f $loadedMs, $grade)
$h.Dispose(); $pg.Dispose()
$sync.Results['Speed'] = [pscustomobject]@{ Down = $d.Mbps; Up = $u.Mbps; Idle = $idleMs; Loaded = $loadedMs; Grade = $grade }
'@

$Quick.cpuprocs = @'
$cores = [Environment]::ProcessorCount
[void](Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue)
Start-Sleep -Milliseconds 1200
$rows = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' }
$g = $rows | Group-Object { $_.Name -replace '#\d+$', '' } | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Cpu = [math]::Round((($_.Group | Measure-Object PercentProcessorTime -Sum).Sum) / $cores, 1) }
} | Where-Object { $blockList -notcontains $_.Name } | Sort-Object Cpu -Descending | Select-Object -First 12
$top = [math]::Max(1, (@($g)[0]).Cpu)
$sync.Results['CpuProcs'] = @($g | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Label = ('{0}% CPU' -f $_.Cpu); Pct = [math]::Max(3, [math]::Round($_.Cpu / $top * 100)) } })
'@

$Quick.wgcheck = @'
if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { $sync.Results['Winget'] = 'missing'; return }
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
Log ''
Log '=== Checking for app updates (winget) ==='
# Preferred: Microsoft's winget PowerShell module (gives full app IDs, no text parsing)
$mod = $false
try { Import-Module Microsoft.WinGet.Client -ErrorAction Stop; $mod = $true } catch {
    try {
        Log '    First run: installing Microsoft''s winget PowerShell module (one time)...'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }
        Install-Module Microsoft.WinGet.Client -Repository PSGallery -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop; $mod = $true
    } catch { Log "    Module not available ($($_.Exception.Message)) - reading winget's text output instead." }
}
if ($mod) {
    try {
        $apps = @()
        foreach ($pk in (Get-WinGetPackage -ErrorAction Stop | Where-Object { $_.IsUpdateAvailable })) {
            $av = @($pk.AvailableVersions)[0]
            $apps += [pscustomobject]@{ Id = [string]$pk.Id; Name = [string]$pk.Name; Detail = "$($pk.InstalledVersion)  ->  $av" }
            Log ("    {0}  {1} -> {2}" -f $pk.Name, $pk.InstalledVersion, $av)
        }
        if (-not $apps.Count) { Log '    Everything is up to date.' }
        $sync.Results['Winget'] = $apps
        return
    } catch { Log "    winget module failed ($($_.Exception.Message)) - trying the text output." }
}
try { [Console]::BufferWidth = 400 } catch {}
$out = @(& winget.exe upgrade --include-unknown --accept-source-agreements --disable-interactivity 2>&1 | ForEach-Object { [string]$_ })
if (($out -join ' ') -match 'Argument name was not recognized|unrecognized') { $out = @(& winget.exe upgrade --include-unknown --accept-source-agreements 2>&1 | ForEach-Object { [string]$_ }) }
$lines = @($out | ForEach-Object { ($_ -split "`r")[-1] })
$hi = -1
for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*Name\s+Id\s+Version\s+Available') { $hi = $i; break } }
$apps = @()
if ($hi -ge 0) {
    $hdr = $lines[$hi]
    $idPos = $hdr.IndexOf('Id'); $verPos = $hdr.IndexOf('Version'); $avPos = $hdr.IndexOf('Available'); $srcPos = $hdr.IndexOf('Source')
    for ($i = $hi + 2; $i -lt $lines.Count; $i++) {
        $row = $lines[$i]
        if (-not $row.Trim()) { break }
        if ($row -match '^\d+ (upgrade|package)') { break }
        if ($row.Length -le $avPos) { continue }
        $id = $row.Substring($idPos, $verPos - $idPos).Trim()
        $ver = $row.Substring($verPos, $avPos - $verPos).Trim()
        $avEnd = $row.Length; if ($srcPos -gt $avPos -and $row.Length -gt $srcPos) { $avEnd = $srcPos }
        $av = $row.Substring($avPos, $avEnd - $avPos).Trim()
        $name = $row.Substring(0, $idPos).Trim()
        if ($id -notmatch '^[\w\.\-\+]+$') {
            # columns shifted (wide characters in the name) - read from the right instead
            $tk = @($row.Trim() -split '\s+')
            if ($tk.Count -ge 5) { $av = $tk[-2]; $ver = $tk[-3]; $id = $tk[-4]; $name = ($tk[0..($tk.Count - 5)] -join ' ') }
        }
        if ($id -match '^[\w\.\-\+]+$' -and $id -notmatch '\.{3}$') {
            $apps += [pscustomobject]@{ Id = $id; Name = $name; Detail = "$ver  ->  $av" }
            Log ("    {0}  {1} -> {2}" -f $name, $ver, $av)
        }
    }
}
if (-not $apps.Count) { Log '    Everything is up to date.' }
$sync.Results['Winget'] = $apps
'@

$Quick.diskscan = @'
function Fmt([double]$b) { if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) } elseif ($b -ge 1MB) { return ('{0:N0} MB' -f ($b / 1MB)) } else { return ('{0:N0} KB' -f ($b / 1KB)) } }
Log ''
Log "=== Disk space: $dsRoot ==="
$res = @()
$dirs = @(Get-ChildItem -LiteralPath $dsRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
$n = 0
foreach ($d in $dirs) {
    $n++
    $sync.DiskProgress = "Measuring $($d.Name)  ($n of $($dirs.Count))"
    $o = & robocopy.exe $d.FullName 'NULL' /L /S /NJH /BYTES /NFL /NDL /NC /XJ /R:0 /W:0 2>$null
    $bytes = 0
    foreach ($l in $o) { if ($l -match '^\s*Bytes\s*:\s*(\d+)') { $bytes = [double]$Matches[1]; break } }
    $res += [pscustomobject]@{ Name = $d.Name; Path = $d.FullName; Bytes = $bytes }
}
$loose = (Get-ChildItem -LiteralPath $dsRoot -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
if ($loose -gt 100MB) { $res += [pscustomobject]@{ Name = '(files directly in this folder)'; Path = $dsRoot; Bytes = [double]$loose } }
$res = @($res | Sort-Object Bytes -Descending | Select-Object -First 12)
$top = [math]::Max(1, $res[0].Bytes)
$dirsOut = @($res | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.Path; Label = (Fmt $_.Bytes); Pct = [math]::Max(2, [math]::Round($_.Bytes / $top * 100)) } })
$sync.DiskProgress = 'Looking for the biggest files...'
$fo = & robocopy.exe $dsRoot 'NULL' /L /S /NJH /NJS /BYTES /NDL /NC /FP /XJ /R:0 /W:0 /MIN:209715200 2>$null
$files = @()
foreach ($l in $fo) { if ($l -match '^\s*(\d+)\s+(\S.*)$') { $files += [pscustomobject]@{ Bytes = [double]$Matches[1]; Path = $Matches[2].Trim() } } }
$files = @($files | Sort-Object Bytes -Descending | Select-Object -First 10)
$ftop = 1; if ($files.Count) { $ftop = $files[0].Bytes }
$filesOut = @($files | ForEach-Object { [pscustomobject]@{ Name = (Split-Path $_.Path -Leaf); Path = $_.Path; Label = (Fmt $_.Bytes); Pct = [math]::Max(2, [math]::Round($_.Bytes / $ftop * 100)) } })
foreach ($r in $dirsOut) { Log ("    {0,-40} {1}" -f $r.Name, $r.Label) }
$sync.DiskProgress = $null
$sync.Results['Disk'] = [pscustomobject]@{ Root = $dsRoot; Dirs = $dirsOut; Files = $filesOut }
'@

$Quick.lan = @'
Log ''
$a = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $a) { $sync.Results['Lan'] = 'offline'; return }
$ipc = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
$myIp = @($ipc.IPv4Address.IPAddress)[0]; $gw = @($ipc.IPv4DefaultGateway.NextHop)[0]
$pre = $myIp -replace '\.\d+$', ''
Log "=== Scanning $pre.0/24 ==="
$jobs = foreach ($i in 1..254) { $p = New-Object System.Net.NetworkInformation.Ping; [pscustomobject]@{ Ip = "$pre.$i"; P = $p; T = $p.SendPingAsync("$pre.$i", 800) } }
try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($jobs | ForEach-Object { $_.T }), 5000) } catch {}
$alive = @{}
foreach ($j in $jobs) { if ($j.T.Status -eq 'RanToCompletion' -and $j.T.Result.Status -eq 'Success') { $alive[$j.Ip] = $true }; $j.P.Dispose() }
Start-Sleep -Milliseconds 300
$mac = @{}
foreach ($nb in (Get-NetNeighbor -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($nb.IPAddress -like "$pre.*" -and $nb.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and $nb.LinkLayerAddress -and $nb.LinkLayerAddress -notmatch '^(FF-){5}FF$|^(00-){5}00$') { $mac[$nb.IPAddress] = $nb.LinkLayerAddress }
}
$mac[$myIp] = $a.MacAddress
$ips = @(@($alive.Keys) + @($mac.Keys) | Where-Object { $_ -notmatch '\.(0|255)$' } | Sort-Object -Unique)
# vendor list (IEEE, cached in the app folder; Wireshark list as a backup)
$ouiFile = Join-Path $appDir 'oui.csv'; $vendors = @{}
if (-not (Test-Path -LiteralPath $ouiFile) -or ((Get-Date) - (Get-Item -LiteralPath $ouiFile).LastWriteTime).TotalDays -gt 120) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $sync.LanProgress = 'Downloading the device maker list (one time)...'
    try {
        Invoke-WebRequest -Uri 'https://standards-oui.ieee.org/oui/oui.csv' -OutFile $ouiFile -UseBasicParsing -TimeoutSec 60 -UserAgent 'Mozilla/5.0 PCOptimizer'
    } catch {
        try {
            $raw = (Invoke-WebRequest -Uri 'https://www.wireshark.org/download/automated/data/manuf' -UseBasicParsing -TimeoutSec 60 -UserAgent 'Mozilla/5.0 PCOptimizer').Content
            $csv = foreach ($l in ($raw -split "`n")) { if ($l -match '^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\t[^\t]*\t(.+)$') { '"x","{0}{1}{2}","{3}",""' -f $Matches[1], $Matches[2], $Matches[3], ($Matches[4].Trim() -replace '"', "'") } }
            Set-Content -LiteralPath $ouiFile -Value (@('Registry,Assignment,Organization Name,Organization Address') + @($csv)) -Encoding UTF8
        } catch {}
    }
}
if (Test-Path -LiteralPath $ouiFile) { try { foreach ($r in (Import-Csv -LiteralPath $ouiFile)) { $vendors[[string]$r.Assignment] = [string]$r.'Organization Name' } } catch {} }
$sync.LanProgress = 'Looking up device names...'
$dns = @{}
$dj = foreach ($ip in $ips) { [pscustomobject]@{ Ip = $ip; T = [System.Net.Dns]::GetHostEntryAsync($ip) } }
try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($dj | ForEach-Object { $_.T }), 3000) } catch {}
foreach ($x in $dj) { if ($x.T.Status -eq 'RanToCompletion' -and $x.T.Result.HostName -and $x.T.Result.HostName -ne $x.Ip) { $dns[$x.Ip] = $x.T.Result.HostName } }
$out = @()
foreach ($ip in ($ips | Sort-Object { [int]($_ -replace '^.*\.', '') })) {
    $m = $mac[$ip]; $vendor = ''; $badge = 'Online'; $bg = '#3A4170'
    if ($m) {
        $first = [Convert]::ToInt32($m.Substring(0, 2), 16)
        if ($first -band 2) { $vendor = 'Private (randomized) MAC'; $badge = 'Phone/laptop?' }
        else { $vendor = $vendors[($m -replace '-', '').Substring(0, 6).ToUpper()] }
    }
    if ($ip -eq $myIp) { $badge = 'This PC'; $bg = '#8C7BFF' } elseif ($ip -eq $gw) { $badge = 'Router'; $bg = '#FF4F9A' }
    $name = $dns[$ip]; if (-not $name) { $name = $vendor }; if (-not $name) { $name = 'Unknown device' }
    $sub = $ip; if ($m) { $sub += "   |   $m" }; if ($vendor -and $vendor -ne $name) { $sub += "   |   $vendor" }
    $out += [pscustomobject]@{ Name = $name; Sub = $sub; Badge = $badge; BadgeBg = $bg }
}
Log ("    Found {0} device(s)" -f $out.Count)
$sync.LanProgress = $null
$sync.Results['Lan'] = $out
'@

$Quick.security = @'
$ok = '#4BE3A6'; $warn = '#FFC857'; $bad = '#FF5C7A'; $na = '#8B91B7'
$items = New-Object System.Collections.ArrayList
function Add-Check($name, $detail, $color) { [void]$items.Add([pscustomobject]@{ Name = $name; Detail = $detail; Color = $color }) }
Log ''
Log '=== Security check ==='
try {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    $on = @($av | Where-Object { ($_.productState -band 0xF000) -eq 0x1000 })
    if ($on.Count) {
        $stale = @($on | Where-Object { ($_.productState -band 0xF0) -ne 0 })
        if ($stale.Count) { Add-Check 'Antivirus' ("{0} - definitions out of date" -f ($on.displayName -join ', ')) $warn } else { Add-Check 'Antivirus' ("{0} - on and up to date" -f ($on.displayName -join ', ')) $ok }
    } else { Add-Check 'Antivirus' 'No active antivirus found' $bad }
} catch { Add-Check 'Antivirus' "Couldn't read Security Center" $na }
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.AntivirusEnabled) {
        if ($mp.RealTimeProtectionEnabled) { Add-Check 'Defender real-time protection' 'On' $ok } else { Add-Check 'Defender real-time protection' 'Off' $bad }
        if ($mp.AntivirusSignatureAge -le 3) { Add-Check 'Defender definitions' ("{0} day(s) old" -f $mp.AntivirusSignatureAge) $ok } else { Add-Check 'Defender definitions' ("{0} days old - update them" -f $mp.AntivirusSignatureAge) $warn }
        if ($mp.QuickScanAge -le 14) { Add-Check 'Last Defender scan' ("{0} day(s) ago" -f $mp.QuickScanAge) $ok } else { Add-Check 'Last Defender scan' ("{0} days ago - run a quick scan" -f $mp.QuickScanAge) $warn }
    }
} catch {}
try {
    $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
    $off = @($fw | Where-Object { -not $_.Enabled })
    if ($off.Count) { Add-Check 'Firewall' ("Off for: {0}" -f ($off.Name -join ', ')) $bad } else { Add-Check 'Firewall' 'On for Domain, Private and Public' $ok }
} catch { Add-Check 'Firewall' "Couldn't read firewall" $na }
try {
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
    if ($lua -eq 1) { Add-Check 'User Account Control' 'On' $ok } else { Add-Check 'User Account Control' 'Off - apps can get admin silently' $bad }
} catch {}
try {
    if ((Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) { Add-Check 'SMBv1 file sharing' 'On - old and unsafe, turn it off' $bad } else { Add-Check 'SMBv1 file sharing' 'Off' $ok }
} catch {}
try {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($rdp -eq 1) { Add-Check 'Remote Desktop' 'Off' $ok } else { Add-Check 'Remote Desktop' 'On - only keep this if you use it' $warn }
} catch {}
try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { Add-Check 'Secure Boot' 'On' $ok } else { Add-Check 'Secure Boot' 'Off' $warn } } catch { Add-Check 'Secure Boot' 'Not supported or not readable' $na }
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') { Add-Check 'Drive encryption (BitLocker)' 'On' $ok } else { Add-Check 'Drive encryption (BitLocker)' 'Off - fine for a desktop, recommended on laptops' $na }
} catch {}
$ports = @()
try {
    $ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | Sort-Object LocalPort -Unique | ForEach-Object {
        $pn = '?'; try { $pn = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        [pscustomobject]@{ Name = $pn; Detail = "TCP $($_.LocalPort)" }
    } | Select-Object -First 14)
} catch {}
$sync.SecProgress = 'Asking Windows Update about pending updates...'
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $n = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates.Count
    if ($n -eq 0) { Add-Check 'Windows Update' 'Up to date' $ok } else { Add-Check 'Windows Update' ("{0} update(s) waiting - install them" -f $n) $warn }
} catch { Add-Check 'Windows Update' "Couldn't check" $na }
$sync.SecProgress = $null
$good = @($items | Where-Object { $_.Color -eq $ok }).Count
$scored = @($items | Where-Object { $_.Color -ne $na }).Count
foreach ($it in $items) { Log ("    {0}: {1}" -f $it.Name, $it.Detail) }
$sync.Results['Security'] = [pscustomobject]@{ Items = @($items); Ports = $ports; Score = ("{0}/{1}" -f $good, $scored) }
'@

$Quick.updcheck = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $j = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/$updRepo/main/version.json" -UseBasicParsing -TimeoutSec 15 -Headers @{ 'Cache-Control' = 'no-cache' }
    $sync.Results['UpdCheck'] = [pscustomobject]@{ Ok = $true; Version = [string]$j.version; Notes = [string]$j.notes; Newer = ([version]$j.version -gt [version]$curVer) }
} catch {
    $sync.Results['UpdCheck'] = [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
}
'@

$Quick.startup = @'
$items = @()
foreach ($s in (Get-CimInstance Win32_StartupCommand | Sort-Object Name)) {
    $where = 'Your account'
    if ($s.Location -match 'Startup') { $where = 'Startup folder' } elseif ($s.Location -match '^HKLM') { $where = 'All users' }
    $items += [pscustomobject]@{ Name = $s.Name; Detail = $where }
}
$sync.Results['Startup'] = $items
'@

$Monitor = @'
$p = New-Object System.Net.NetworkInformation.Ping
$i = 0
$nvsmi = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
$hasSmi = Test-Path -LiteralPath $nvsmi
$gpuName = ''; $vramTotal = 0
try { $gpuName = (@(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Basic Display|Remote|Virtual|Parsec|Mirror' }) | Select-Object -First 1).Name } catch {}
try {
    foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue)) {
        $v = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'HardwareInformation.qwMemorySize' -ErrorAction SilentlyContinue).'HardwareInformation.qwMemorySize'
        if ($v -and ($v / 1MB) -gt $vramTotal) { $vramTotal = [double]$v / 1MB }
    }
} catch {}
while ($sync.Running) {
    if ($sync.ForceRefresh) { $i = 0; $sync.ForceRefresh = $false }
    try { $r = $p.Send('1.1.1.1', 1000); if ($r.Status -eq 'Success') { $sync.Ping = [int]$r.RoundtripTime } else { $sync.Ping = -1 } } catch { $sync.Ping = -1 }
    $sync.PingSeq++
    if ($i % 2 -eq 0) {
        try { $sync.Cpu = [int](Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime } catch {}
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $sync.RamTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            $sync.RamUsed  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 1)
        } catch {}
        try {
            $d = [IO.DriveInfo]::new($env:SystemDrive)
            $sync.DiskTotal = [math]::Round($d.TotalSize / 1GB)
            $sync.DiskFree  = [math]::Round($d.AvailableFreeSpace / 1GB, 1)
        } catch {}
        # graphics card
        try {
            if ($hasSmi) {
                $l = @(& $nvsmi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,clocks.gr,power.draw --format=csv,noheader,nounits 2>$null)[0]
                $f = @($l -split ',\s*')
                if ($f.Count -ge 7) {
                    $sync.Gpu = @{ Src = 'nvidia'; Name = $f[0]; Temp = ($f[1] -as [int]); Load = ($f[2] -as [int]); MemUsed = ($f[3] -as [double]); MemTotal = ($f[4] -as [double]); Clock = ($f[5] -as [int]); Power = ($f[6] -as [double]) }
                }
            } else {
                $eng = @(Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction Stop | Where-Object { $_.Name -like '*engtype_3D*' })
                $load = [math]::Min(100, [double](($eng | Measure-Object UtilizationPercentage -Sum).Sum))
                $mem = [double]((Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction Stop | Measure-Object DedicatedUsage -Maximum).Maximum) / 1MB
                $sync.Gpu = @{ Src = 'counters'; Name = $gpuName; Temp = $null; Load = [int]$load; MemUsed = $mem; MemTotal = $vramTotal; Clock = $null; Power = $null }
            }
        } catch {}
    }
    if ($i % 10 -eq 0) {
        try {
            $a = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
            if ($a) {
                $sync.Adapter = "$($a.Name)  ($($a.LinkSpeed))"
                $sync.Dns = (@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses) -join ', ')
            } else { $sync.Adapter = 'Offline'; $sync.Dns = '-' }
        } catch {}
        try { $l = (powercfg.exe /getactivescheme) -join ' '; if ($l -match '\(([^)]+)\)') { $sync.Plan = $Matches[1] } } catch {}
        # CPU temperature: only what the motherboard reports to Windows (many boards report nothing)
        try {
            $tz = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Where-Object { $_.CurrentTemperature -gt 2732 })
            if ($tz.Count) { $sync.CpuTemp = [int](($tz | Measure-Object CurrentTemperature -Maximum).Maximum / 10 - 273.15) } else { $sync.CpuTemp = $null }
        } catch { $sync.CpuTemp = $null }
    }
    $i++
    Start-Sleep -Milliseconds 1000
}
$p.Dispose()
'@

# ---------------------------------------------------------------
#  Weekly auto-clean mode: run Clean PC with no window, log it, quit
# ---------------------------------------------------------------
if ($AutoClean) {
    $q = $queue
    try {
        Invoke-Expression ($Prelude + "`n" + $Tasks.cleanup)
        Write-SecureLog 'Weekly auto-clean finished'
    } catch { try { Write-SecureLog ('Weekly auto-clean failed: ' + $_.Exception.Message) } catch {} }
    exit
}

# Windows system processes the process manager never shows or ends
$BlockList = @('Idle', 'System', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'LsaIso', 'svchost', 'dwm',
    'fontdrvhost', 'Memory Compression', 'MsMpEng', 'NisSrv', 'SecurityHealthService', 'SgrmBroker', 'audiodg', 'spoolsv', 'conhost',
    'sihost', 'ctfmon', 'taskhostw', 'RuntimeBroker', 'StartMenuExperienceHost', 'ShellExperienceHost', 'SearchHost', 'TextInputHost',
    'WmiPrvSE', 'dllhost', 'smartscreen', 'explorer', 'powershell', 'PC Optimizer', 'System Idle Process', 'Secure System', 'WUDFHost',
    'MpDefenderCoreService', 'SearchIndexer', 'LockApp', 'ApplicationFrameHost', 'SystemSettings', 'nvcontainer', 'NVDisplay.Container')

# ---------------------------------------------------------------
#  Worker plumbing
# ---------------------------------------------------------------
$script:Runners = New-Object System.Collections.ArrayList

function Start-Runner([string]$code, [hashtable]$vars) {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('q', $queue)
    $rs.SessionStateProxy.SetVariable('sync', $sync)
    $rs.SessionStateProxy.SetVariable('logFile', $logFile)
    $rs.SessionStateProxy.SetVariable('logEntropy', $logEntropy)
    $rs.SessionStateProxy.SetVariable('appDir', $PSScriptRoot)
    $rs.SessionStateProxy.SetVariable('nvCode', $NvCode)
    $rs.SessionStateProxy.SetVariable('blockList', $BlockList)
    $rs.SessionStateProxy.SetVariable('gpuVendor', $script:GpuVendor)
    $rs.SessionStateProxy.SetVariable('curVer', $AppVersion)
    if ($vars) { foreach ($k in $vars.Keys) { $rs.SessionStateProxy.SetVariable($k, $vars[$k]) } }
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($code)
    $h = $ps.BeginInvoke()
    [void]$script:Runners.Add(@{ PS = $ps; H = $h; RS = $rs })
}

function Start-Task([string]$name, [hashtable]$vars) {
    if ($sync.Busy) { Set-Status ("Hang on - '{0}' is still running." -f $sync.Current); return }
    $sync.Busy = $true
    $sync.TaskName = $name
    $sync.TaskVars = $vars
    $sync.Current = $TaskTitles[$name]
    $code = $Prelude + "`n" + $TaskWrapTop + "`n" + $Tasks[$name] + "`n" + $TaskWrapBottom
    Start-Runner $code $vars
}

function Start-Quick([string]$name, [hashtable]$vars) {
    if ($sync["Q_$name"]) { return }
    $sync["Q_$name"] = $true
    $code = $Prelude + "`n`$qn = '$name'`ntry {`n" + $Quick[$name] + "`n} catch { Log ('[X] ' + `$_.Exception.Message); `$sync.Results['Fail_' + `$qn] = `$_.Exception.Message } finally { `$sync['Q_' + `$qn] = `$false }"
    Start-Runner $code $vars
}

function Write-Note([string]$m) {
    $queue.Enqueue("[+] $m")
    try { Write-SecureLog $m } catch {}
}

function Set-Status([string]$m) {
    $StatusText.Text = $m
    $script:StatusUntil = (Get-Date).AddSeconds(5)
}

function Ask([string]$text, [string]$icon = 'Question') {
    return ([System.Windows.MessageBox]::Show($win, $text, 'PC Optimizer', 'YesNo', $icon) -eq 'Yes')
}

# ---------------------------------------------------------------
#  Drawing helpers
# ---------------------------------------------------------------
$inv = [Globalization.CultureInfo]::InvariantCulture

function Set-Arc($path, [double]$pct) {
    $cx = 75; $cy = 75; $r = 63
    $f = [math]::Min([math]::Max($pct, 0), 99.9) / 100
    if ($f -le 0.001) { $path.Data = $null; return }
    $a0 = 135 * [math]::PI / 180
    $a1 = (135 + 270 * $f) * [math]::PI / 180
    $x0 = $cx + $r * [math]::Cos($a0); $y0 = $cy + $r * [math]::Sin($a0)
    $x1 = $cx + $r * [math]::Cos($a1); $y1 = $cy + $r * [math]::Sin($a1)
    $large = 0; if (270 * $f -gt 180) { $large = 1 }
    $s = [string]::Format($inv, 'M {0:0.##},{1:0.##} A {2},{2} 0 {3} 1 {4:0.##},{5:0.##}', $x0, $y0, $r, $large, $x1, $y1)
    $path.Data = [System.Windows.Media.Geometry]::Parse($s)
}

$script:PingHist = New-Object 'System.Collections.Generic.List[int]'

function Draw-Chart {
    $w = $PingCanvas.ActualWidth; $h = $PingCanvas.ActualHeight
    $vals = $script:PingHist.ToArray()
    if ($w -lt 10 -or $h -lt 10 -or $vals.Count -lt 2) { return }
    $good = @($vals | Where-Object { $_ -ge 0 })
    $top = 40
    if ($good.Count) { $top = [math]::Max(40, ($good | Measure-Object -Maximum).Maximum * 1.3) }
    $cap = 60
    $step = $w / ($cap - 1)
    $start = $cap - $vals.Count
    $line = New-Object System.Windows.Media.PointCollection
    $fill = New-Object System.Windows.Media.PointCollection
    $fill.Add([System.Windows.Point]::new($start * $step, $h))
    for ($i = 0; $i -lt $vals.Count; $i++) {
        $v = $vals[$i]; if ($v -lt 0) { $v = $top }
        $pt = [System.Windows.Point]::new(($start + $i) * $step, $h - ($v / $top) * ($h - 8) - 4)
        $line.Add($pt); $fill.Add($pt)
    }
    $fill.Add([System.Windows.Point]::new(($start + $vals.Count - 1) * $step, $h))
    $PingLine.Points = $line
    $PingFill.Points = $fill
}

# ---------------------------------------------------------------
#  Power plan (runs on the UI thread, it's instant)
# ---------------------------------------------------------------
$guidRx = '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'

function Get-PlanName {
    $l = (powercfg.exe /getactivescheme) -join ' '
    if ($l -match '\(([^)]+)\)') { return $Matches[1] }
    return '?'
}

function Set-Plan([string]$which, [switch]$Quiet) {
    $old = Get-PlanName
    $guid = $null
    if ($which -eq 'ult') {
        $line = powercfg.exe /list | Where-Object { $_ -match 'Ultimate' } | Select-Object -First 1
        if ($line -and $line -match $guidRx) { $guid = $Matches[1] }
        if (-not $guid) { $d = (powercfg.exe -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null) -join ' '; if ($d -match $guidRx) { $guid = $Matches[1] } }
        $want = 'Ultimate'
    } elseif ($which -eq 'high') {
        $guid = 'SCHEME_MIN'; $want = 'High'
    } else {
        $guid = 'SCHEME_BALANCED'; $want = 'Balanced'
    }
    if ($guid) { powercfg.exe /setactive $guid 2>$null | Out-Null }
    $new = Get-PlanName
    if ($which -eq 'high' -and $new -notmatch 'High') {
        $d = (powercfg.exe -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null) -join ' '
        if ($d -match $guidRx) { powercfg.exe /setactive $Matches[1] 2>$null | Out-Null; $new = Get-PlanName }
    }
    if ($new -notmatch $want) {
        if (-not $Quiet) { [void][System.Windows.MessageBox]::Show($win, "That power plan isn't available on this PC. This is common on laptops with Modern Standby.", 'PC Optimizer', 'OK', 'Information') }
    } elseif ($new -ne $old) {
        Write-Note "Power plan: $old -> $new"
    }
    $sync.Plan = $new
    Update-PlanUI
    return $new
}

function Update-PlanUI {
    $p = [string]$sync.Plan
    $script:ShownPlan = $p
    $PlanNow.Text = "Current: $p"
    $PlanUlt.IsChecked  = ($p -match 'Ultimate')
    $PlanHigh.IsChecked = ($p -match 'High')
    $PlanBal.IsChecked  = ($p -match 'Balanced')
}

# ---------------------------------------------------------------
#  Pages
# ---------------------------------------------------------------
$script:NetLoaded = $false
$script:SysLoaded = $false
$script:GameLoaded = $false
$script:SetLoaded = $false
$script:GpuVendor = ''
$script:WgSelected = New-Object 'System.Collections.Generic.HashSet[string]'
$deg = [string][char]0x00B0

# ---- process manager ----
function Load-ProcList {
    if ($PrCpu.IsChecked) { $PrNote.Text = 'Measuring CPU use (1 second)...'; Start-Quick 'cpuprocs'; return }
    $PrNote.Text = 'Grouped by app. End closes every copy of it. Windows system processes are hidden so you cannot break anything.'
    $procs = Get-Process | Where-Object { $BlockList -notcontains $_.ProcessName } | Group-Object ProcessName | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; MB = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum) / 1MB); N = $_.Count }
    } | Sort-Object MB -Descending | Select-Object -First 12
    $top = [math]::Max(1, (@($procs)[0]).MB)
    $PrList.ItemsSource = @($procs | ForEach-Object {
        $lbl = "$($_.MB) MB"; if ($_.N -gt 1) { $lbl += "  ($($_.N) copies)" }
        [pscustomobject]@{ Name = $_.Name; Label = $lbl; Pct = [math]::Max(3, [math]::Round($_.MB / $top * 100)) }
    })
}

function Stop-AppByName([string]$name) {
    if (-not $name -or $BlockList -contains $name) { return }
    $n = @(Get-Process -Name $name -ErrorAction SilentlyContinue).Count
    if (-not $n) { Load-ProcList; return }
    $msg = "End $name?"; if ($n -gt 1) { $msg = "End all $n copies of $name?" }
    if (-not (Ask "$msg`n`nAnything unsaved in it will be lost." 'Warning')) { return }
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Note "Ended app: $name"
    Start-Sleep -Milliseconds 400
    Load-ProcList
}

# ---- gaming presets ----
$PresetDesc = @{
    NVIDIA = @{
        Performance = 'Max FPS and lowest input lag. NVIDIA: power = prefer maximum performance, texture filtering = high performance, low latency = on, threaded optimization = on. Windows: Ultimate (or High) power plan.'
        Balanced    = 'Smooth FPS without wasting power. NVIDIA: power = normal, texture filtering = quality, low latency = on, threaded optimization = auto. Windows: Balanced power plan.'
        Quality     = 'Best-looking image. NVIDIA: power = prefer maximum performance, texture filtering = high quality, low latency = off, threaded optimization = auto. Windows: High performance power plan.'
    }
    Other = @{
        Performance = 'Max FPS and lowest input lag. Windows: Ultimate (or High) power plan - applied now. Graphics: follow the checklist below in AMD Software.'
        Balanced    = 'Smooth FPS without wasting power. Windows: Balanced power plan - applied now. Graphics: follow the checklist below.'
        Quality     = 'Best-looking image. Windows: High performance power plan - applied now. Graphics: follow the checklist below.'
    }
}
$AmdChecklist = @{
    Performance = @(('Radeon Anti-Lag', 'On'), ('Radeon Boost', 'On'), ('Radeon Chill', 'Off'), ('Radeon Image Sharpening', 'Off'), ('Enhanced Sync', 'Off'), ('Wait for Vertical Refresh', 'Always Off'), ('Texture Filtering Quality', 'Performance'), ('Surface Format Optimization', 'On'), ('Tessellation Mode', 'AMD Optimized'))
    Balanced    = @(('Radeon Anti-Lag', 'On'), ('Radeon Boost', 'Off'), ('Radeon Chill', 'Off'), ('Radeon Image Sharpening', 'On (50%)'), ('Enhanced Sync', 'Off'), ('Wait for Vertical Refresh', 'Off, unless application specifies'), ('Texture Filtering Quality', 'Standard'), ('Surface Format Optimization', 'On'), ('Tessellation Mode', 'AMD Optimized'))
    Quality     = @(('Radeon Anti-Lag', 'Off'), ('Radeon Boost', 'Off'), ('Radeon Chill', 'Off'), ('Radeon Image Sharpening', 'On (80%)'), ('Enhanced Sync', 'On (great with FreeSync)'), ('Wait for Vertical Refresh', 'On, unless application specifies'), ('Texture Filtering Quality', 'High'), ('Surface Format Optimization', 'Off'), ('Tessellation Mode', 'Use application settings'))
}

function Update-PresetUI {
    $p = [string]$script:cfg.LastPreset
    $GpPerf.IsChecked = ($p -eq 'Performance'); $GpBal.IsChecked = ($p -eq 'Balanced'); $GpQual.IsChecked = ($p -eq 'Quality')
    $key = 'Other'; if ($script:GpuVendor -eq 'NVIDIA') { $key = 'NVIDIA' }
    if ($p) { $GpDesc.Text = $PresetDesc[$key][$p] }
    if ($script:GpuVendor -eq 'AMD' -and $p) {
        $AmdCard.Visibility = 'Visible'; $AmdTitle.Text = "AMD Software checklist - $p"
        $AmdList.ItemsSource = @($AmdChecklist[$p] | ForEach-Object { [pscustomobject]@{ Name = $_[0]; Detail = $_[1] } })
    } else { $AmdCard.Visibility = 'Collapsed' }
}

function Apply-Preset([string]$p) {
    if ($sync.Busy) { Set-Status ("Hang on - '{0}' is still running." -f $sync.Current); Update-PresetUI; return }
    $script:cfg.LastPreset = $p; Save-Config
    if ($p -eq 'Performance') { $n = Set-Plan 'ult' -Quiet; if ($n -notmatch 'Ultimate') { [void](Set-Plan 'high' -Quiet) } }
    elseif ($p -eq 'Balanced') { [void](Set-Plan 'bal' -Quiet) }
    else { [void](Set-Plan 'high' -Quiet) }
    Update-PresetUI
    Start-Task 'gpupreset' @{ preset = $p; gpuVendor = $script:GpuVendor }
}

function Open-GpuPanel {
    if ($script:GpuVendor -eq 'NVIDIA') {
        $cpl = Join-Path $env:ProgramFiles 'NVIDIA Corporation\Control Panel Client\nvcplui.exe'
        if (Test-Path -LiteralPath $cpl) { Start-Process $cpl } else { try { Start-Process 'shell:AppsFolder\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel' } catch { Set-Status 'NVIDIA Control Panel not found - get it from the Microsoft Store.' } }
    } elseif ($script:GpuVendor -eq 'AMD') {
        $amd = Join-Path $env:ProgramFiles 'AMD\CNext\CNext\RadeonSoftware.exe'
        if (Test-Path -LiteralPath $amd) { Start-Process $amd } else { Set-Status 'AMD Software not found - install it from amd.com.' }
    } else { Set-Status 'No NVIDIA or AMD graphics card found.' }
}

# ---- scheduled tasks (start with Windows, weekly clean) ----
$TaskFolder = '\PC Optimizer\'
$Me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
function New-LaunchAction([string]$arg) {
    $exeP = Join-Path $PSScriptRoot 'PC Optimizer.exe'
    if (Test-Path -LiteralPath $exeP) { return New-ScheduledTaskAction -Execute $exeP -Argument $arg -WorkingDirectory $PSScriptRoot }
    return New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`" $arg"
}
function Test-AppTask([string]$name) { return [bool](Get-ScheduledTask -TaskPath $TaskFolder -TaskName $name -ErrorAction SilentlyContinue) }
function Set-StartupTask([bool]$on) {
    if ($on) {
        $t = New-ScheduledTaskTrigger -AtLogOn -User $Me; $t.Delay = 'PT20S'
        $pr = New-ScheduledTaskPrincipal -UserId $Me -LogonType Interactive -RunLevel Highest
        $st = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName 'Start with Windows' -TaskPath $TaskFolder -Action (New-LaunchAction '-StartInTray') -Trigger $t -Principal $pr -Settings $st -Force -ErrorAction Stop | Out-Null
        Write-Note 'Start with Windows: on'
    } else {
        Unregister-ScheduledTask -TaskPath $TaskFolder -TaskName 'Start with Windows' -Confirm:$false -ErrorAction SilentlyContinue
        Write-Note 'Start with Windows: off'
    }
}
function Set-CleanTask([bool]$on) {
    if ($on) {
        $at = [datetime]::ParseExact([string]$script:cfg.CleanTime, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture)
        $t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek ([string]$script:cfg.CleanDay) -At $at
        $pr = New-ScheduledTaskPrincipal -UserId $Me -LogonType Interactive -RunLevel Highest
        $st = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
        Register-ScheduledTask -TaskName 'Weekly auto-clean' -TaskPath $TaskFolder -Action (New-LaunchAction '-AutoClean') -Trigger $t -Principal $pr -Settings $st -Force -ErrorAction Stop | Out-Null
        $SetCleanNote.Text = "Next run: every $($script:cfg.CleanDay) at $($at.ToString('h:mm tt'))."
    } else {
        Unregister-ScheduledTask -TaskPath $TaskFolder -TaskName 'Weekly auto-clean' -Confirm:$false -ErrorAction SilentlyContinue
        $SetCleanNote.Text = 'Off.'
    }
}

function Load-SettingsUI {
    $SetTray.IsChecked = [bool]$script:cfg.CloseToTray
    $SetAutoUpd.IsChecked = [bool]$script:cfg.AutoCheckUpdates
    $SetStartup.IsChecked = Test-AppTask 'Start with Windows'
    $cleanOn = Test-AppTask 'Weekly auto-clean'
    $SetClean.IsChecked = $cleanOn
    foreach ($rb in $SetDays.Children) { $rb.IsChecked = ($rb.Tag -eq $script:cfg.CleanDay) }
    foreach ($rb in $SetTimes.Children) { $rb.IsChecked = ($rb.Tag -eq $script:cfg.CleanTime) }
    if ($cleanOn) { $SetCleanNote.Text = "Runs every $($script:cfg.CleanDay)." } else { $SetCleanNote.Text = 'Off.' }
    $SetRepo.Text = [string]$script:cfg.UpdateRepo
    $SetVer.Text = "You have version $AppVersion"
}

# ---- updates ----
$script:UpdInfo = $null
function Check-Updates([switch]$Silent) {
    $repo = [string]$script:cfg.UpdateRepo
    if (-not $repo) { if (-not $Silent) { $SetUpdStatus.Text = 'Add your GitHub repo above first (example: yourname/pc-optimizer).' }; return }
    if (-not $Silent) { $SetUpdStatus.Text = "Checking $repo ..." }
    Start-Quick 'updcheck' @{ updRepo = $repo }
}
function Start-AppUpdate {
    if (-not $script:UpdInfo) { return }
    if (Ask ("Update PC Optimizer from $AppVersion to $($script:UpdInfo.Version)?`n`n$($script:UpdInfo.Notes)`n`nThe app closes for a few seconds and reopens by itself.")) {
        Start-Task 'update' @{ updRepo = [string]$script:cfg.UpdateRepo }
    }
}

# ---- tray icon ----
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$script:ReallyExit = $false
$script:TrayTipShown = $false
$tray = New-Object System.Windows.Forms.NotifyIcon
try { $tray.Icon = New-Object System.Drawing.Icon((Join-Path $PSScriptRoot 'PC_Optimizer.ico')) } catch { $tray.Icon = [System.Drawing.SystemIcons]::Application }
$tray.Text = 'PC Optimizer'
$trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
$miOpen  = $trayMenu.Items.Add('Open PC Optimizer')
$miBoost = $trayMenu.Items.Add('Boost network')
$miClean = $trayMenu.Items.Add('Clean PC')
[void]$trayMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$miExit  = $trayMenu.Items.Add('Exit')
$tray.ContextMenuStrip = $trayMenu
function Show-Main {
    $win.Show()
    if ($win.WindowState -eq 'Minimized') { $win.WindowState = 'Normal' }
    [void]$win.Activate()
}

function Show-Page([string]$p) {
    foreach ($pg in $PageDash, $PageGame, $PageNet, $PageSys, $PageTools, $PageAct, $PageSet) { $pg.Visibility = 'Collapsed' }
    switch ($p) {
        'dash' { $PageDash.Visibility = 'Visible'; $PageTitle.Text = 'Dashboard' }
        'game' {
            $PageGame.Visibility = 'Visible'; $PageTitle.Text = 'Gaming'
            if (-not $script:GameLoaded) { $script:GameLoaded = $true; Update-PresetUI }
        }
        'net'  {
            $PageNet.Visibility = 'Visible'; $PageTitle.Text = 'Network'
            if (-not $script:NetLoaded) { $script:NetLoaded = $true; Start-Quick 'netinfo' }
        }
        'sys'  {
            $PageSys.Visibility = 'Visible'; $PageTitle.Text = 'System'
            if (-not $script:SysLoaded) { $script:SysLoaded = $true; Start-Quick 'startup'; Start-Quick 'gpu'; Load-ProcList }
        }
        'tools' { $PageTools.Visibility = 'Visible'; $PageTitle.Text = 'Tools' }
        'act'  { $PageAct.Visibility = 'Visible'; $PageTitle.Text = 'Activity'; Show-LogTab ([bool]$ActTabLog.IsChecked) }
        'set'  {
            $PageSet.Visibility = 'Visible'; $PageTitle.Text = 'Settings'
            if (-not $script:SetLoaded) { $script:SetLoaded = $true; Load-SettingsUI }
        }
    }
}

# ---------------------------------------------------------------
#  Main UI refresh (runs every 400 ms)
# ---------------------------------------------------------------
$script:LastSeq = -1
$script:LastLine = ''
$script:StatusUntil = Get-Date
$script:ShownPlan = ''

function Update-UI {
    # 1. new output lines from workers
    $sb = New-Object System.Text.StringBuilder
    $line = $null
    while ($queue.TryDequeue([ref]$line)) {
        [void]$sb.AppendLine($line)
        if ($line.Trim()) { $script:LastLine = $line.Trim() }
    }
    if ($sb.Length -gt 0) {
        $ConsoleBox.AppendText($sb.ToString())
        if ($ConsoleBox.Text.Length -gt 300000) { $ConsoleBox.Text = $ConsoleBox.Text.Substring($ConsoleBox.Text.Length - 200000) }
        $ConsoleBox.ScrollToEnd()
    }

    # 2. busy / status bar
    if ($sync.Busy) {
        $BusyBar.Visibility = 'Visible'; $BusyBar.IsIndeterminate = $true
        if ((Get-Date) -gt $script:StatusUntil) { $StatusText.Text = "Running: $($sync.Current)   |   $($script:LastLine)" }
    } else {
        $BusyBar.IsIndeterminate = $false; $BusyBar.Visibility = 'Collapsed'
        if ((Get-Date) -gt $script:StatusUntil) {
            if ($script:LastLine) { $StatusText.Text = "Last: $($script:LastLine)" } else { $StatusText.Text = 'Ready' }
        }
    }

    # 3. restore point badge
    if ($sync.RpDone) { $RpStatus.Text = 'Restore point saved'; $RpDot.Fill = [System.Windows.Media.Brushes]::MediumSpringGreen }

    # 4. restore point failed -> ask to continue
    if ($sync.AskContinue -and -not $sync.Busy) {
        $n = $sync.AskContinue; $sync.AskContinue = $null
        if (Ask "Windows couldn't create a restore point (System Protection may be off, or one was made very recently).`n`nContinue without one?" 'Warning') {
            $sync.RpSkip = $true
            Start-Task $n $sync.TaskVars
        }
    }

    # 5. results from workers
    foreach ($k in @($sync.Results.Keys)) {
        $v = $sync.Results[$k]
        $sync.Results.Remove($k)
        switch ($k) {
            'NetInfo' {
                $ni = @($v)[0]
                if ($ni) {
                    $NiAdapter.Text = $ni.Adapter; $NiDevice.Text = $ni.Device; $NiSpeed.Text = $ni.Speed
                    $NiIp.Text = $ni.IPv4; $NiGw.Text = $ni.Gateway; $NiDns.Text = $ni.Dns; $NiMac.Text = $ni.Mac
                } else {
                    $NiAdapter.Text = 'No active network adapter'
                    foreach ($t in $NiDevice, $NiSpeed, $NiIp, $NiGw, $NiDns, $NiMac) { $t.Text = '' }
                }
            }
            'Wifi' {
                $w = $v
                if ($w -and $w['State'] -eq 'connected' -and $w['SSID']) {
                    $WiSsid.Text = $w['SSID']
                    $sig = 0; if ($w['Signal'] -match '(\d+)') { $sig = [int]$Matches[1] }
                    $WiSignal.Text = "$sig%"; $WiBar.Value = $sig
                    $WiRadio.Text = [string]$w['Radio type']; $WiBand.Text = [string]$w['Band']; $WiChannel.Text = [string]$w['Channel']
                    $WiRate.Text = ('Down {0} / Up {1} Mbps' -f $w['Receive rate (Mbps)'], $w['Transmit rate (Mbps)'])
                } else {
                    $WiSsid.Text = 'Not using Wi-Fi'; $WiSignal.Text = ''; $WiBar.Value = 0
                    foreach ($t in $WiRadio, $WiBand, $WiChannel, $WiRate) { $t.Text = '' }
                }
            }
            'PingCheck' {
                $r = $v.Router; $i = $v.Net
                if ($r -and $null -ne $r.Avg) { $PcRouter.Text = "$($r.Avg) ms"; $PcRouterLoss.Text = "lost $($r.Lost) of 10  ($($v.Gw))" } else { $PcRouter.Text = 'n/a'; $PcRouterLoss.Text = 'router did not reply' }
                if ($null -ne $i.Avg) { $PcNet.Text = "$($i.Avg) ms"; $PcNetLoss.Text = "lost $($i.Lost) of 10" } else { $PcNet.Text = 'n/a'; $PcNetLoss.Text = 'no reply - offline?' }
                if ($r -and (($null -ne $r.Avg -and $r.Avg -gt 20) -or $r.Lost -gt 0)) {
                    $PcVerdict.Text = 'Your router is slow to answer or dropping packets. That points to Wi-Fi or your local network. Try a cable or move closer to the router.'
                } elseif ($null -eq $i.Avg -or $i.Avg -gt 80 -or $i.Lost -gt 0) {
                    $PcVerdict.Text = 'Your router is fine but the internet side is slow or dropping. That points to your ISP or modem.'
                } else {
                    $PcVerdict.Text = 'Connection looks healthy on both sides.'
                }
            }
            'DnsTest' { $DnsList.ItemsSource = @($v); $DnsNote.Text = 'Lower is better.' }
            'Startup' {
                $StartupList.ItemsSource = @($v)
                if (-not @($v).Count) { $StartupList.ItemsSource = @([pscustomobject]@{ Name = 'Nothing found here - check Settings'; Detail = '' }) }
            }
            'Drivers' {
                $prob = @($v.Problems)
                if ($prob.Count) { $DrvList.ItemsSource = $prob; $DrvNote.Text = "$($prob.Count) device(s) need attention." }
                else { $DrvList.ItemsSource = @([pscustomobject]@{ Name = 'None - all devices OK'; Detail = '' }); $DrvNote.Text = 'All devices are working.' }
                $DrvOldList.ItemsSource = @($v.Old)
            }
            'Health' { $HealthStatus.Text = [string]$v }
            'DriverScan' {
                $list = @($v)
                $script:DuSelected.Clear()
                foreach ($d in $list) { [void]$script:DuSelected.Add([string]$d.Id) }
                $DuList.ItemsSource = $list
                $DuInstall.IsEnabled = ($list.Count -gt 0)
                if ($list.Count) { $DuNote.Text = "Found $($list.Count) update(s). Untick any you want to skip, then hit Install selected." }
                else { $DuNote.Text = 'No driver updates on Windows Update - you are up to date. Check your graphics card below.' }
            }
            'DriverInstalled' {
                $DuList.ItemsSource = $null; $DuInstall.IsEnabled = $false
                if ($v) { $DuNote.Text = 'Drivers installed. Restart your PC to finish.' } else { $DuNote.Text = 'Done - see Activity for details.' }
            }
            'Gpu' {
                $GpuList.ItemsSource = @($v)
                if (-not @($v).Count) { $GpuList.ItemsSource = @([pscustomobject]@{ Name = 'No NVIDIA / AMD / Intel graphics found'; Detail = ''; Url = 'ms-settings:windowsupdate-optionalupdates'; Btn = 'Optional updates' }) }
            }
            'NetRefresh' { Start-Quick 'netinfo' }
            'GpuVendor' {
                $script:GpuVendor = [string]$v.Vendor
                if ($v.Name) { $GpVendor.Text = "$($v.Name) detected." } else { $GpVendor.Text = 'No NVIDIA / AMD graphics card found - presets only change the Windows power plan.' }
                if ($script:GpuVendor -eq 'NVIDIA') { $GpOpenPanel.Content = 'Open NVIDIA Control Panel' }
                elseif ($script:GpuVendor -eq 'AMD') { $GpOpenPanel.Content = 'Open AMD Software' }
                Update-PresetUI
            }
            'GpuPreset' { if ($v) { $GpDesc.Text = $GpDesc.Text + '   Applied.' } else { $script:cfg.LastPreset = ''; Save-Config; Update-PresetUI; $GpDesc.Text = 'Your original GPU settings are back.' } }
            'CpuProcs' { $PrList.ItemsSource = @($v); $PrNote.Text = 'CPU use right now, grouped by app. Windows system processes are hidden.' }
            'Speed' {
                $SpDown.Text = [string]$v.Down; $SpUp.Text = [string]$v.Up
                $SpIdle.Text = if ($null -ne $v.Idle) { [string]$v.Idle } else { 'n/a' }
                $SpLoaded.Text = if ($null -ne $v.Loaded) { [string]$v.Loaded } else { 'n/a' }
                $SpGrade.Text = [string]$v.Grade
                $SpNote.Text = switch -Regex ($v.Grade) {
                    '^A' { 'Ping barely moves when the connection is busy - great for gaming while others stream.' }
                    '^B' { 'Ping rises a little under load. Fine for most games.' }
                    '^C' { 'Ping jumps a lot when someone downloads or streams. Turning on SQM / QoS in your router fixes this.' }
                    '^[DF]' { 'Heavy lag spikes under load (bufferbloat). Turn on SQM / Smart Queue / QoS in your router settings.' }
                    default { 'Done. Ping replies were blocked, so the bufferbloat grade could not be measured.' }
                }
                $SpRun.IsEnabled = $true
            }
            'Winget' {
                if ($v -is [string] -and $v -eq 'missing') { $WgNote.Text = 'winget is not installed. Get "App Installer" from the Microsoft Store, then try again.'; $WgList.ItemsSource = $null }
                else {
                    $list = @($v); $script:WgSelected.Clear()
                    foreach ($a in $list) { [void]$script:WgSelected.Add([string]$a.Id) }
                    $WgList.ItemsSource = $list
                    $WgUpdate.IsEnabled = ($list.Count -gt 0)
                    if ($list.Count) { $WgNote.Text = "$($list.Count) app(s) can be updated. Untick any you want to skip." } else { $WgNote.Text = 'All your apps are up to date.' }
                }
                $WgCheck.IsEnabled = $true
            }
            'WingetDone' { Start-Quick 'wgcheck' }
            'Disk' {
                $DsList.ItemsSource = @($v.Dirs); $DsFiles.ItemsSource = @($v.Files)
                if (-not @($v.Files).Count) { $DsFiles.ItemsSource = @([pscustomobject]@{ Name = 'No single files over 200 MB here'; Path = $v.Root; Label = ''; Pct = 0 }) }
                $DsNote.Text = "Results for $($v.Root)"
                foreach ($b in $DsC, $DsUser, $DsPick) { $b.IsEnabled = $true }
            }
            'Lan' {
                if ($v -is [string]) { $LanNote.Text = 'No active network connection.' }
                else { $LanList.ItemsSource = @($v); $LanNote.Text = "$(@($v).Count) device(s) found. Phones often hide behind a private MAC, so they show up without a maker." }
                $LanScan.IsEnabled = $true
            }
            'Security' {
                $SecList.ItemsSource = @($v.Items); $SecPorts.ItemsSource = @($v.Ports)
                if (-not @($v.Ports).Count) { $SecPorts.ItemsSource = @([pscustomobject]@{ Name = 'Nothing listening'; Detail = '' }) }
                $SecScore.Text = $v.Score; $SecNote.Text = 'Green = good, yellow = worth a look, red = fix it. Read-only - nothing was changed.'
                $SecRun.IsEnabled = $true
            }
            'UpdCheck' {
                if (-not $v.Ok) { $SetUpdStatus.Text = "Couldn't reach the update repo: $($v.Error)" }
                elseif ($v.Newer) {
                    $script:UpdInfo = $v
                    $SetUpdStatus.Text = "Version $($v.Version) is available. $($v.Notes)"
                    $SetUpdNow.Visibility = 'Visible'; $UpdBanner.Visibility = 'Visible'; $UpdBannerText.Text = "v$($v.Version) - click to install"
                } else { $SetUpdStatus.Text = "You're on the latest version ($AppVersion)."; $SetUpdNow.Visibility = 'Collapsed'; $UpdBanner.Visibility = 'Collapsed' }
            }
            default {
                if ($k -like 'Fail_*') {
                    $job = $k.Substring(5)
                    switch ($job) {
                        'speedtest' { $SpNote.Text = "Speed test failed: $v"; $SpRun.IsEnabled = $true }
                        'wgcheck' { $WgNote.Text = "winget failed: $v"; $WgCheck.IsEnabled = $true }
                        'diskscan' { $DsNote.Text = "Scan failed: $v"; foreach ($b in $DsC, $DsUser, $DsPick) { $b.IsEnabled = $true } }
                        'lan' { $LanNote.Text = "Scan failed: $v"; $LanScan.IsEnabled = $true }
                        'security' { $SecNote.Text = "Check failed: $v"; $SecRun.IsEnabled = $true }
                        'cpuprocs' { $PrNote.Text = "Couldn't read CPU use: $v" }
                    }
                }
            }
        }
    }

    # 6. live stats
    if ($null -ne $sync.Cpu) { $StCpu.Text = "$($sync.Cpu)%" }
    if ($sync.RamTotal) {
        $ru = [double]$sync.RamUsed; $rt = [double]$sync.RamTotal; $pct = $ru / $rt * 100
        $StRam.Text = ('{0:N1} GB' -f $ru); $RamPct.Text = ('{0:N0}%' -f $pct); $RamSub.Text = ('{0:N1} of {1:N0} GB' -f $ru, $rt)
        Set-Arc $RamArc $pct
    }
    if ($sync.DiskTotal) {
        $df = [double]$sync.DiskFree; $dt = [double]$sync.DiskTotal; $pct = ($dt - $df) / $dt * 100
        $StDisk.Text = ('{0:N0} GB' -f $df); $DiskPct.Text = ('{0:N0}%' -f $pct); $DiskSub.Text = ('{0:N0} GB free of {1:N0}' -f $df, $dt)
        Set-Arc $DiskArc $pct
    }
    if ($sync.Adapter) { $CnAdapter.Text = $sync.Adapter; $CnDns.Text = $sync.Dns }
    if ($sync.Plan -and $sync.Plan -ne $script:ShownPlan) { Update-PlanUI }

    # 6b. graphics card + temps
    $g = $sync.Gpu
    if ($g) {
        if ($null -ne $g.Temp) { $StGpu.Text = "$($g.Temp)$($deg)C"; $StGpuLbl.Text = 'GPU temp'; $GpuTemp.Text = "$($g.Temp)$($deg)C" }
        else { $StGpu.Text = "$($g.Load)%"; $StGpuLbl.Text = 'GPU load'; $GpuTemp.Text = 'n/a' }
        $GpuPct.Text = "$($g.Load)%"; Set-Arc $GpuArc ([double]$g.Load)
        if ($g.MemTotal -gt 0) {
            $vp = [double]$g.MemUsed / [double]$g.MemTotal * 100
            $VramPct.Text = ('{0:N0}%' -f $vp); $VramSub.Text = ('VRAM  {0:N1} of {1:N0} GB' -f ($g.MemUsed / 1024), ($g.MemTotal / 1024)); Set-Arc $VramArc $vp
        }
        if ($null -ne $g.Clock) { $GpuClock.Text = "$($g.Clock) MHz" } else { $GpuClock.Text = 'n/a' }
        if ($null -ne $g.Power) { $GpuPower.Text = ('{0:N0} W' -f $g.Power) } else { $GpuPower.Text = 'n/a' }
        if ($g.Name -and $GpuName.Text -ne $g.Name) { $GpuName.Text = $g.Name }
        if ($g.Src -eq 'nvidia') { $GpuMonNote.Text = 'Live from the NVIDIA driver.' } else { $GpuMonNote.Text = 'Load and VRAM from Windows. Temp, clock and power need an NVIDIA card (AMD/Intel do not share them with Windows).' }
    }
    if ($null -ne $sync.CpuTemp) { $CpuTemp.Text = "$($sync.CpuTemp)$($deg)C" } else { $CpuTemp.Text = 'n/a' }

    # 6c. progress text for long scans
    if ($sync.DiskProgress) { $DsNote.Text = [string]$sync.DiskProgress }
    if ($sync.LanProgress) { $LanNote.Text = [string]$sync.LanProgress }
    if ($sync.SecProgress) { $SecNote.Text = [string]$sync.SecProgress }

    # 6d. someone opened the app again -> bring this window up
    if ($script:ShowEvent.WaitOne(0)) { Show-Main }

    # 7. ping chart
    if ($sync.PingSeq -ne $script:LastSeq) {
        $script:LastSeq = $sync.PingSeq
        $pv = $sync.Ping
        if ($null -ne $pv) {
            $script:PingHist.Add([int]$pv)
            while ($script:PingHist.Count -gt 60) { $script:PingHist.RemoveAt(0) }
            if ($pv -ge 0) { $PingNow.Text = "$pv ms"; $StPing.Text = "$pv ms" } else { $PingNow.Text = 'timeout'; $StPing.Text = '--' }
            $good = @($script:PingHist | Where-Object { $_ -ge 0 })
            $drops = $script:PingHist.Count - $good.Count
            if ($good.Count) {
                $m = $good | Measure-Object -Average -Minimum -Maximum
                $PingStats.Text = ('min {0}  |  avg {1:N0}  |  max {2}  |  drops {3}' -f $m.Minimum, $m.Average, $m.Maximum, $drops)
            }
            Draw-Chart
        }
    }

    # 8. clean up finished workers
    for ($x = $script:Runners.Count - 1; $x -ge 0; $x--) {
        $rn = $script:Runners[$x]
        if ($rn.H.IsCompleted) {
            try { [void]$rn.PS.EndInvoke($rn.H) } catch {}
            try { $rn.PS.Dispose(); $rn.RS.Dispose() } catch {}
            $script:Runners.RemoveAt($x)
        }
    }
}

# ---------------------------------------------------------------
#  Wire up the window
# ---------------------------------------------------------------
$uname = $env:USERNAME
if ($uname) { $uname = $uname.Substring(0, 1).ToUpper() + $uname.Substring(1) }
$Hello.Text = "Hello, $uname!"
$PageSub.Text = (Get-Date).ToString('dddd, MMMM d')
Set-Arc $RamTrack 99.9
Set-Arc $DiskTrack 99.9

# App icon: use PC_Optimizer.ico next to the script, otherwise draw one
$icoPath = Join-Path $PSScriptRoot 'PC_Optimizer.ico'
$iconSet = $false
if (Test-Path -LiteralPath $icoPath) {
    try { $win.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create([Uri]$icoPath); $iconSet = $true } catch {}
}
if (-not $iconSet) { try {
    $g = New-Object System.Windows.Controls.Grid; $g.Width = 64; $g.Height = 64
    $e = New-Object System.Windows.Shapes.Ellipse; $e.Fill = $win.FindResource('Accent'); [void]$g.Children.Add($e)
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = [string][char]0xE945; $t.FontFamily = $win.FindResource('Icons'); $t.FontSize = 32
    $t.Foreground = [System.Windows.Media.Brushes]::White; $t.HorizontalAlignment = 'Center'; $t.VerticalAlignment = 'Center'
    [void]$g.Children.Add($t)
    $g.Measure([System.Windows.Size]::new(64, 64)); $g.Arrange([System.Windows.Rect]::new(0, 0, 64, 64)); $g.UpdateLayout()
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap 64, 64, 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($g)
    $win.Icon = $bmp
} catch {} }

# Tag the window with the app's taskbar ID + icon (and what to launch if it gets pinned)
$win.Add_SourceInitialized({
    try {
        $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper $win).Handle
        $exeP = Join-Path $PSScriptRoot 'PC Optimizer.exe'
        if (Test-Path -LiteralPath $exeP) { [PCOpt.AppId]::ForWindow($hwnd, $AppUserModelId, $exeP, "$exeP,0", 'PC Optimizer') }
        else { [PCOpt.AppId]::ForWindow($hwnd, $AppUserModelId, $null, $null, $null) }
    } catch {}
})

# Desktop shortcut (the installer makes one; this button re-creates it)
function New-DesktopShortcut {
    $lnk = Join-Path $desktop 'PC Optimizer.lnk'
    $exePath = Join-Path $PSScriptRoot 'PC Optimizer.exe'
    if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force }
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    if (Test-Path -LiteralPath $exePath) {
        $sc.TargetPath = $exePath
        $sc.IconLocation = "$exePath,0"
    } else {
        $sc.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`""
        if (Test-Path -LiteralPath $icoPath) { $sc.IconLocation = "$icoPath,0" }
        $sc.WindowStyle = 7
    }
    $sc.WorkingDirectory = $PSScriptRoot
    $sc.Description = 'PC Optimizer'
    $sc.Save()
    try { [PCOpt.AppId]::ForShortcut($lnk, $AppUserModelId) } catch {}
}

# Move the old plain-text Desktop log (from earlier versions) into the secure log
$oldLog = Join-Path $desktop 'PC_Optimizer_Log.txt'
if (Test-Path -LiteralPath $oldLog) {
    try {
        foreach ($l in (Get-Content -LiteralPath $oldLog)) { if ($l.Trim()) { Write-SecureLog ('(old log) ' + $l) } }
        Remove-Item -LiteralPath $oldLog -Force
        $queue.Enqueue('Moved your old Desktop log into the secure change log and removed the Desktop copy.')
    } catch {}
}

function Show-LogTab([bool]$showLog) {
    if ($showLog) {
        $lines = Read-SecureLog
        if ($lines.Count) { $LogBox.Text = ($lines -join "`r`n") } else { $LogBox.Text = 'No changes logged yet.' }
        $LogBox.Visibility = 'Visible'; $ConsoleBox.Visibility = 'Collapsed'
        $ActLogClear.Visibility = 'Visible'; $ActClear.Visibility = 'Collapsed'
        $LogBox.ScrollToEnd()
    } else {
        $LogBox.Visibility = 'Collapsed'; $ConsoleBox.Visibility = 'Visible'
        $ActLogClear.Visibility = 'Collapsed'; $ActClear.Visibility = 'Visible'
        $ConsoleBox.ScrollToEnd()
    }
}

# Driver update picks (checkbox state)
$script:DuSelected = New-Object 'System.Collections.Generic.HashSet[string]'

$Header.Add_MouseLeftButtonDown({ try { $win.DragMove() } catch {} })
$MinBtn.Add_Click({ $win.WindowState = 'Minimized' })
$CloseBtn.Add_Click({ $win.Close() })

$NavDash.Add_Checked({ Show-Page 'dash' })
$NavNet.Add_Checked({ Show-Page 'net' })
$NavSys.Add_Checked({ Show-Page 'sys' })
$NavAct.Add_Checked({ Show-Page 'act' })
$StatusLink.Add_Click({ $NavAct.IsChecked = $true })
$CnMore.Add_Click({ $NavNet.IsChecked = $true })

# Dashboard tiles
$RunAllBtn.Add_Click({ Start-Task 'runall' })
$TBoost.Add_Click({ Start-Task 'network' })
$TKill.Add_Click({ Start-Task 'kill' })
$TClean.Add_Click({ Start-Task 'cleanup' })
$TRestore.Add_Click({ Start-Task 'restorepoint' })
$TDrivers.Add_Click({ Start-Task 'drivers'; $NavSys.IsChecked = $true })
$THealth.Add_Click({ if (Ask "The health check takes 10-20 minutes. You can keep using your PC while it runs.`n`nStart it now?") { Start-Task 'health' } })
$TReset.Add_Click({ if (Ask "This undoes the network tweaks and resets TCP/IP + Winsock to Windows defaults. You'll need to restart after.`n`nContinue?") { Start-Task 'netreset' } })
$TUpdate.Add_Click({ Start-Process 'ms-settings:windowsupdate-optionalupdates' })

# Power plan
$PlanUlt.Add_Click({ Set-Plan 'ult' })
$PlanHigh.Add_Click({ Set-Plan 'high' })
$PlanBal.Add_Click({ Set-Plan 'bal' })

# Network page
$NetRefresh.Add_Click({ Start-Quick 'netinfo' })
$NetBoost.Add_Click({ Start-Task 'network' })
$NetReset.Add_Click({ if (Ask "This undoes the network tweaks and resets TCP/IP + Winsock to Windows defaults. You'll need to restart after.`n`nContinue?") { Start-Task 'netreset' } })
$PingRun.Add_Click({ $PcVerdict.Text = 'Pinging... (about 5 seconds)'; Start-Quick 'pingcheck' })
$DnsCf.Add_Click({ Start-Task 'dnsset' @{ dnsName = 'Cloudflare'; dnsServers = [string[]]@('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001') } })
$DnsGg.Add_Click({ Start-Task 'dnsset' @{ dnsName = 'Google'; dnsServers = [string[]]@('8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844') } })
$DnsQ9.Add_Click({ Start-Task 'dnsset' @{ dnsName = 'Quad9'; dnsServers = [string[]]@('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9') } })
$DnsAuto.Add_Click({ Start-Task 'dnsset' @{ dnsName = 'Automatic (router/ISP)'; dnsServers = $null } })
$DnsTestBtn.Add_Click({ $DnsNote.Text = 'Testing... (a few seconds)'; Start-Quick 'dnstest' })

# System page
$StartupRefresh.Add_Click({ Start-Quick 'startup' })
$StartupOpen.Add_Click({ Start-Process 'ms-settings:startupapps' })
$DrvRun.Add_Click({ $DrvNote.Text = 'Checking... see Activity for details.'; Start-Task 'drivers' })
$DrvUpdates.Add_Click({ Start-Process 'ms-settings:windowsupdate-optionalupdates' })
$DuScan.Add_Click({ $DuNote.Text = 'Searching Windows Update... (usually 30 sec - 2 min)'; $DuInstall.IsEnabled = $false; Start-Task 'driverscan' })
$DuInstall.Add_Click({
    $ids = [string[]]@($script:DuSelected)
    if (-not $ids.Count) { Set-Status 'Tick at least one driver first.'; return }
    if (Ask ("Install {0} driver update(s) from Windows Update?`n`nA restore point is made first. Your screen may flicker if a display driver is included." -f $ids.Count)) {
        $DuNote.Text = 'Installing... see Activity for live progress.'
        Start-Task 'driverinstall' @{ updateIds = $ids }
    }
})
$DuList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $cb = $e.OriginalSource
    if ($cb -is [System.Windows.Controls.CheckBox]) {
        $id = [string]$cb.Tag
        if ($cb.IsChecked) { [void]$script:DuSelected.Add($id) } else { [void]$script:DuSelected.Remove($id) }
    }
})
$GpuList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $b = $e.OriginalSource
    if ($b -is [System.Windows.Controls.Button] -and $b.Tag) { Start-Process ([string]$b.Tag) }
})
$HealthRun.Add_Click({ if (Ask "The health check takes 10-20 minutes. You can keep using your PC while it runs.`n`nStart it now?") { $HealthStatus.Text = 'Running... see Activity for live output.'; Start-Task 'health' } })

# Activity page
$ActTabLive.Add_Checked({ Show-LogTab $false })
$ActTabLog.Add_Checked({ Show-LogTab $true })
$ActLogClear.Add_Click({
    if (Ask "Delete the whole change log? This can't be undone." 'Warning') {
        try { Remove-Item -LiteralPath $logFile -Force -ErrorAction Stop } catch {}
        Write-SecureLog 'Change log cleared'
        Show-LogTab $true
    }
})
$ActRp.Add_Click({ Start-Task 'restorepoint' })
$ActRestore.Add_Click({ Start-Process rstrui.exe })
$ActClear.Add_Click({ $ConsoleBox.Clear() })
$ActShortcut.Add_Click({ try { New-DesktopShortcut; Set-Status 'Desktop shortcut created.' } catch { Set-Status "Couldn't make the shortcut: $($_.Exception.Message)" } })

$PingCanvas.Add_SizeChanged({ Draw-Chart })

# ---- Gaming page ----
$NavGame.Add_Checked({ Show-Page 'game' })
$GpPerf.Add_Click({ Apply-Preset 'Performance' })
$GpBal.Add_Click({ Apply-Preset 'Balanced' })
$GpQual.Add_Click({ Apply-Preset 'Quality' })
$GpOpenPanel.Add_Click({ Open-GpuPanel })
$GpRestore.Add_Click({
    if ($script:GpuVendor -ne 'NVIDIA') { Set-Status 'Nothing to restore - AMD/Intel settings are only changed by you in their own app.'; return }
    if (Ask 'Put your NVIDIA Control Panel settings back to how they were before the first preset?') { Start-Task 'gpurestore' }
})

# ---- Network: speed test ----
$SpRun.Add_Click({ $SpRun.IsEnabled = $false; $SpNote.Text = 'Testing... about 20 seconds. Pause big downloads for the best result.'; foreach ($t in $SpDown, $SpUp, $SpIdle, $SpLoaded, $SpGrade) { $t.Text = '...' }; Start-Quick 'speedtest' })

# ---- System: processes ----
$PrRefresh.Add_Click({ Load-ProcList })
$PrMem.Add_Checked({ Load-ProcList })
$PrCpu.Add_Checked({ Load-ProcList })
$PrList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $b = $e.OriginalSource
    if ($b -is [System.Windows.Controls.Button] -and $b.Tag) { Stop-AppByName ([string]$b.Tag) }
})

# ---- Tools ----
$NavTools.Add_Checked({ Show-Page 'tools' })
$WgCheck.Add_Click({ $WgCheck.IsEnabled = $false; $WgUpdate.IsEnabled = $false; $WgNote.Text = 'Asking winget which apps are out of date... (up to a minute)'; Start-Quick 'wgcheck' })
$WgUpdate.Add_Click({
    $ids = [string[]]@($script:WgSelected)
    if (-not $ids.Count) { Set-Status 'Tick at least one app first.'; return }
    if (Ask ("Update {0} app(s)? Close them first if they're open." -f $ids.Count)) { $WgNote.Text = 'Updating... see Activity for progress.'; $WgUpdate.IsEnabled = $false; Start-Task 'wgupdate' @{ wgIds = $ids } }
})
$WgList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $cb = $e.OriginalSource
    if ($cb -is [System.Windows.Controls.CheckBox]) {
        $id = [string]$cb.Tag
        if ($cb.IsChecked) { [void]$script:WgSelected.Add($id) } else { [void]$script:WgSelected.Remove($id) }
    }
})
function Start-DiskScan([string]$root) {
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { return }
    foreach ($b in $DsC, $DsUser, $DsPick) { $b.IsEnabled = $false }
    $DsNote.Text = "Scanning $root ... (the whole C: drive can take a few minutes)"
    $DsList.ItemsSource = $null; $DsFiles.ItemsSource = $null
    Start-Quick 'diskscan' @{ dsRoot = $root }
}
$DsC.Add_Click({ Start-DiskScan "$env:SystemDrive\" })
$DsUser.Add_Click({ Start-DiskScan $env:USERPROFILE })
$DsPick.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Pick a folder to scan'
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Start-DiskScan $dlg.SelectedPath }
})
$openHandler = [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $b = $e.OriginalSource
    if ($b -is [System.Windows.Controls.Button] -and $b.Tag) {
        $path = [string]$b.Tag
        if (Test-Path -LiteralPath $path -PathType Leaf) { Start-Process explorer.exe -ArgumentList "/select,`"$path`"" }
        elseif (Test-Path -LiteralPath $path) { Start-Process explorer.exe -ArgumentList "`"$path`"" }
    }
}
$DsList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $openHandler)
$DsFiles.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $openHandler)
$LanScan.Add_Click({ $LanScan.IsEnabled = $false; $LanNote.Text = 'Pinging every address on your network...'; $LanList.ItemsSource = $null; Start-Quick 'lan' })
$SecRun.Add_Click({ $SecRun.IsEnabled = $false; $SecNote.Text = 'Checking... (Windows Update can take up to a minute)'; $SecScore.Text = ''; Start-Quick 'security' })
$SecScan.Add_Click({ Start-Task 'defscan' })
$SecOpen.Add_Click({ Start-Process 'windowsdefender:' })

# ---- Settings ----
$NavSet.Add_Checked({ Show-Page 'set' })
$SetTray.Add_Click({ $script:cfg.CloseToTray = [bool]$SetTray.IsChecked; Save-Config })
$SetAutoUpd.Add_Click({ $script:cfg.AutoCheckUpdates = [bool]$SetAutoUpd.IsChecked; Save-Config })
$SetStartup.Add_Click({
    try { Set-StartupTask ([bool]$SetStartup.IsChecked) }
    catch { $SetStartup.IsChecked = -not $SetStartup.IsChecked; Set-Status "Couldn't change startup: $($_.Exception.Message)" }
})
$SetClean.Add_Click({
    try { Set-CleanTask ([bool]$SetClean.IsChecked); Write-Note ("Weekly auto-clean: " + $(if ($SetClean.IsChecked) { 'on' } else { 'off' })) }
    catch { $SetClean.IsChecked = -not $SetClean.IsChecked; Set-Status "Couldn't set up auto-clean: $($_.Exception.Message)" }
})
$cleanPick = [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $rb = $e.OriginalSource
    if ($rb -is [System.Windows.Controls.RadioButton] -and $rb.Tag) {
        if ($rb.GroupName -eq 'cday') { $script:cfg.CleanDay = [string]$rb.Tag } else { $script:cfg.CleanTime = [string]$rb.Tag }
        Save-Config
        if ($SetClean.IsChecked) { try { Set-CleanTask $true } catch { Set-Status "Couldn't update auto-clean: $($_.Exception.Message)" } }
    }
}
$SetDays.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $cleanPick)
$SetTimes.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $cleanPick)
$SetRepoSave.Add_Click({
    $r = $SetRepo.Text.Trim() -replace '^https?://github\.com/', '' -replace '\.git$', '' -replace '/+$', ''
    if ($r -and $r -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') { $SetUpdStatus.Text = 'That does not look like owner/name (example: yourname/pc-optimizer).'; return }
    $script:cfg.UpdateRepo = $r; Save-Config; $SetRepo.Text = $r
    if ($r) { Write-Note "Update repo set to $r"; Check-Updates } else { $SetUpdStatus.Text = 'Updates are off (no repo set).' }
})
$SetUpdCheck.Add_Click({ Check-Updates })
$SetUpdNow.Add_Click({ Start-AppUpdate })
$UpdBannerBtn.Add_Click({ Start-AppUpdate })

# ---- tray ----
$miOpen.Add_Click({ Show-Main })
$miBoost.Add_Click({ Start-Task 'network' })
$miClean.Add_Click({ Start-Task 'cleanup' })
$miExit.Add_Click({ $script:ReallyExit = $true; $win.Close() })
$tray.Add_MouseDoubleClick({ Show-Main })
$tray.Visible = $true

$win.Add_Closing({
    param($s, $e)
    if (-not $script:ReallyExit -and $script:cfg.CloseToTray) {
        $e.Cancel = $true
        $win.Hide()
        if (-not $script:TrayTipShown) { $script:TrayTipShown = $true; $tray.ShowBalloonTip(3000, 'PC Optimizer', 'Still running down here. Right-click the icon to quit.', [System.Windows.Forms.ToolTipIcon]::Info) }
        return
    }
    if ($sync.Busy) {
        if (-not (Ask ("'{0}' is still running. Close anyway?" -f $sync.Current) 'Warning')) { $e.Cancel = $true; $script:ReallyExit = $false }
    }
})
$win.Add_Closed({
    $sync.Running = $false
    $timer.Stop()
    try { $tray.Visible = $false; $tray.Dispose() } catch {}
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.InvokeShutdown()
})

# Start
try { Write-SecureLog ('===== App started on {0} =====' -f $env:COMPUTERNAME) } catch {}
$queue.Enqueue("PC Optimizer $AppVersion ready. Every change goes in the encrypted change log (Activity > Change log).")
$sync.Plan = Get-PlanName
Update-PlanUI
Show-Page 'dash'
Set-Arc $GpuTrack 99.9
Set-Arc $VramTrack 99.9
Start-Runner ($Prelude + "`n" + $Monitor) $null
Start-Quick 'gpu'
if ($script:cfg.AutoCheckUpdates -and $script:cfg.UpdateRepo) { Check-Updates -Silent }

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(400)
$timer.Add_Tick({ try { Update-UI } catch {} })
$timer.Start()

if (-not $StartInTray) { $win.Show() }
[System.Windows.Threading.Dispatcher]::Run()
$sync.Running = $false
