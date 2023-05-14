Write-Host "On edite le Registre pour Set-ExecutionPolicy Unrestricted" -ForegroundColor Cyan
$filePathunrestricted = "$env:TEMP\edit_policy_unrestricted.bat"
$content = '@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system" && (
    goto :gotAdmin
) || (
    echo Requesting administrative privileges...
    echo.
    set "batchPath=%~0"
    set "batchArgs=%*"
    setlocal DisableDelayedExpansion
    set "batchArgs=%batchArgs:"=\"%"
    set "batchArgs=%batchArgs:>=^>%"
    set "batchCmd=cmd.exe /c ""%batchPath%" %batchArgs% & pause"""
    echo %batchCmd% > "%temp%\runAsAdmin.cmd"
    start /wait "" "%temp%\runAsAdmin.cmd"
    del "%temp%\runAsAdmin.cmd" >nul 2>&1
    exit /b
)
:gotAdmin
set regFile=%temp%\powershell_policy.reg
echo Windows Registry Editor Version 5.00 >> %regFile%
echo. >> %regFile%
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell] >> %regFile%
echo "ExecutionPolicy"="Unrestricted" >> %regFile%
regedit /s %regFile%
del %regFile%'
New-Item -Path $filePathunrestricted -ItemType File -Value $content | Out-Null
cmd /c $filePathunrestricted.
Remove-Item -Path $filePathunrestricted -Recurse -Force | Out-Null
Clear-Host

# On enlève La collection de data 
Write-Host "On enlève La collection de data" -ForegroundColor Cyan
if (Get-WindowsEdition -Online | Where-Object -FilterScript {($_.Edition -like "Enterprise*") -or ($_.Edition -eq "Education")})
{
    if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force
    }
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
    Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWORD -Value 0
}
else
{
    if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force
    }
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force
    Set-Policy -Scope Computer -Path SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWORD -Value 1
}
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack))
{
    New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name MaxTelemetryAllowed -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Name ShowedToastAtLevel -PropertyType DWord -Value 1 -Force

$EnableExt = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt 
If($($EnableExt.HideFileExt) -ne 0)
{
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    REG ADD "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /VE /T REG_SZ /D "" /F
    Write-Host "File Extension explorer activé" -ForegroundColor Green
} else {
    Write-Host "File Extension explorer déja activé" -ForegroundColor Green
}

$AutoCheckSelect = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect
If($($AutoCheckSelect.AutoCheckSelect) -ne 1)
{
   New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 1 -Force
   Write-Host "Checkbox explorer activé" -ForegroundColor Green
} else {
   Write-Host "Checkbox explorer déja activé" -ForegroundColor Green
}

# On enlève L'envoi de rapports d'erreur 
Write-Host "On enlève L'envoi de rapports d'erreur" -ForegroundColor Cyan
if ((Get-WindowsEdition -Online).Edition -notmatch "Core")
			{
				Get-ScheduledTask -TaskName QueueReporting | Disable-ScheduledTask
				New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force
			}
			Get-Service -Name WerSvc | Stop-Service -Force
			Get-Service -Name WerSvc | Set-Service -StartupType Disabled
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
			{
				New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force

$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo))
{
    New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force1New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force

if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
	}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
	}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
Clear-Host

# On enlève SearchboxTaskbar
Write-Host "On enlève SearchboxTaskbar" -ForegroundColor Cyan
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarMn -PropertyType DWord -Value 0 -Force
Clear-Host

# Jpeg Wallpaped Quality max et modifications esthétiques
Write-Host "Jpeg Wallpaped Quality max et modifications esthétiques" -ForegroundColor Cyan
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates))
	{
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Force
	}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -PropertyType String -Value "%s.lnk" -Force

New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force

New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 0 -Force
Clear-Host

# On change le curseur de souris par défaut
Write-Host "On change le curseur de souris par défaut" -ForegroundColor Cyan
$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
$Parameters = @{
    Uri             = "https://github.com/farag2/Sophia-Script-for-Windows/raw/master/Misc/Cursors.zip"
    OutFile         = "$DownloadsFolder\Cursors.zip"
    UseBasicParsing = $true
    Verbose         = $true
}
Invoke-WebRequest @Parameters
if (-not (Test-Path -Path "$env:SystemRoot\Cursors\W11_dark_v2.2"))
{
    New-Item -Path "$env:SystemRoot\Cursors\W11_dark_v2.2" -ItemType Directory -Force
}
Add-Type -Assembly System.IO.Compression.FileSystem
$ZIP = [IO.Compression.ZipFile]::OpenRead("$DownloadsFolder\Cursors.zip")
$ZIP.Entries | Where-Object -FilterScript {$_.FullName -like "dark/*.*"} | ForEach-Object -Process {
    [IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$env:SystemRoot\Cursors\W11_dark_v2.2\$($_.Name)", $true)
}
$ZIP.Dispose()
Remove-Item -Path "$DownloadsFolder\Cursors.zip" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "(default)" -PropertyType String -Value "W11 Cursors Dark HD v2.2 by Jepri Creations" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name AppStarting -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\working.ani" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Arrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\pointer.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name ContactVisualization -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Crosshair -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\precision.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name CursorBaseSize -PropertyType DWord -Value 32 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name GestureVisualization -PropertyType DWord -Value 31 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Hand -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\link.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Help -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\help.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name IBeam -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\beam.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name No -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\unavailable.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name NWPen -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\handwriting.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Person -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\person.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Pin -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\pin.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name precisionhair -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\precision.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Scheme Source" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeAll -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\move.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNESW -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\dgn2.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNS -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\vert.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeNWSE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\dgn1.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name SizeWE -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\horz.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name UpArrow -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\alternate.cur" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name Wait -PropertyType ExpandString -Value "%SystemRoot%\Cursors\W11_dark_v2.2\busy.ani" -Force
if (-not (Test-Path -Path "HKCU:\Control Panel\Cursors\Schemes"))
{
    New-Item -Path "HKCU:\Control Panel\Cursors\Schemes" -Force
}
[string[]]$Schemes = (
    "%SystemRoot%\Cursors\W11_dark_v2.2\working.ani",
    "%SystemRoot%\Cursors\W11_dark_v2.2\pointer.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\precision.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\link.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\help.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\beam.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\unavailable.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\handwriting.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\pin.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\person.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\move.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\dgn2.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\vert.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\dgn1.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\horz.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\alternate.cur",
    "%SystemRoot%\Cursors\W11_dark_v2.2\busy.ani"
) -join ","
New-ItemProperty -Path "HKCU:\Control Panel\Cursors\Schemes" -Name "W11 Cursors Dark HD v2.2 by Jepri Creations" -PropertyType String -Value $Schemes -Force


[string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process {$_.Meta.Attributes["UninstallString"]}
if (-not $UninstallString)
{
    return
}
$UserEmail = Get-ItemProperty -Path HKCU:\Software\Microsoft\OneDrive\Accounts\Personal -Name UserEmail -ErrorAction Ignore
if ($UserEmail)
{
    return
}
Stop-Process -Name OneDrive, OneDriveSetup, FileCoAuth -Force -ErrorAction Ignore
[string[]]$OneDriveSetup = ($UninstallString -Replace("\s*/", ",/")).Split(",").Trim()
if ($OneDriveSetup.Count -eq 2)
{
    Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
}
else
{
    Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
}
if (Test-Path -Path $env:OneDrive)
{
    if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -eq 0)
    {
        Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Ignore

        # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa
        # The system does not move the file until the operating system is restarted
        # The system moves the file immediately after AUTOCHK is executed, but before creating any paging files
        $Script:Signature = @{
            Namespace        = "WinAPI"
            Name             = "DeleteFiles"
            Language         = "CSharp"
            MemberDefinition = @"
public enum MoveFileFlags
{
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
}
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);
public static bool MarkFileDelete (string sourcefile)
{
return MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
}
"@
        }

        # If there are some files or folders left in %OneDrive%
        if ((Get-ChildItem -Path $env:OneDrive -Force -ErrorAction Ignore | Measure-Object).Count -ne 0)
        {
            if (-not ("WinAPI.DeleteFiles" -as [type]))
            {
                Add-Type @Signature
            }

            try
            {
                Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Stop
            }
            catch
            {
                # If files are in use remove them at the next boot
                Get-ChildItem -Path $env:OneDrive -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
            }
        }
    }
    else
    {
        Start-Process -FilePath explorer -ArgumentList $env:OneDrive
    }
}

Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
$Path = @(
    "HKCU:\Software\Microsoft\OneDrive",
    "$env:ProgramData\Microsoft OneDrive",
    "$env:SystemDrive\OneDriveTemp"
)
Remove-Item -Path $Path -Recurse -Force -ErrorAction Ignore
Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false -ErrorAction Ignore
$OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -PropertyType DWord -Value 0 -Force
Stop-Process -Name explorer -Force
Start-Sleep -Seconds 3
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -PropertyType DWord -Value 1 -Force
$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\FileSyncShell64.dll" -Force
foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName)
{
    Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
    Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore
    if (Test-Path -Path $FileSyncShell64dll)
    {
        if (-not ("WinAPI.DeleteFiles" -as [type]))
        {
            Add-Type @Signature
        }
        Get-ChildItem -Path $FileSyncShell64dll -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
    }
}
Start-Sleep -Seconds 1
Start-Process -FilePath explorer
$Path = @(
    $OneDriveFolder,
    "$env:LOCALAPPDATA\OneDrive",
    "$env:LOCALAPPDATA\Microsoft\OneDrive",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
)
Remove-Item -Path $Path -Recurse -Force -ErrorAction Ignore



if ((Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
{
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
}
if ((Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
{
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 30 -Force
}

New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force

New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force

New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force

New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 0 -Force 
Delete-DeliveryOptimizationCache -Force

if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain)
{
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -PropertyType DWord -Value 1 -Force
	Set-Policy -Scope Computer -Path "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Type DWORD -Value 1
}

(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")

if (Get-NetAdapter -Physical | Where-Object -FilterScript {($_.Status -eq "Up") -and $_.MacAddress})
{
	$PhysicalAdaptersStatusUp = @((Get-NetAdapter -Physical | Where-Object -FilterScript {($_.Status -eq "Up") -and $_.MacAddress}).Name)
}

$Adapters = Get-NetAdapter -Physical | Where-Object -FilterScript {$_.MacAddress} | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
foreach ($Adapter in $Adapters)
{
	$Adapter.AllowComputerToTurnOffDevice = "Disabled"
	$Adapter | Set-NetAdapterPowerManagement
}
if ($PhysicalAdaptersStatusUp)
{
	while
	(
		Get-NetAdapter -Physical -Name $PhysicalAdaptersStatusUp | Where-Object -FilterScript {($_.Status -eq "Disconnected") -and $_.MacAddress}
	)
	{
		Write-Information -MessageData "" -InformationAction Continue
		# Extract the localized "Please wait..." string from shell32.dll
		Write-Verbose -Message ([WinAPI.GetStr]::GetString(12612)) -Verbose
		Start-Sleep -Seconds 2
	}
}

Set-WinDefaultInputMethodOverride -InputTip "0C0A:0000040A"
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force

if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
{
	New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 3 -Force

if (-not (Test-Path -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
			{
				New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
			}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force

New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force

New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force

$FirewallRules = @(
	# File and printer sharing
	"@FirewallAPI.dll,-32752",

    # Network discovery
	"@FirewallAPI.dll,-28502"
)
if (-not (Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain)
{
    Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled True

    Set-NetFirewallRule -Profile Public, Private -Name FPS-SMB-In-TCP -Enabled True
    Set-NetConnectionProfile -NetworkCategory Private
}

New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 0 -Force

if (Get-AppxPackage -Name Microsoft.WindowsTerminal)
{
    # Checking if the Terminal version supports such feature
    $TerminalVersion = (Get-AppxPackage -Name Microsoft.WindowsTerminal).Version
    if ([System.Version]$TerminalVersion -ge [System.Version]"1.11")
    {
        if (-not (Test-Path -Path "HKCU:\Console\%%Startup"))
        {
            New-Item -Path "HKCU:\Console\%%Startup" -Force
        }

        # Find the current GUID of Windows Terminal
        $PackageFullName = (Get-AppxPackage -Name Microsoft.WindowsTerminal).PackageFullName
        Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\PackagedCom\Package\$PackageFullName\Class" | ForEach-Object -Process {
            if ((Get-ItemPropertyValue -Path $_.PSPath -Name ServerId) -eq 0)
            {
                New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationConsole -PropertyType String -Value $_.PSChildName -Force
            }

            if ((Get-ItemPropertyValue -Path $_.PSPath -Name ServerId) -eq 1)
            {
                New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name DelegationTerminal -PropertyType String -Value $_.PSChildName -Force
            }
        }
    }
}

Pause