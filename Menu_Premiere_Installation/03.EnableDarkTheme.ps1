$appUseLightTheme = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme
If($($appUseLightTheme.AppsUseLightTheme) -ne 0)
{
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type DWord -Force
    Write-Host "Dark Theme applications est activé" -ForegroundColor Green
} else {
    Write-Host "Dark Theme applications est déja activé" -ForegroundColor Green   
}

$systemUsesLightTheme = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme
If($($systemUsesLightTheme.SystemUsesLightTheme) -ne 0)
{
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type DWord -Force
    Write-Host "Dark Theme Sytème est activé" -ForegroundColor Green
} else {
    Write-Host "Dark Theme Sytème est déja activé" -ForegroundColor Green
}