$DisableUac = Get-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA 
If($($DisableUac.EnableLUA) -ne 0)
{
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    Write-Host "Uac est déssactivé" -ForegroundColor Green
} else {
    Write-Host "Uac est déja déssactivé" -ForegroundColor Green
}
