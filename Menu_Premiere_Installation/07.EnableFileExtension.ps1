$EnableExt = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt 
If($($EnableExt.HideFileExt) -ne 0)
{
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    REG ADD "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /VE /T REG_SZ /D "" /F
    Write-Host "File Extension explorer activé" -ForegroundColor Green
} else {
    Write-Host "File Extension explorer déja activé" -ForegroundColor Green
}
