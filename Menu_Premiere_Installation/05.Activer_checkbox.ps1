# Scripts Nono
# 2.EnableDarkTheme
# "V:\03.PC\01.WINDOWS\04.COMPILATION_SCRIPTS\Menu_ALL-v2\archives\Scripts\2.EnableDarkTheme.ps1"
Clear-Host
$AutoCheckSelect = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect
If($($AutoCheckSelect.AutoCheckSelect) -ne 1)
{
   New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 1 -Force
   Write-Host "Checkbox explorer activé" -ForegroundColor Green
} else {
   Write-Host "Checkbox explorer déja activé" -ForegroundColor Green
}