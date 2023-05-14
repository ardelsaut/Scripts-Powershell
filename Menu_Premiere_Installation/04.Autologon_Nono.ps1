# Scripts Nono
# 3.Autologon_Nono
# "V:\03.PC\01.WINDOWS\04.COMPILATION_SCRIPTS\Menu_ALL-v2\archives\Scripts\3.Autologon_Nono.ps1"
Clear-Host

if(!(($env:USERNAME) -eq "nono") -and ((Get-ItemPropertyValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon) -eq "1"))
{
    $usernamewin = Read-Host "Nom d'utilisateur"
    $passwordwin = Read-Host "Mot de passe"
    Clear-Host
    Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $usernamewin
    Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $passwordwin
    Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value "1"
    Clear-Host
    Write-Host "Autologon activé" -ForegroundColor Green
} else{
        Write-Host "Autologon déjà activé" -ForegroundColor Green
}
