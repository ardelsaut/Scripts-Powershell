# Scripts Nono
# 10.ConnectionNasnonobouli.myds.me.ps1
# V:\03.PC\01.WINDOWS\04.COMPILATION_SCRIPTS\Menu_ALL-v2\archives\Scripts\10.ConnectionNasnonobouli.myds.me.ps1
Clear-Host
net use * /d /y | Out-Null
Clear-Host
Write-Host "Authentification Au Nas... Entrez vos identifiants:" -ForegroundColor Cyan
$usernas = Read-Host "Nom d'utilisateur"
$passwordnas = Read-Host "Mot de passe"
Write-Host "Lecteur S:\ (Web_Packages)" -ForegroundColor Cyan
net use s: \\nonobouli.myds.me\web_packages /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur T:\ (Backup)" -ForegroundColor Cyan
net use t: \\nonobouli.myds.me\backup /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur U:\ (Downloads)" -ForegroundColor Cyan
net use u: \\nonobouli.myds.me\downloads /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur V:\ (Drive)" -ForegroundColor Cyan
net use v: \\nonobouli.myds.me\Drive /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur W:\ (Web)" -ForegroundColor Cyan
net use w: \\nonobouli.myds.me\web /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur X:\ (Photo)" -ForegroundColor Cyan
net use x: \\nonobouli.myds.me\photo /u:$UserNas $passwordnas /persistent:No
Write-Host "Lecteur Y:\ (Video)" -ForegroundColor Cyan
net use y: \\nonobouli.myds.me\video /u:$UserNas $passwordnas /persistent:No
try {
    Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' | Out-Null
    }
catch
{ 
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force | Out-Null
    stop-process -name explorer –force
    Start-Sleep -Seconds 5
}
if(!$error)
{ 
}                    
pause
