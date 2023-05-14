# Enable ssh
$ConfigurationReseau = (Get-NetConnectionProfile).InterfaceAlias
Set-NetConnectionProfile -InterfaceAlias "$ConfigurationReseau" -NetworkCategory Private


Write-Host "Configuration de open ssh et autres éléments nécessaires..." -ForegroundColor Cyan
$test = Get-WindowsCapability -Online | ? Name -like 'OpenSSH.*'
foreach ($r in $test) {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Règle PareFeu 'OpenSSH-Server-In-TCP' n'existe pas, création en cours..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Output "Règle PareFeu 'OpenSSH-Server-In-TCP' a été créée et existe."
    }
}

# Enable Remote Desktop
# Get-CimInstance -Namespace "root\cimv2\TerminalServices" -Class win32_terminalservicesetting | select ServerName, AllowTSConnections

# $rd = Get-CimInstance -Namespace "root/cimv2/TerminalServices" -ClassName "Win32_TerminalServiceSetting" -ComputerName <Remote-PC>

# $rd | Invoke-CimMethod -MethodName "SetAllowTSConnections" -Arguments @{AllowTSConnections=1;ModifyFirewallException=1}
Enable-PSRemoting -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0

$computerName = $env:COMPUTERNAME
if ($computerName -match "portable") {
    $portvalue = 3391
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "$portvalue"
} elseif ($computerName -match "fixe") {
    $portvalue = 3390
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "$portvalue"
} elseif ($computerName -match "nas") {
    $portvalue = 3389
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "$portvalue"
} else {
    
    Write-Host "pas un pc de Nono, a faire soit meme..."
    
    $PortRule = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "PortNumber"
    if ($PortRule -eq "3389") {
    
        Write-Host "le port de remote desktop est actuellement: $PortRule" -ForegroundColor Cyan
    
    $ChangeRule = Read-Host "Faut-il changer le port (Y/N)(1/2)?"
        if (($ChangeRule -eq "Y") -or ($ChangeRule -eq "1")){
            Clear-Host
            $NewPortRule = Read-Host "Quel numéro de port faut-il pour remote desktop?"
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value $NewPortRule
        } elseif (($ChangeRule -eq "N") -or ($ChangeRule -eq "2")) {
            Write-Host "le port de remote desktop est actuellement: $PortRule et restera donc tel quel."
        } else {
            Write-Host "Mauvaise Entrée"
            Pause
            exit
        }
    }
}

$tsConnectionsValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
if (!($tsConnectionsValue -eq 0)) {
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
}
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
Enable-NetFirewallRule -DisplayGroup "Bureau à Distance"

New-NetFirewallRule -DisplayName 'RDPPORTLatest-TCP-In' -Profile 'Public' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $portvalue 
New-NetFirewallRule -DisplayName 'RDPPORTLatest-UDP-In' -Profile 'Public' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $portvalue 
New-NetFirewallRule -DisplayName 'RDPPORTLatest-TCP-In' -Profile 'Private' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $portvalue 
New-NetFirewallRule -DisplayName 'RDPPORTLatest-UDP-In' -Profile 'Private' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $portvalue 
New-NetFirewallRule -DisplayName 'RDPPORTLatest-TCP-In' -Profile 'Domain' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $portvalue 
New-NetFirewallRule -DisplayName 'RDPPORTLatest-UDP-In' -Profile 'Domain' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $portvalue 

