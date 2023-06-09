


# #####
# #LOG#
# #####
# $destinationFolder1 = "C:\Logs\Nas"
# if (!(Test-Path -path $destinationFolder1 -ErrorAction SilentlyContinue))
# {
#     New-Item $destinationFolder1 -Type Directory -Force
# }
# Start-Transcript -Path "$destinationFolder1\Nas_$(Get-Date -UFormat "%d-%m-%Y_%H.%M.%S").txt" 
# Get-Childitem -Path $destinationFolder1 -Recurse -Force -File  | Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 | Remove-Item -Force

# #####

Clear-Host
if((cmdkey /list | Select-String -Pattern "192.168.1.54") -eq "")
{
    Write-Warning -Message "-------------------------------------" -Verbose
    Write-Warning -Message "Entrez Vos informations de Connection" -Verbose
    Write-Warning -Message "-------------------------------------" -Verbose
    $credential = $host.ui.PromptForCredential("Authentification Au Nas", "Quel est le mot de passe?.", "Nono", "")
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $UserNas = ($credential.UserName)
    cmdkey /add:192.168.1.54 /user:$UserNas /pass:$PlainPassword | Out-Null
    cmdkey /add:nonobouli.myds.me /user:$UserNas /pass:$PlainPassword | Out-Null  
}
$computer = "192.168.1.54"
if( ( (test-path 'S:\','T:\','U:\','V:\','W:\','X:\','Y:\') -eq $false).Count )
{

@{
    WebApp         = 'S:\'
    Backup         = 'T:\'
    Downloads      = 'U:\'
    Drive          = 'V:\'
    Web            = 'W:\'
    Photo          = 'X:\'
    Vidéo          = 'Y:\'

}.GetEnumerator() | ForEach-Object {
    if (Test-Path -LiteralPath $_.Value) {
        '{0,-10} - Trouvé.' -f $_.Key
    }
    else {
        '{0,-10} - Erreur!! Pas Trouvé. Reconnection!' -f $_.Key
    }
}

if ( Test-Connection -ComputerName $computer -BufferSize 8 -Count 1 -ea 0 -quiet )
  {
  net use * /d /y | Out-Null

      Write-Host "Nas found on local wifi" -ForegroundColor DarkYellow
      Write-Host "Lecteur S:\ (Web_Packages)" -ForegroundColor Cyan
      net use s: \\192.168.1.54\web_packages /persistent:No
      Write-Host "Lecteur T:\ (Backup)" -ForegroundColor Cyan
      net use t: \\192.168.1.54\backup /persistent:No
      Write-Host "Lecteur U:\ (Downloads)" -ForegroundColor Cyan
      net use u: \\192.168.1.54\downloads /persistent:No
      Write-Host "Lecteur V:\ (Drive)" -ForegroundColor Cyan
      net use v: \\192.168.1.54\Drive /persistent:No
      Write-Host "Lecteur W:\ (Web)" -ForegroundColor Cyan
      net use w: \\192.168.1.54\web /persistent:No
      Write-Host "Lecteur X:\ (Photo)" -ForegroundColor Cyan
      net use x: \\192.168.1.54\photo /persistent:No
      Write-Host "Lecteur Y:\ (Video)" -ForegroundColor Cyan
      net use y: \\192.168.1.54\video /persistent:No
  }else
    {
      net use * /d /y | Out-Null
      Write-Host "Nas found on local wifi" -ForegroundColor DarkYellow
      Write-Host "Lecteur S:\ (Web_Packages)" -ForegroundColor Cyan
      net use s: \\nonobouli.myds.me\web_packages /persistent:No
      Write-Host "Lecteur T:\ (Backup)" -ForegroundColor Cyan
      net use t: \\nonobouli.myds.me\backup /persistent:No
      Write-Host "Lecteur U:\ (Downloads)" -ForegroundColor Cyan
      net use u: \\nonobouli.myds.me\downloads /persistent:No
      Write-Host "Lecteur V:\ (Drive)" -ForegroundColor Cyan
      net use v: \\nonobouli.myds.me\Drive /persistent:No
      Write-Host "Lecteur W:\ (Web)" -ForegroundColor Cyan
      net use w: \\nonobouli.myds.me\web /persistent:No
      Write-Host "Lecteur X:\ (Photo)" -ForegroundColor Cyan
      net use x: \\nonobouli.myds.me\photo /persistent:No
      Write-Host "Lecteur Y:\ (Video)" -ForegroundColor Cyan
      net use y: \\nonobouli.myds.me\video /persistent:No
    }
   
 }else
 {
 write-host "Le Nas est déja connecté, rien á faire!" -ForegroundColor Green
 }
  $destinationFolder = "$env:userprofile\Documents\1.Scripts\1.Nas"
  if (!(Test-Path -path $destinationFolder\Nas.ps1 -ErrorAction SilentlyContinue))
  {
      New-Item "$destinationFolder" -Type Directory -Force | Out-Null
    #   New-Item "$destinationFolder\3.Nas.ps1" -ItemType "File" -Force | Out-Null
    #   Get-Content "$PSCommandPath" > "$destinationFolder\3.Nas.ps1"
    Get-Content "$PSCommandPath" | Set-Content -Encoding UTF8 -Path "$destinationFolder\3.Nas.ps1" -Force
    }
  if(!(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Nas -ErrorAction SilentlyContinue))
  {
  New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Nas -PropertyType ExpandString -Value 'powershell.exe -ExecutionPolicy Bypass -File "%UserProfile%\Documents\Applications_Portables\Scripts\Nas\Nas.ps1"' -Force
  }
  
$error.clear()
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