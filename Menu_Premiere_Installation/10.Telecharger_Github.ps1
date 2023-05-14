Write-Host "1.Menu_ALL-v2" -ForegroundColor Cyan
Write-Host "2.Scripts-Powershell"  -ForegroundColor Cyan
$TelechargementGithub = $(Write-Host "Que faut-il téléchager? Entrez '1' ou '2')" -foregroundcolor "Cyan") + $(Read-Host)

if ($TelechargementGithub -eq "1") {
    $url = "https://github.com/ardelsaut/Menu_ALL-v2/archive/refs/heads/main.zip"
    $output = "$env:USERPROFILE\Desktop\main.zip"
    $destination = "$env:USERPROFILE\Desktop"
    $MenuFolder = (Get-ChildItem -Path $destination -Filter "*Menu_ALL*" -Directory).FullName
    if (Test-Path -Path "$MenuFolder") {
        Remove-Item -Path "$MenuFolder" -Force -Recurse
    }
    Invoke-WebRequest -Uri $url -OutFile $output
    Expand-Archive -LiteralPath $output -DestinationPath $destination
    Remove-Item -Path "$output"
    explorer.exe "$MenuFolder"
} elseif ($TelechargementGithub -eq "2") {
    $url = "https://codeload.github.com/ardelsaut/Scripts-Powershell/zip/refs/heads/main"
    $output = "$env:USERPROFILE\Desktop\main.zip"
    $destination = "$env:USERPROFILE\Desktop"
    $FinalDestinationName = "$env:USERPROFILE\Desktop\Scripts-Powershell-main"
    if (Test-Path "$FinalDestinationName") {
        Remove-Item -Path "$FinalDestinationName" -Force -Recurse | Out-Null
    }
    Invoke-WebRequest -Uri $url -OutFile $output
    Expand-Archive -LiteralPath $output -DestinationPath $destination
    Remove-Item -Path "$output"
    # Move-Item -Path "$FinalDestinationName" -Destination "$destination\Scripts-Powershell"
    explorer.exe $FinalDestinationName

} else {
    Write-Host "Mauvaise entrée, recommencez si nécessaire..." -ForegroundColor Cyan
    Pause
}