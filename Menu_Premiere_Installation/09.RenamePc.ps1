Write-Host "A la suite, le PC va redémarrer... " -foregroundcolor "Magenta"
$continue = $(Write-Host "Voulez-vous continuer ?(Y/N)" -foregroundcolor "Cyan") + $(Read-Host)
if ($continue -eq "Y" -or $continue -eq "y") {
    Clear-Host
    $NouveauNomPc = $(Write-Host "Quel est le nouveau nom à attribuer ?" -foregroundcolor "Yellow") + $(Read-Host)
    Write-Host "Le pc redémarre..." -ForegroundColor Cyan
    Start-Sleep -Seconds 5
    Rename-Computer -NewName "$NouveauNomPc" -Restart
} elseif ($continue -eq "N" -or $continue -eq "n") {
    Clear-Host
    Write-Host "Opération annulée." -ForegroundColor Cyan
} else {
    Write-Host "Entrée invalide. Veuillez entrer Y ou N." -ForegroundColor Red
}