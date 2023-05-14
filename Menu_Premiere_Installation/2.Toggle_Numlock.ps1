if(-not [console]::NumberLock){
    $w = New-Object -ComObject WScript.Shell;
    $w.SendKeys('{NUMLOCK}'); 
    Write-Host "Numlock activé" -ForegroundColor Green
} else {
    Write-Host "Numlock était activé" -ForegroundColor Green 
}