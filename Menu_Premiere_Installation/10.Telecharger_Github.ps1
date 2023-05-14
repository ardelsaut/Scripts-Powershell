# Write-Host "1.Menu_ALL-v2" -ForegroundColor Cyan
# Write-Host "2.Scripts-Powershell"  -ForegroundColor Cyan
# $TelechargementGithub = $(Write-Host "Que faut-il téléchager? Entrez '1' ou '2')" -foregroundcolor "Cyan") + $(Read-Host)

# if ($TelechargementGithub -eq "1") {
#     $url = "https://github.com/ardelsaut/Menu_ALL-v2/archive/refs/heads/main.zip"
#     $output = "$env:USERPROFILE\Desktop\main.zip"
#     $destination = "$env:USERPROFILE\Desktop"
#     $MenuFolder = (Get-ChildItem -Path $destination -Filter "*Menu_ALL*" -Directory).FullName
#     if (Test-Path -Path "$MenuFolder") {
#         Remove-Item -Path "$MenuFolder" -Force -Recurse
#     }
#     Invoke-WebRequest -Uri $url -OutFile $output
#     Expand-Archive -LiteralPath $output -DestinationPath $destination
#     Remove-Item -Path "$output"
#     explorer.exe "$MenuFolder"
# } elseif ($TelechargementGithub -eq "2") {
#     $url = "https://codeload.github.com/ardelsaut/Scripts-Powershell/zip/refs/heads/main"
#     $output = "$env:USERPROFILE\Desktop\main.zip"
#     $destination = "$env:USERPROFILE\Desktop"
#     $FinalDestinationName = "$env:USERPROFILE\Desktop\Scripts-Powershell-main"
#     if (Test-Path "$FinalDestinationName") {
#         Remove-Item -Path "$FinalDestinationName" -Force -Recurse | Out-Null
#     }
#     Invoke-WebRequest -Uri $url -OutFile $output
#     Expand-Archive -LiteralPath $output -DestinationPath $destination
#     Remove-Item -Path "$output"
#     # Move-Item -Path "$FinalDestinationName" -Destination "$destination\Scripts-Powershell"
#     explorer.exe $FinalDestinationName

# } else {
#     Write-Host "Mauvaise entrée, recommencez si nécessaire..." -ForegroundColor Cyan
#     Pause
# }



Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Win32Utils
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
    
        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;
        public const int SW_MINIMIZE = 6;
    }
"@
# Minimize the PowerShell console window
$consoleWindow = [Win32Utils]::GetConsoleWindow()
[Win32Utils]::ShowWindow($consoleWindow, [Win32Utils]::SW_MINIMIZE)
Clear-Host
$scriptName = Split-Path -Leaf $PSCommandPath
$scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | Where-Object { $_.FullName -ne "$PSScriptRoot\$scriptName" }
Add-Type -AssemblyName System.Windows.Forms
$checkBoxes = @{}
$i = 0
$scripts | ForEach-Object {
    $checkBoxes[$i] = New-Object System.Windows.Forms.CheckBox
    $checkBoxes[$i].Text = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
    $checkBoxes[$i].Top = 30 * $i
    $checkBoxes[$i].Left = 10
    $checkBoxes[$i].Width = 500
    $i++
}
$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = "Run Selected Scripts"
$runButton.Top = ($checkBoxes.Count * 30) + 20
$runButton.Left = 10
$runButton.Width = 150
$runButton.Add_Click({
$selectedScripts = $checkBoxes.Values | Where-Object { $_.Checked } | ForEach-Object { $_.Text } 
    if ($selectedScripts.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No scripts selected.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
$selectedScriptsText = $selectedScripts -join "`n"
$form = New-Object System.Windows.Forms.Form
$form.Text = "Confirmation lancement"
$form.Size = New-Object System.Drawing.Size(300, ($selectedScripts.Count * 180))
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(50, 20)
$label.Size = New-Object System.Drawing.Size(200, ($selectedScripts.Count * 30))
$label.Text = $selectedScriptsText
$button1 = New-Object System.Windows.Forms.Button
$button1.Location = New-Object System.Drawing.Point(50, ($selectedScripts.Count * 70))
$button1.Size = New-Object System.Drawing.Size(100, 30)
$button1.Text = "Oui, Lancer"
$button1.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$button2 = New-Object System.Windows.Forms.Button
$button2.Location = New-Object System.Drawing.Point(150, ($selectedScripts.Count * 70))
$button2.Size = New-Object System.Drawing.Size(100, 30)
$button2.Text = "Non, Annulé"
$button2.DialogResult = [System.Windows.Forms.DialogResult]::No
$form.Controls.Add($label)
$form.Controls.Add($button1)
$form.Controls.Add($button2)
$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    $selectedScripts | ForEach-Object {
        $scriptToRun = Join-Path $PSScriptRoot "$_.ps1"
        Write-Host "Running script: $scriptToRun"
        & $scriptToRun
    } 
    [System.Windows.Forms.MessageBox]::Show("All selected scripts executed.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
elseif ($result -eq [System.Windows.Forms.DialogResult]::No) {
    Write-Host "Opération pour: `n$selectedScriptsText `nToutes les opérations annulées"
}
    }
})
$form = New-Object System.Windows.Forms.Form
$form.Text = "$scriptName"
$form.Width = 550
$form.Height = ($checkBoxes.Count * 30) + 100
$checkBoxes.Values | ForEach-Object {
    $form.Controls.Add($_)
}
$form.Controls.Add($runButton)
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
[Win32Utils]::ShowWindow($consoleWindow, [Win32Utils]::SW_SHOW)