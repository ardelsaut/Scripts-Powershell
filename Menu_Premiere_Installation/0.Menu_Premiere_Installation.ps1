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
        [System.Windows.Forms.MessageBox]::Show("No scripts selected.", "Information", "OK", "Information")
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Running selected scripts. Please wait...", "Information", "OK", "Information")
    
        $selectedScripts | ForEach-Object {
            $scriptToRun = Join-Path $PSScriptRoot "$_.ps1"
            Write-Host "Running script: $scriptToRun"
            & $scriptToRun
        }
    
        [System.Windows.Forms.MessageBox]::Show("All selected scripts executed.", "Information", "OK", "Information")
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

# Show the PowerShell console window again
[Win32Utils]::ShowWindow($consoleWindow, [Win32Utils]::SW_SHOW)
