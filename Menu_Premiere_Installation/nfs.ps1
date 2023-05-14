# if (!(Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "FS-NFS-Service"})) {
# Add-WindowsFeature FS-NFS-Service

# }   
#  Import-Module ServerManager
# Get-WindowsCapability -Online | Where-Object {$_.Name -like "RSAT*"}
$test = Get-WindowsCapability -Online | ? Name -like 'RSAT*'
foreach ($r in $test) {
    Add-WindowsCapability -Online -Name $r.Name
}
Import-Module -SkipEditionCheck ServerManager