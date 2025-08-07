
$scriptFiles = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter *.ps1 | Sort-Object FullName

foreach ($file in $scriptFiles) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Error $($file.FullName): $_"
    }
}

# $moduleFunctions = Get-Command -CommandType Function | Where-Object {
#     $_.ScriptBlock.File -like "$PSScriptRoot*"
# } | Select-Object -ExpandProperty Name

Export-ModuleMember -Function Search-CVE, Search-Local, Get-CVE, Get-AllCVE, Initialize-Database

