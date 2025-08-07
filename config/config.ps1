function Read-ConfigFile {
    param(
        [string]$ConfigPath = "$PSScriptRoot\config.env"
    )
    
    $config = @{}
    
    Get-Content $ConfigPath | ForEach-Object {
        $line = $_.Trim()
        
        if ($line -and -not $line.StartsWith('#')) {
            if ($line -match '^([^=]+)=([^#]*)') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $config[$key] = $value
            }
        }
    }
    
    return $config
}