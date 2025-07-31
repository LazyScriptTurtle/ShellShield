function Search-Local {

    $local = Get-NetTCPConnection | Select-Object -ExpandProperty RemoteAddress -Unique

    $exclusions = @(
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::"
    )

    foreach ($item in $local) {
        $ip = $item  
    
        if ($exclusions -notcontains $ip) {
            Write-Host "Checking IP: $ip"
            $result = Invoke-SqliteQuery -DataSource "D:\SQLite\Baza\nowe.sqlite3" -Query "SELECT * FROM IOC WHERE IP = '$ip'"
            Write-Host " "
        
            if ($result) {
                $resultArray = @($result)
                Write-Host "Results from database: $($resultArray.Count)"
                Write-Host "ALERT! Malicious connection to: $ip" -ForegroundColor Red
            
                # Display the details
                foreach ($record in $resultArray) {
                    Write-Host "  IP: $($record.IP)" -ForegroundColor Yellow
                    Write-Host "  Risk: $($record.RISK)" -ForegroundColor Yellow
                    Write-Host "  Timestamp: $($record.TIMESTAMP)" -ForegroundColor Yellow
                    Write-Host "  Source: $($record.SOURCE)" -ForegroundColor Yellow
                }
            }# else {
            #     Write-Host "IP $ip not found in database"
            #     Write-Host " "
            # }
        }
    }
}