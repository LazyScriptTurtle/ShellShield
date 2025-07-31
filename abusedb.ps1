function AbuseIPDB-Connector {

    $databasePath = "<Your Path>"
    $newCount = 0
    $updatedCount = 0

    $headers = @{
        'Key'    = '<API KEY>'
        'Accept' = 'application/json'
    }
    $params = @{
        'confidenceMinimum' = 75
        'limit'             = 100000
    }
    $response = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/blacklist" -Method Get -Headers $headers -Body $params
    Write-Host "Download $($response.data.Count) IP"
    Import-Module PSSQLite

    foreach ($item in $response.data) {
        $ip = $item.ipAddress
        $risk = $item.abuseConfidenceScore
        $timestamp = $item.lastReportedAt
        $source = "AbuseIPDB"

        $exists = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT IP FROM IOC WHERE IP = '$ip'"
        if (-not $exists) { 
            Invoke-SqliteQuery -DataSource $databasePath -Query "INSERT INTO IOC (IP, RISK, TIMESTAMP, SOURCE) VALUES ('$ip', $risk, '$timestamp', '$source')"
            $newCount++
        }
        else {
            Invoke-SqliteQuery -DataSource $databasePath -Query "UPDATE IOC SET RISK=$risk, TIMESTAMP='$timestamp' WHERE IP='$ip'"
            $updatedCount++
        }
    }
    Write-Host "Statistics: $newCount new IPs, $updatedCount updated IPs" -ForegroundColor Green
}