function AbuseIPDB-Connector {
param(
    [string]$configPath = $PSScriptRoot + "\..\config\config.env"
)
    $config = Read-ConfigFile -ConfigPath $configPath
    $databasePath = $config['DATABASE_PATH']
    $confidence = $config['CONFIDENCE_MINIMUM']
    $abuseipdbAPI = $config['ABUSEIPDB_API_KEY']
    $newCount = 0
    $updatedCount = 0




    $headers = @{
        'Key'    =  $abuseipdbAPI
        'Accept' =  'application/json'
    }
    $params = @{
        'confidenceMinimum' = $confidence
        'limit'             = 100000
    }
    $response = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/blacklist" -Method Get -Headers $headers -Body $params
    Write-Host "Download $($response.data.Count) IP"
    Import-Module PSSQLite

    foreach ($item in $response.data) {

        $parameters = @{
        ip        = $item.ipAddress
        risk      = $item.abuseConfidenceScore
        timestamp = $item.lastReportedAt
        source    = "AbuseIPDB"
        }

        $exists = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT IP FROM IPAddresses WHERE IP = @ip" -SqlParameters $parameters
        if (-not $exists) { 
            Invoke-SqliteQuery -DataSource $databasePath -Query "INSERT INTO IPAddresses (IP, RISK, TIMESTAMP, SOURCE) VALUES (@ip, @risk, @timestamp, @source)" -SqlParameters $parameters
            $newCount++
        }
        else {
            Invoke-SqliteQuery -DataSource $databasePath -Query "UPDATE IPAddresses SET RISK=@risk, TIMESTAMP=@timestamp WHERE IP=@ip" -SqlParameters $parameters
            $updatedCount++
        }
    }
        Write-Host "Statistics: $newCount new IPs, $updatedCount updated IPs" -ForegroundColor Green

    }
