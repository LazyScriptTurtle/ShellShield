function Urlhaus-Connector {

    $databasePath = "<PATH>"
    $url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    $csvData = Invoke-WebRequest -Uri $url
    $csvContent = $csvData.Content
    $newCount = 0

    $headers = @( 
        "id",
        "dateadded", 
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter"
    )
    $parsedData = ConvertFrom-Csv -InputObject $csvContent -Header $headers

    Write-Host "Downloaded $($parsedData.Count) URLs"
    Import-Module PSSQLite
    try {
        Invoke-SqliteQuery -DataSource $databasePath -Query "BEGIN TRANSACTION"
        foreach ($row in $parsedData) {
            if ($row.id -like "#*") { continue }

            try {
                
                $query = "INSERT OR IGNORE INTO DOMAINS (DOMAIN, TIMESTAMP, STATUS, LAST_SEEN, THREAT, SOURCES) VALUES (@domain, @timestamp, @status, @lastSeen, @threat, @source)"


                $parameters = @{
                    domain    = $row.url
                    timestamp = $row.dateadded
                    status    = $row.url_status
                    lastSeen  = $row.last_online
                    threat    = $row.threat
                    source    = "URLhaus"
                }
            
                Invoke-SqliteQuery -DataSource $databasePath -Query $query -SqlParameters $parameters
                $newCount++
            }
            catch {
                #Write-Warning "Error inserting record: $($_.Exception.Message)"
                Write-Warning "Skipping problematic URL: $($row.url.Substring(0,50))..."
            }
        }
        Invoke-SqliteQuery -DataSource $databasePath -Query "COMMIT"

    }
    catch {
        Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Blue
        Write-Host "Rolling back..." -ForegroundColor Yellow   
        Invoke-SqliteQuery -DataSource $databasePath -Query "ROLLBACK" -ErrorAction SilentlyContinue
 
    }
    Write-Host "Statistics: $newCount successfully inserted" -ForegroundColor Green

}

