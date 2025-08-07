function Get-AllCVE {
    param (
        [string]$configPath = $PSScriptRoot + "\..\config\config.env"
    )
    # . .\config.ps1
    $config = Read-ConfigFile -ConfigPath $configPath
    
   
    if ($config["START_DATE"] -eq "now") {
        $currentDate = Get-Date
    }
    else {
        $currentDate = [DateTime]::Parse($config["START_DATE"])
    }
    
    if ($config["END_DATE"] -eq "now") {
        $endDate = Get-Date
    }
    else {
        $endDate = [DateTime]::Parse($config["END_DATE"])  
    }
    $totalPeriods = [math]::Floor(($endDate - $currentDate).TotalDays / 120)

    $periodNumber = 1
    
    while ($currentDate -lt $endDate) { 
        $periodEnd = $currentDate.AddDays(120) 
        if ($periodEnd -gt $endDate) { $periodEnd = $endDate }
        
        $startTimePeriod = Get-Date -Format "HH:mm:ss"
        Write-Host "Time Start : $startTimePeriod "
        Write-Host "Period $periodNumber/$totalPeriods : $($currentDate.ToString('yyyy-MM-dd')) to $($periodEnd.ToString('yyyy-MM-dd'))"
        
        Get-CVE -startDate $currentDate -endDate $periodEnd  
        
        Start-Sleep -Seconds 2 
        $currentDate = $periodEnd.AddDays(1) 
        $periodNumber++
    }
}

function Get-CVE {
    param (
        [string]$configPath = ".\config.env",
        [DateTime]$startDate,
        [DateTime]$endDate
    )
    . .\config.ps1
    $config = Read-ConfigFile -ConfigPath $configPath
    $databasePath = $config['DATABASE_PATH']
    $apiKey = $config['NIST_API_KEY']
    $startIndex = 0
    $resultsPerPage = 2000
    $allVulnerabilities = @()

    $headers = @{
        "apiKey" = $apiKey
    }

    $startDateStr = $startDate.ToString("yyyy-MM-ddTHH:mm:ss.fff")
    $endDateStr = $endDate.ToString("yyyy-MM-ddTHH:mm:ss.fff")
    

    do {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$startDateStr&pubEndDate=$endDateStr&startIndex=$startIndex&resultsPerPage=$resultsPerPage"
        
        Write-Host "Fetching page: startIndex=$startIndex"
        $response = Invoke-RestMethod -Uri $url -Headers $headers
        
        Write-Host "Retrieved: $($response.vulnerabilities.Count) / Total: $($response.totalResults)"
        
        $allVulnerabilities += $response.vulnerabilities
        $startIndex += $resultsPerPage
        Start-Sleep -Seconds 1
        
    } while ($startIndex -lt $response.totalResults)

    # $totalFetched = $allVulnerabilities.Count
    # $filteredByStatus = 0
    # $processedSuccessfully = 0
    # $duplicates = 0
    # $sqlErrors = 0
    
    #Write-Host "Starting processing $totalFetched CVE..." -ForegroundColor Green

    foreach ($item in $allVulnerabilities) {

        # if ($filteredByStatus % 500 -eq 0 -and $filteredByStatus -gt 0) {
        #    Write-Host "Processed $filteredByStatus CVE so far..." -ForegroundColor Yellow
        # }
        
        if ($item.cve.vulnStatus -eq "Modified" -or $item.cve.vulnStatus -eq "Analyzed") {
            $filteredByStatus++

            $cveID = $item.cve.id
            $published = $item.cve.published
            $desc = $item.cve.descriptions[0].value
            $score = $null
            $severity = $null
            
            if ($item.cve.metrics.cvssMetricV31 -and $item.cve.metrics.cvssMetricV31.Count -gt 0) {
                $score = $item.cve.metrics.cvssMetricV31[0].cvssData.baseScore
                $severity = $item.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
            }
            
            $reference = $item.cve.references.url -join ";"

            $parameters = @{
                cveID       = $cveID
                published   = $published
                description = $desc
                ref         = $reference
                score       = $score
                severity    = $severity
            }

            $exists = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT CVE_ID FROM NIST WHERE CVE_ID = @cveID" -SqlParameters $parameters
            if (-not $exists) {
                try {
                    Invoke-SqliteQuery -DataSource $databasePath -Query "INSERT INTO NIST (CVE_ID, PUBLISHED, DESCRIPTIONS, REFFERER, SCORE, SEVERITY) VALUES (@cveID, @published, @description, @ref, @score, @severity)" -SqlParameters $parameters
                    $processedSuccessfully++
                }
                catch {
                    $sqlErrors++
                    Write-Host "SQL Error for $cveID : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            else {
                $duplicates++
            }
        }
    }
    
    # Write-Host "=== PERIOD STATISTICS ===" -ForegroundColor Yellow
    # Write-Host "Total fetched from API: $totalFetched"
    # Write-Host "Passed status filter: $filteredByStatus"  
    # Write-Host "Successfully inserted: $processedSuccessfully"
    # Write-Host "Duplicates found: $duplicates"
    # Write-Host "SQL errors: $sqlErrors"
    # Write-Host "===========================" -ForegroundColor Yellow
}