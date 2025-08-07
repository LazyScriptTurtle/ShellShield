function Format-Summary {
    param($data)
    
    Write-Host "===PROOF-OF-CONCEPTS SUMMARY===" -ForegroundColor Magenta
    Write-Host "Found: $($data.Count) repositories" -ForegroundColor White
    
    $languages = $data | Group-Object LANGUAGE | Sort-Object Count -Descending
    $langString = ($languages | ForEach-Object { 
            if ($_.Name) { "$($_.Name)($($_.Count))" } else { "Unknown($($_.Count))" }
        }) -join ", "
    Write-Host "Languages: $langString" -ForegroundColor Cyan
    
    $topStarred = $data | Sort-Object SCORE_STAR -Descending | Select-Object -First 1
    Write-Host "Top starred: $($topStarred.AUTHOR)/$($topStarred.REPO_NAME) ($($topStarred.SCORE_STAR))" -ForegroundColor Yellow
}
function Format-CVEReport {
    param($cveData)
    
    Write-Host "===CVE===" -ForegroundColor Blue
    Write-Host $cveData.CVE_ID -ForegroundColor White
    
    Write-Host "===RISK===" -ForegroundColor Red
    Write-Host "Score: $($cveData.SCORE)" -ForegroundColor White  
    Write-Host "Severity: $($cveData.SEVERITY)" -ForegroundColor White
    
    Write-Host "===Description===" -ForegroundColor Yellow
    Write-Host $cveData.DESCRIPTIONS -ForegroundColor White
    
    Write-Host "===References===" -ForegroundColor Yellow
    
    $references = $cveData.REFFERER.Split(";")  
    foreach ($ref in $references) {
        Write-Host $ref -ForegroundColor Cyan
    }
    
    Write-Host "=========" -ForegroundColor Blue
}
function Format-GitHubPoCs {
    param(
        $githubData,
        [string]$Format = 'Summary',
        [int]$Top = 5,
        [string]$SortBy = 'Stars'
    )
    
    if (-not $githubData -or $githubData.Count -eq 0) {
        Write-Host "===PROOF-OF-CONCEPTS===" -ForegroundColor Magenta
        Write-Host "No PoCs found" -ForegroundColor Gray
        return
    }
    
    switch ($SortBy) {
        'Stars' { 
            $sorted = $githubData | Sort-Object SCORE_STAR -Descending 
        }
        'Recent' { 
            $sorted = $githubData | Sort-Object LAST_UPDATE -Descending 
        }
        'Name' { 
            $sorted = $githubData | Sort-Object REPO_NAME 
        }
    }
    
    switch ($Format) {
        'Summary' { Format-Summary -data $sorted }
        'Top' { Format-TopN -data $sorted -count $Top }
        'Detailed' { Format-Detailed -data $sorted }
        'Table' { Format-CompactTable -data $sorted }
    }
}
function Format-TopN {
    param($data, [int]$count = 5)
    
    Write-Host "===TOP $count PROOF-OF-CONCEPTS===" -ForegroundColor Magenta
    

    $topRepos = $data | Select-Object -First $count
    
    for ($i = 0; $i -lt $topRepos.Count; $i++) {
        $repo = $topRepos[$i]
        $prefix = if ($i -lt $count) { "$($i+1)." }
        Write-Host "$prefix $($repo.AUTHOR)/$($repo.REPO_NAME) ( Stars: $($repo.SCORE_STAR) | Language: $($repo.LANGUAGE))" -ForegroundColor Cyan
    }
}

function Format-CompactTable {
    param($data)
    
    Write-Host "===PROOF-OF-CONCEPTS TABLE===" -ForegroundColor Magenta
    $data | Select-Object AUTHOR, REPO_NAME, SCORE_STAR, LANGUAGE | Format-Table -AutoSize
}
function Format-Detailed {
    param($data)
    
    Write-Host "===DETAILED PROOF-OF-CONCEPTS===" -ForegroundColor Magenta
    Write-Host "Found: $($data.Count) repositories" -ForegroundColor White
    Write-Host ""
    
    foreach ($repo in $data) {
        Write-Host "Repository: $($repo.AUTHOR)/$($repo.REPO_NAME)" -ForegroundColor Cyan
        Write-Host "   Stars: $($repo.SCORE_STAR) |  Watchers: $($repo.WATCHERS)" -ForegroundColor White
        Write-Host "   URL: $($repo.URL)" -ForegroundColor Gray
        Write-Host "   Language: $($repo.LANGUAGE)" -ForegroundColor Yellow
        Write-Host "   Last Commit: $($repo.LAST_COMMIT_TIME)" -ForegroundColor Green
        Write-Host "   Last Update: $($repo.LAST_UPDATE)" -ForegroundColor Green
        Write-Host "  " 
    }
}

function GetSingleCVE-FromNIST {
    param([string]$CVE)
    
    # 1. Check cache first
    $cachedCVE = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT * FROM NIST WHERE CVE_ID = @cve" -SqlParameters @{cve = $CVE}
    if ($cachedCVE) {
        return $cachedCVE
    }
    
    # 2. Call NIST API for single CVE
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE"
    try {
        $response = Invoke-RestMethod -Uri $url
        if ($response.vulnerabilities.Count -gt 0) {
            # TODO: Implement save logic
            return $response.vulnerabilities[0].cve
        }
    } catch {
        Write-Host "Failed to fetch CVE from NIST: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $null
}

function Search-CVE {
    [CmdletBinding(DefaultParameterSetName = 'Summary')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('CVE-\d{4}-\d{4,7}')]
        [string]$CVE,
        
        [switch]$ForceRefresh,
        
        [Parameter(ParameterSetName = 'Summary')]
        [switch]$Summary,
        
        [Parameter(ParameterSetName = 'Top')]
        [int]$Top = 5,
        
        [Parameter(ParameterSetName = 'Detailed')]  
        [switch]$Detailed,
        
        [Parameter(ParameterSetName = 'Table')]
        [switch]$Table,
        
        [ValidateSet('Stars', 'Recent', 'Name')]
        [string]$SortBy = 'Stars',

        [string]$configPath = $PSScriptRoot + "\..\config\config.env"
    )
    
    # . ..\config\config.ps1
    # . ..\connectors\github.ps1
    # . ..\connectors\nistcve.ps1

    $config = Read-ConfigFile -ConfigPath $configPath
    $databasePath = $config['DATABASE_PATH']

    $githubData = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT * FROM GITHUB WHERE CVE = @cve" -SqlParameters @{cve = $CVE }

    $formatType = 'Summary'
    if ($Top) { $formatType = 'Top' }
    if ($Detailed) { $formatType = 'Detailed' } 
    if ($Table) { $formatType = 'Table' }
    
    if ($githubData -and $githubData.Count -gt 0 -and -not $ForceRefresh) {
        Write-Host " Found PoCs in cache!" -ForegroundColor Green
        $cachedCVE = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT * FROM NIST WHERE CVE_ID = @cve" -SqlParameters @{cve = $CVE }
        
        Format-GitHubPoCs -githubData $githubData -Format $formatType -Top $Top -SortBy $SortBy
        if ($cachedCVE) {
            Format-CVEReport -cveData $cachedCVE
        }
    }
    else {
        # WARIANT 1: Brak cache - KOMPLETNA LOGIKA
        Write-Host " No PoCs in cache, searching GitHub..." -ForegroundColor Yellow  
        
        # 1. Search GitHub
        $githubResponse = Get-Github -CVE $CVE -ProofOfConcept $true
        
        # 2. Check results
        if ($githubResponse.total_count -gt 0) {
            Write-Host " Found $($githubResponse.total_count) PoCs on GitHub!" -ForegroundColor Green
            
            # 3. Get fresh GitHub data from database (just inserted)
            $freshGithubData = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT * FROM GITHUB WHERE CVE = @cve" -SqlParameters @{cve = $CVE }
            
            # 4. Get NIST data (from cache or API)
            $nistData = GetSingleCVE-FromNIST -CVE $CVE
            
            # 5. Format results
            Format-GitHubPoCs -githubData $freshGithubData -Format $formatType -Top $Top -SortBy $SortBy
            if ($nistData) {
                Format-CVEReport -cveData $nistData
            }
        }
        else {
            Write-Host " No PoCs found on GitHub for $CVE " -ForegroundColor Red
            
            # Still show NIST info if available
            $nistData = GetSingleCVE-FromNIST -CVE $CVE
            if ($nistData) {
                Write-Host " NIST Information:" -ForegroundColor Yellow
                Format-CVEReport -cveData $nistData
            }
            else {
                Write-Host " No information found for $CVE " -ForegroundColor Red
            }
        }
    }
}