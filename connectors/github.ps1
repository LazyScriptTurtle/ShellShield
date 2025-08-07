function Get-Github {
    param (
        [bool]$ProofOfConcept = $true,
        [string]$CVE,
        [string]$configPath = $PSScriptRoot + "\..\config\config.env"
    )
    # . .\config.ps1
    $config = Read-ConfigFile -ConfigPath $configPath
    $databasePath = $config['DATABASE_PATH']

    if ($ProofOfConcept){
    $query = "(poc OR exploit OR 'proof of concept')"
    $githubQuery = "$CVE $query" 
    $encodedQuery = [System.Uri]::EscapeDataString($githubQuery) 
    $response = Invoke-RestMethod -Uri "https://api.github.com/search/repositories?q=$encodedQuery"
    }else {
        $githubQuery = "$CVE"
        $response = Invoke-RestMethod -Uri "https://api.github.com/search/repositories?q=$githubQuery"
    }


    #$responseJSON = $response | ConvertTo-Json

    foreach ($item in $response.items){
        $newItem = $item.full_name.Split("/")
        $parameters = @{
            repoName = $newItem[1]
            url = $item.html_url
            author = $newItem[0]
            cve = $CVE
            language = $item.language
            stars = $item.stargazers_count
            watchers = $item.watchers
            lastCommit = $item.pushed_at
            lastUpdate = $item.updated_at
        }

        $exists = Invoke-SqliteQuery -DataSource $databasePath -Query "SELECT CVE FROM GITHUB WHERE ( CVE = @cve AND URL = @url)" -SqlParameters $parameters
        if (-not $exists) { 
            Invoke-SqliteQuery -DataSource $databasePath -Query "INSERT INTO GITHUB (REPO_NAME, URL, AUTHOR, CVE, LANGUAGE, SCORE_STAR, WATCHERS, LAST_COMMIT_TIME, LAST_UPDATE) VALUES (@repoName, @url, @author, @cve, @language, @stars, @watchers, @lastCommit, @lastUpdate)" -SqlParameters $parameters

        }

    }

    return $response

    
}
