function Initialize-Database {
    param([string]$DatabasePath)
    
    # Check if database exists
    if (-not (Test-Path $DatabasePath)) {
        Write-Host "Creating new database: $DatabasePath" -ForegroundColor Yellow
        
        # Create database file
        $createTableQuery = @"
CREATE TABLE IF NOT EXISTS IOC (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    IP TEXT UNIQUE NOT NULL,
    RISK NUMERIC,
    TIMESTAMP TEXT,
    SOURCE TEXT
);
"@
        
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createTableQuery
        Write-Host "Database created successfully!" -ForegroundColor Green
    } else {
        Write-Host "Database already exists: $DatabasePath" -ForegroundColor Green
    }
}
