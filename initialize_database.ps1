function Initialize-Database {
    param([string]$DatabasePath)
    
    # Check if database exists
    if (-not (Test-Path $DatabasePath)) {
        Write-Host "Creating new database: $DatabasePath" -ForegroundColor Yellow
        
        # Create database file
        $createIocTableQuery = @"
CREATE TABLE IF NOT EXISTS IOC (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    IP TEXT UNIQUE NOT NULL,
    RISK NUMERIC,
    TIMESTAMP TEXT,
    SOURCE TEXT
);
"@
        $createHashesTableQuery = @"
CREATE TABLE "HASHES" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"NAME"	TEXT,
	"TYPE"	TEXT,
	"SHA256"	TEXT UNIQUE,
	"SHA1"	TEXT UNIQUE,
	"MD5"	TEXT UNIQUE,
	"FIRST_SEEN"	TEXT,
	"ORIG_COUNTRY"	TEXT,
	"SOURCE"	TEXT,
	PRIMARY KEY("ID")
);
"@
        $createDomainTableQuery = @"
CREATE TABLE "DOMAINS" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"DOMAIN"	TEXT NOT NULL UNIQUE,
	"TIMESTAMP"	TEXT,
	"STATUS"	TEXT,
	"LAST_SEEN"	TEXT,
	"THREAT"	TEXT,
	"SOURCES"	TEXT,
	PRIMARY KEY("ID")
);
"@
        
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createIoCTableQuery
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createHashesTableQuery
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createDomainTableQuery
        Write-Host "Database created successfully!" -ForegroundColor Green
    }
    else {
        Write-Host "Databases already exists: $DatabasePath" -ForegroundColor Green
    }
}
