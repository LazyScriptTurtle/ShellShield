function Initialize-Database {
    param([string]$DatabasePath = $PSScriptRoot + "\..\config\ShellShield.sqlite3")
    
    # Check if database exists
    if (-not (Test-Path $DatabasePath)) {
        Write-Host "Creating new database: $DatabasePath" -ForegroundColor Yellow
        
        # Create database file
        $createIPAddressesTableQuery = @"
CREATE TABLE IF NOT EXISTS IPAddresses (
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
        $createNistTableQuery = @"
CREATE TABLE "NIST" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"CVE_ID"	TEXT,
	"PUBLISHED"	TEXT,
	"DESCRIPTIONS"	TEXT,
	"REFFERER"	TEXT,
	"SCORE"	NUMERIC,
	"SEVERITY"	TEXT,
	PRIMARY KEY("ID" AUTOINCREMENT)
);
"@
        
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createIPAddressesTableQuery
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createHashesTableQuery
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createDomainTableQuery
        Invoke-SqliteQuery -DataSource $DatabasePath -Query $createNistTableQuery
        Write-Host "Database created successfully!" -ForegroundColor Green
    }
    else {
        Write-Host "Databases already exists: $DatabasePath" -ForegroundColor Green
    }
}

