# ShellShield 
**PowerShell Threat Intelligence Platform**

A lightweight, automated threat detection system built in PowerShell that collects malicious IP addresses from threat intelligence feeds and monitors your network connections for potential threats.

## 🚀 Features

- **Automated Threat Intelligence Collection**: Fetches malicious IPs from AbuseIPDB
- **Local SQLite Database**: Stores threat indicators for fast lookups
- **Active Connection Monitoring**: Scans network connections against threat database
- **Duplicate Management**: Smart handling of existing vs new threat indicators
- **Statistics & Reporting**: Detailed stats on new/updated threats
- **Zero-Config Database**: Automatic database initialization
- **Scheduled Execution**: Configurable automated threat feeds updates
- **GitHub Ready**: Portable project structure for easy deployment

## 📋 Requirements

- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **PSSQLite Module** (auto-installed)
- **AbuseIPDB API Key** (free tier: 1000 requests/day)
- **Internet Connection** for threat feed updates

## 🔧 Installation

### 1. Clone Repository
```powershell
git clone https://github.com/yourusername/PSGuard.git
cd PSGuard
```

### 2. Install Required Module
```powershell
Install-Module -Name PSSQLite -Force
Import-Module PSSQLite
```

### 3. Get AbuseIPDB API Key
1. Register at [abuseipdb.com](https://www.abuseipdb.com/)
2. Navigate to API section
3. Copy your API key
4. Replace `YOUR_API_KEY` in the script

## ⚙️ Configuration

### Database Settings
```powershell
$Config = @{
    DatabasePath = ".\threats.db"
    ConfidenceMinimum = 75      # Min risk score (1-100)
    MaxResults = 10000          # Max IPs per API call
}
```


## 📊 Database Schema

```sql
CREATE TABLE IOC (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    IP TEXT UNIQUE NOT NULL,
    RISK NUMERIC,
    TIMESTAMP TEXT,
    SOURCE TEXT
);
```

## 🗺️ Roadmap

### Phase 1: Core Functionality ✅
- [x] AbuseIPDB integration
- [x] SQLite database storage
- [x] Network connection monitoring
- [x] Duplicate IP handling
- [x] Basic statistics

### Phase 2: Enhanced Features 🚧
- [ ] **Multiple Threat Sources**
  - VirusTotal API integration
  - AlienVault OTX feeds
  - Custom IOC imports
- [ ] **Advanced Monitoring**
  - Real-time connection monitoring
  - Geolocation enrichment
  - ASN/Organization lookup
- [ ] **Reporting & Alerts**
  - HTML dashboard generation
  - Email/Slack notifications
  - CSV/JSON export capabilities

### Phase 3: Intelligence & Automation 📋
- [ ] **Threat Hunting**
  - Historical connection analysis
  - Pattern detection algorithms
  - Attribution tracking
- [ ] **Integration Capabilities**
  - SIEM forwarding (Splunk, ELK)
  - REST API endpoints
  - Windows Event Log integration
- [ ] **Machine Learning**
  - Anomaly detection
  - Risk scoring improvements
  - Predictive threat modeling

### Phase 4: Enterprise Features 🎯
- [ ] **Multi-Source Intelligence**
  - Commercial feed integration
  - Custom threat sharing
  - IoC lifecycle management
- [ ] **Advanced Analytics**
  - Trend analysis dashboard
  - Threat landscape reports
  - Performance metrics
- [ ] **Compliance & Governance**
  - Data retention policies
  - Audit trail logging
  - Compliance reporting (SOC/ISO)

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Report Issues**: Found a bug? Open an issue
2. **Feature Requests**: Got ideas? Let us know

### Development Setup
```powershell
# Clone your fork
git clone https://github.com/yourusername/PSGuard.git

```
## 🙏 Acknowledgments

- **AbuseIPDB** for providing free threat intelligence API
- **PSSQLite** module maintainers
- **PowerShell Community** for continuous inspiration

⭐ **Star this repo if you find it useful!** ⭐
