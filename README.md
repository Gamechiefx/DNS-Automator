# DNS Packet Analyzer

A Python-based tool for analyzing DNS packets from pcap files to detect potential DNS attacks, malformed queries, and volumetric query patterns.

## Features

- **Continuous Directory Monitoring**: Automatically processes new pcap/pcapng files as they appear
- **DNS Field Extraction**: Extracts source IP, destination IP, query/response status, domain, TTL, answers, and timestamps
- **Non-DNS TCP Detection**: Identifies and flags suspicious TCP packets without DNS layer
- **Detailed CSV Reports**: One row per DNS packet with all extracted fields
- **Summary CSV Reports**: Aggregated analysis with query counts and rates (tab-delimited)
- **Volumetric Analysis**: Calculates query rates per unique domain to detect attack patterns

## Requirements

- Python 3.8+
- Wireshark (tshark and editcap must be in PATH)
- Required Python packages (see requirements.txt)

## Quick Start

Run the setup script to automatically configure the environment:

```bash
./setup.sh
```

This will:
- Check Python 3.8+ installation
- Verify tshark and editcap availability
- Create a Python virtual environment
- Install all required dependencies
- Create output directories
- Validate the installation

## Manual Installation

If you prefer to install manually:

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure tshark and editcap are installed and accessible:
```bash
which tshark
which editcap
```

**Note**: On macOS, you may need to use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python dns_analyzer.py --input-dir /path/to/pcap/files --output-dir /path/to/output
```

### Command Line Arguments

- `--input-dir`: Directory to watch for pcap/pcapng files (required)
- `--output-dir`: Directory for output CSVs and JSONs (default: ./output)
- `--keep-json`: Keep intermediate JSON files after CSV generation (default: True)

## Output Structure

```
output/
├── detailed/          # Detailed CSV files (one per pcap)
├── summary/           # Summary CSV files (tab-delimited, one per pcap)
└── json/              # Intermediate JSON files (if kept)
```

## CSV Output Formats and Column Descriptions

### Detailed CSV
Contains one row per DNS packet with the following columns:

| Column | Description | Example |
|--------|-------------|---------|
| **Timestamp** | When the packet was captured | 2024-11-07T10:30:45 |
| **Source IP** | IP address initiating the request | 192.168.1.100 |
| **Destination IP** | IP address receiving the request | 8.8.8.8 |
| **Query/Response** | Indicates if packet is a query or response | Query, Response |
| **Domain** | The domain name being queried | example.com |
| **TTL** | Time-to-live in seconds (responses only) | 300 |
| **Answer** | The resolved IP address(es) (responses only) | 93.184.216.34 |
| **Packet Type** | Type of packet | DNS |

### Summary CSV (Tab-delimited)
Aggregated statistics for each unique client/server/domain combination:

| Column | Description | Example |
|--------|-------------|---------|
| **Client IP** | IP address of the DNS client | 192.168.1.100 |
| **DNS Server IP** | IP address of the DNS server | 8.8.8.8 |
| **Domain** | The queried domain name | example.com |
| **Query Type** | Whether these are queries or responses | Query |
| **Total Count** | Number of packets for this combination | 1500 |
| **Rate (qps)** | Queries per second | 125.5 |
| **First Seen** | Timestamp of first occurrence | 2024-11-07 10:30:45 |
| **Last Seen** | Timestamp of last occurrence | 2024-11-07 10:42:45 |
| **Time Window (s)** | Duration between first and last seen | 720 |

### Non-DNS TCP CSV
Captures suspicious TCP packets without DNS layer:

| Column | Description |
|--------|-------------|
| **Timestamp** | When the packet was captured |
| **Source IP** | Source IP address |
| **Destination IP** | Destination IP address |
| **Source Port** | TCP source port |
| **Destination Port** | TCP destination port (53 indicates DNS) |
| **Packet Type** | "TCP (Non-DNS)" |

## Detecting Abnormal DNS Behavior

### 1. High Query Rates (DNS Flooding/DDoS)
Look for unusually high rates in the summary CSV:
```python
# Normal: 1-10 queries per second per client
# Suspicious: >100 qps from a single client
# Attack: >1000 qps from a single client
```

**Detection**: Sort summary CSV by "Rate (qps)" column descending. Any client with >100 qps warrants investigation.

### 2. DNS Tunneling
Indicators of DNS tunneling include:
- **Long domain names**: Domains >50 characters (e.g., `a7f3b2c9d4e5f6.suspicious-domain.com`)
- **High entropy domains**: Random-looking subdomain strings
- **Unusual TLDs**: Non-standard top-level domains
- **Large response sizes**: DNS responses with unusually large answers

**Detection**: Look for domains with suspicious patterns in the detailed CSV.

### 3. DNS Cache Poisoning Attempts
Look for:
- Multiple responses for the same query from different servers
- Responses with very low or very high TTL values (<60 or >86400)
- Responses arriving before queries

**Detection**: Check for duplicate domains with different answers or unusual TTL values.

### 4. DNS Amplification Attack Patterns
Characteristics:
- Small queries generating large responses
- Queries for TXT, ANY, or DNSSEC records
- Repeated queries to the same domain

**Detection**: High query rates combined with specific query types (would need additional query type logging).

### 5. Domain Generation Algorithm (DGA) Detection
DGA domains typically show:
- Random alphanumeric patterns
- Similar length domains
- High frequency of failed resolutions (NXDOMAIN)
- Clusters of queries in short time windows

**Detection**: Look for patterns of similar-length random domains in the detailed CSV.

### 6. DNS Hijacking/Redirection
Signs include:
- Known domains resolving to unexpected IPs
- Private IP responses for public domains
- Responses from unauthorized DNS servers

**Detection**: Compare answer IPs for well-known domains against expected values.

### 7. Reconnaissance Activity
Patterns indicating reconnaissance:
- Sequential queries for related domains
- Queries for mail servers (MX), name servers (NS)
- Zone transfer attempts (AXFR)
- Version queries (version.bind)

**Detection**: Look for systematic querying patterns from single sources.

## Analysis Examples

### Finding Top Queried Domains
```bash
# Sort summary CSV by count (5th column)
sort -t$'\t' -k5 -nr *_summary.csv | head -20
```

### Finding Suspicious Query Rates
```bash
# Find clients with >100 queries per second
awk -F'\t' '$6 > 100 {print $1, $3, $6}' *_summary.csv
```

### Identifying Long Domains (potential tunneling)
```bash
# Find domains longer than 50 characters
awk -F',' 'length($5) > 50 {print $1, $2, $5}' *_detailed.csv
```

### Finding Non-DNS TCP Traffic to Port 53
```bash
# Check non-DNS TCP CSV for suspicious activity
grep "TCP (Non-DNS)" *_non_dns_tcp.csv | grep ":53"
```

## Best Practices for Analysis

1. **Baseline Normal Behavior**: Establish what's normal for your network before identifying anomalies
2. **Correlate Multiple Indicators**: Single indicators may have false positives; multiple indicators increase confidence
3. **Time-based Analysis**: Look for patterns that emerge during specific time windows
4. **Cross-reference Sources**: Compare against threat intelligence feeds for known malicious domains
5. **Monitor Trends**: Track changes in query patterns over time

## How It Works

1. **Directory Monitoring**: Uses watchdog library to monitor the input directory for new `.pcap` and `.pcapng` files
2. **Packet Processing**: Uses tshark to extract DNS fields and convert to JSON
3. **Data Extraction**: Parses JSON to extract relevant DNS fields and identify packet types
4. **CSV Generation**: Creates detailed and summary CSV files for analysis
5. **Volumetric Analysis**: Calculates query rates to identify high-volume patterns

## Error Handling

- Validates tshark/editcap availability on startup
- Handles malformed pcap files gracefully
- Skips files that are still being written
- Logs errors without stopping continuous processing

## Version Control / Git

To set up regular pushes to GitHub, see [GIT_SETUP.md](GIT_SETUP.md) for detailed instructions.

Quick start:
```bash
# Initialize git (if not already done)
git init
git remote add origin https://github.com/Gamechiefx/DNS-Automator.git

# Use the helper script for easy pushes
./git_push.sh "Your commit message"
```

The `.gitignore` file excludes output files, logs, and virtual environments from version control.

