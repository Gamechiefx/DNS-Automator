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

## CSV Formats

### Detailed CSV
- Timestamp, Source IP, Destination IP, Query/Response, Domain, TTL, Answer, Packet Type

### Summary CSV (Tab-delimited)
- Client IP, DNS Server IP, Domain, Query Type, Total Count, Rate (qps), First Seen, Last Seen, Time Window

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

