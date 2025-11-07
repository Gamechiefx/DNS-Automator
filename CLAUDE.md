# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DNS-Automator is a Python-based DNS packet analysis tool that monitors directories for PCAP/PCAPNG files and performs automated DNS traffic analysis to detect potential attacks and anomalies. The tool uses Wireshark's tshark utility to extract DNS data and generates both detailed packet-level and aggregated summary reports.

## Common Commands

### Setup and Environment
```bash
# Initial setup (creates venv, installs dependencies, validates tools)
./setup.sh

# Activate virtual environment
source venv/bin/activate

# Install dependencies manually
pip install -r requirements.txt

# Check required external tools availability
which tshark editcap
```

### Running the Application
```bash
# Basic usage (monitors directory and processes new PCAP files)
python dns_analyzer.py --input-dir /path/to/pcaps --output-dir ./output

# With JSON retention disabled (saves disk space)
python dns_analyzer.py --input-dir /path/to/pcaps --output-dir ./output --no-keep-json

# Process existing files in test_input directory
python dns_analyzer.py --input-dir test_input --output-dir output
```

## Architecture Overview

The codebase is structured as a single Python file (`dns_analyzer.py`) containing two primary classes:

### DNSAnalyzer Class (Lines 39-548)
Core processing engine responsible for:
- **Initialization**: Validates tshark/editcap availability and creates output directories
- **File Processing Pipeline**:
  1. `process_pcap_file()`: Entry point, orchestrates the processing workflow
  2. `_run_tshark()`: Executes tshark with specific field extraction parameters
  3. `extract_dns_data()`: Parses tshark JSON output, extracts DNS fields, handles both direct and nested field structures
  4. `generate_detailed_csv()`: Creates packet-level CSV with all DNS transaction details
  5. `generate_summary_csv()`: Aggregates data by client/server/domain combinations
  6. `calculate_query_rates()`: Performs volumetric analysis for anomaly detection

### PcapFileHandler Class (Lines 550-570)
File system monitor that:
- Extends watchdog's FileSystemEventHandler
- Monitors input directory for new .pcap/.pcapng files
- Implements 2-second debouncing to ensure file write completion
- Triggers DNSAnalyzer processing for each new file

## Key Technical Details

### Dependencies
- **External Tools** (must be in PATH):
  - `tshark`: Packet extraction and JSON conversion
  - `editcap`: Required for validation (not actively used)
- **Python Requirements** (requirements.txt):
  - `watchdog>=3.0.0`: File system monitoring
  - `pandas>=2.0.0`: Data manipulation and aggregation
  - Python 3.8+ required

### Output Structure
```
output/
├── detailed/       # Row-per-packet CSV files
│   └── {basename}_detailed.csv
├── summary/        # Tab-delimited aggregated statistics
│   └── {basename}_summary.csv
└── json/          # Intermediate tshark output (optional)
    └── {basename}_dns.json
```

### CSV Output Formats
- **Detailed CSV**: `Timestamp,Source IP,Destination IP,Query/Response,Domain,TTL,Answer,Packet Type`
- **Summary CSV**: Tab-delimited with `Client IP\tDNS Server IP\tDomain\tQuery Type\tTotal Count\tRate (qps)\tFirst Seen\tLast Seen\tTime Window (s)`
- **Non-DNS TCP CSV**: Similar format but captures suspicious TCP packets without DNS layer

### Field Extraction Strategy
The tool uses defensive extraction handling multiple field naming conventions:
```python
# IPv4/IPv6 field resolution
ip_src = self._get_field(packet, ['ip.src', 'ipv6.src'])
ip_dst = self._get_field(packet, ['ip.dst', 'ipv6.dst'])

# DNS field extraction with nested structure support
dns_qry_name = self._get_field(dns_layer, ['dns.qry.name', 'Queries', 'queries'])
```

### Processing Pipeline Details
1. **File Stability Check**: Waits for file size to stabilize before processing
2. **tshark Execution**: Runs with 1-hour timeout, extracts specific fields:
   - Frame: `frame.time_epoch`, `frame.time_delta`
   - IP: `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`
   - DNS: All DNS fields including queries, answers, flags, TTL
3. **Data Processing**: Separates DNS packets from non-DNS TCP packets
4. **Rate Calculation**: Analyzes query patterns over time windows

### Error Handling Patterns
- Tool validation on startup with informative error messages
- Graceful PCAP processing failures (logs errors, continues processing)
- Timeout protection for large file processing (1-hour limit)
- Comprehensive logging to `dns_analyzer.log` and stdout

## Development Workflow

### Making Changes
1. Main processing logic is in `DNSAnalyzer.extract_dns_data()` method
2. Field extraction relies on tshark's JSON output structure
3. Summary generation uses pandas DataFrame operations
4. File watching uses watchdog's event-driven Observer pattern

### Testing Changes
```bash
# Use test_input directory with sample PCAP files
python dns_analyzer.py --input-dir test_input --output-dir output

# Check outputs in respective directories
ls -la output/detailed/
ls -la output/summary/
```

### Debugging
- Enable verbose logging by checking `dns_analyzer.log`
- JSON files in `output/json/` contain raw tshark output for debugging
- Use `--no-keep-json` flag to disable JSON retention in production

## Current Limitations and Technical Debt
- Single-file architecture (all logic in dns_analyzer.py)
- No automated testing framework
- No linting or code formatting configuration
- Sequential file processing (no parallelization)
- No configuration file support (all parameters via CLI)

## Performance Considerations
- File processing is CPU-bound due to tshark execution
- Large PCAP files may take significant time (1-hour timeout)
- JSON intermediate files can consume disk space
- Tab-delimited format used for summary files to handle domains with commas