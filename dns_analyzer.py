#!/usr/bin/env python3
"""
DNS Packet Analyzer

Processes pcap files to extract DNS packet data, identify potential attacks,
and generate detailed and summary CSV reports with volumetric analysis.
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
from tqdm import tqdm
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """Main class for DNS packet analysis."""
    
    def __init__(self, input_dir: str, output_dir: str, keep_json: bool = True):
        """
        Initialize DNS Analyzer.
        
        Args:
            input_dir: Directory to watch for pcap files
            output_dir: Directory for output files
            keep_json: Whether to keep intermediate JSON files
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.keep_json = keep_json
        self.processed_files = set()
        
        # Create output directories
        self.detailed_dir = self.output_dir / 'detailed'
        self.summary_dir = self.output_dir / 'summary'
        self.json_dir = self.output_dir / 'json'
        
        for dir_path in [self.detailed_dir, self.summary_dir, self.json_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Validate tshark and editcap availability
        self._validate_tools()
    
    def _validate_tools(self):
        """Validate that tshark and editcap are available."""
        for tool in ['tshark', 'editcap']:
            if not shutil.which(tool):
                raise RuntimeError(f"{tool} not found in PATH. Please install Wireshark.")
        logger.info("tshark and editcap validated successfully")
    
    def extract_dns_data(self, json_data: List[Dict], total_packets: int = 0) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse tshark JSON output and extract DNS fields.
        
        Args:
            json_data: List of packet dictionaries from tshark JSON output
            total_packets: Total number of packets for progress bar
            
        Returns:
            Tuple of (dns_packets, non_dns_tcp_packets)
        """
        dns_packets = []
        non_dns_tcp_packets = []
        
        # Create progress bar
        progress_bar = tqdm(json_data, desc="Extracting DNS packets", 
                          total=total_packets if total_packets > 0 else len(json_data),
                          unit="packets", leave=False)
        
        for packet in progress_bar:
            if '_source' not in packet:
                continue
            
            layers = packet.get('_source', {}).get('layers', {})
            
            # Detect protocols by checking for field presence
            # (when using -e flags, protocol keys aren't in layers)
            has_tcp = any(key.startswith('tcp.') for key in layers.keys())
            has_dns = any(key.startswith('dns.') for key in layers.keys())
            
            # Also check for protocol keys (in case they exist)
            has_tcp = has_tcp or 'tcp' in layers
            has_dns = has_dns or 'dns' in layers
            
            if has_tcp and not has_dns:
                # Non-DNS TCP packet
                tcp_info = self._extract_tcp_info(layers)
                if tcp_info:
                    non_dns_tcp_packets.append(tcp_info)
                continue
            
            # Extract DNS packet data
            if has_dns:
                dns_info = self._extract_dns_info(layers)
                if dns_info:
                    dns_packets.append(dns_info)
        
        progress_bar.close()
        return dns_packets, non_dns_tcp_packets
    
    def _extract_dns_info(self, layers: Dict) -> Optional[Dict]:
        """
        Extract DNS-specific fields from packet layers.
        
        Args:
            layers: Dictionary of protocol layers
            
        Returns:
            Dictionary with DNS fields or None if extraction fails
        """
        try:
            # Extract IP addresses (support both IPv4 and IPv6)
            source_ip = self._get_field(layers, ['ip.src', 'ipv6.src'])
            dest_ip = self._get_field(layers, ['ip.dst', 'ipv6.dst'])
            
            if not source_ip or not dest_ip:
                return None
            
            # Extract DNS fields
            dns_layer = layers.get('dns', {})
            if isinstance(dns_layer, list):
                dns_layer = dns_layer[0] if dns_layer else {}
            
            # Query vs Response
            is_response = self._get_field(layers, ['dns.flags.response'])
            query_response = 'Response' if is_response == '1' else 'Query'
            
            # Domain name (query name or response name)
            domain = self._get_field(layers, ['dns.qry.name', 'dns.resp.name'])
            
            # TTL
            ttl = self._get_field(layers, ['dns.resp.ttl'])
            
            # Answers (A, AAAA, TXT, etc.)
            answer = self._get_field(layers, ['dns.a', 'dns.aaaa', 'dns.txt', 'dns.cname'])
            
            # Timestamp
            frame_time = self._get_field(layers, ['frame.time'])
            timestamp = self._parse_timestamp(frame_time) if frame_time else None
            
            return {
                'timestamp': timestamp or frame_time,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'query_response': query_response,
                'domain': domain or 'N/A',
                'ttl': ttl or 'N/A',
                'answer': answer or 'N/A',
                'packet_type': 'DNS'
            }
        except Exception as e:
            logger.warning(f"Error extracting DNS info: {e}")
            return None
    
    def _extract_tcp_info(self, layers: Dict) -> Optional[Dict]:
        """
        Extract TCP packet information for non-DNS TCP packets.
        
        Args:
            layers: Dictionary of protocol layers
            
        Returns:
            Dictionary with TCP fields or None
        """
        try:
            source_ip = self._get_field(layers, ['ip.src', 'ipv6.src'])
            dest_ip = self._get_field(layers, ['ip.dst', 'ipv6.dst'])
            source_port = self._get_field(layers, ['tcp.srcport'])
            dest_port = self._get_field(layers, ['tcp.dstport'])
            frame_time = self._get_field(layers, ['frame.time'])
            
            if not source_ip or not dest_ip:
                return None
            
            return {
                'timestamp': frame_time or 'N/A',
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'source_port': source_port or 'N/A',
                'destination_port': dest_port or 'N/A',
                'packet_type': 'TCP (Non-DNS)'
            }
        except Exception as e:
            logger.warning(f"Error extracting TCP info: {e}")
            return None
    
    def _get_field(self, layers: Dict, field_names: List[str]) -> Optional[str]:
        """
        Get field value from layers, trying multiple field names.
        
        Args:
            layers: Dictionary of protocol layers
            field_names: List of possible field names to try
            
        Returns:
            Field value or None
        """
        for field_name in field_names:
            # First try direct key access (for -e flag output format)
            if field_name in layers:
                current = layers[field_name]
                if current is not None:
                    if isinstance(current, list):
                        return ', '.join(str(v) for v in current)
                    return str(current)
            
            # Fallback: try nested structure navigation (for full JSON output)
            parts = field_name.split('.')
            current = layers
            
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and len(current) > 0:
                    current = current[0].get(part) if isinstance(current[0], dict) else None
                else:
                    current = None
                    break
                
                if current is None:
                    break
            
            if current is not None:
                if isinstance(current, list):
                    return ', '.join(str(v) for v in current)
                return str(current)
        
        return None
    
    def _parse_timestamp(self, time_str: str) -> Optional[str]:
        """
        Parse tshark timestamp to standardized format.
        
        Args:
            time_str: Timestamp string from tshark
            
        Returns:
            Formatted timestamp string or None
        """
        try:
            # tshark format: "Jul 15, 2024 10:30:45.123456000 UTC"
            # Try to parse and reformat
            dt = datetime.strptime(time_str.split('.')[0], '%b %d, %Y %H:%M:%S')
            return dt.isoformat()
        except:
            return time_str
    
    def _get_packet_count(self, file_path: Path) -> int:
        """
        Get total packet count from pcap file.
        
        Args:
            file_path: Path to pcap file
            
        Returns:
            Total number of packets in the file
        """
        try:
            # Use capinfos which is much faster for getting packet count
            cmd = ['capinfos', '-c', str(file_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                # Parse output like "Number of packets:   12899"
                for line in result.stdout.split('\n'):
                    if 'Number of packets:' in line:
                        count_str = line.split(':')[1].strip()
                        # Handle 'k' notation (e.g., "12k" -> 12000)
                        if count_str.endswith('k'):
                            base_num = float(count_str[:-1])
                            return int(base_num * 1000)
                        elif count_str.isdigit():
                            return int(count_str)
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout getting packet count for {file_path.name}")
        except Exception as e:
            logger.warning(f"Could not get packet count using capinfos, trying fallback: {e}")
            
        # Fallback to tshark with tail (faster than full scan)
        try:
            cmd = ['tshark', '-r', str(file_path), '-T', 'fields', '-e', 'frame.number', '-c', '1', '-o', 'frame.number:1']
            result = subprocess.run(['tshark', '-r', str(file_path), '-T', 'fields', '-e', 'frame.number'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if lines and lines[-1].isdigit():
                    return int(lines[-1])
        except Exception:
            pass
            
        return 0
    
    def _process_pcap_streaming(self, file_path: Path, total_packets: int) -> bool:
        """
        Process large PCAP files in streaming mode to avoid memory issues.
        
        Args:
            file_path: Path to pcap file
            total_packets: Total number of packets
            
        Returns:
            True if processing succeeded, False otherwise
        """
        try:
            base_name = file_path.stem
            batch_size = 100000  # Process 100k packets at a time
            
            # Initialize output files
            detailed_path = self.detailed_dir / f"{base_name}_detailed.csv"
            summary_path = self.summary_dir / f"{base_name}_summary.csv"
            tcp_path = self.detailed_dir / f"{base_name}_non_dns_tcp.csv"
            
            all_dns_packets = []
            
            # Create progress bar for the entire file
            progress_bar = tqdm(total=total_packets, desc=f"Processing {file_path.name}", 
                              unit="packets", leave=True)
            
            processed_packets = 0
            batch_num = 0
            
            while processed_packets < total_packets:
                batch_num += 1
                start_packet = processed_packets + 1
                end_packet = min(processed_packets + batch_size, total_packets)
                
                logger.info(f"Processing batch {batch_num}: packets {start_packet}-{end_packet}")
                
                # Process batch using tshark with packet range filter
                frame_filter = f"frame.number >= {start_packet} and frame.number <= {end_packet}"
                display_filter = f"({frame_filter}) and (dns or (tcp and not dns))"
                
                cmd = [
                    'tshark', '-r', str(file_path),
                    '-T', 'json',
                    '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ipv6.src', '-e', 'ipv6.dst',
                    '-e', 'dns.flags.response', '-e', 'dns.qry.name', '-e', 'dns.resp.name',
                    '-e', 'dns.resp.ttl', '-e', 'dns.a', '-e', 'dns.aaaa', '-e', 'dns.txt',
                    '-e', 'dns.cname', '-e', 'frame.time', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                    '-Y', display_filter
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                    if result.returncode == 0 and result.stdout:
                        batch_json = json.loads(result.stdout)
                        
                        # Process this batch
                        dns_packets, non_dns_tcp_packets = self.extract_dns_data(batch_json, 0)
                        
                        # Append to detailed CSV
                        self._append_detailed_csv(dns_packets, detailed_path, batch_num == 1)
                        self._append_tcp_csv(non_dns_tcp_packets, tcp_path, batch_num == 1)
                        
                        # Collect DNS packets for summary
                        all_dns_packets.extend(dns_packets)
                        
                        progress_bar.update(len(batch_json))
                        processed_packets += len(batch_json)
                        
                    else:
                        logger.warning(f"No data in batch {batch_num}")
                        break
                        
                except Exception as e:
                    logger.error(f"Error processing batch {batch_num}: {e}")
                    break
            
            progress_bar.close()
            
            # Generate summary from all collected DNS packets
            if all_dns_packets:
                self.generate_summary_csv(all_dns_packets, summary_path)
            
            self.processed_files.add(file_path)
            logger.info(f"Successfully processed {file_path.name} in streaming mode")
            return True
            
        except Exception as e:
            logger.error(f"Error in streaming processing {file_path.name}: {e}", exc_info=True)
            return False
    
    def _append_detailed_csv(self, dns_packets: List[Dict], output_path: Path, write_header: bool = False):
        """
        Append DNS packets to detailed CSV file.
        
        Args:
            dns_packets: List of DNS packet dictionaries
            output_path: Path for output CSV
            write_header: Whether to write header (first batch)
        """
        if not dns_packets:
            return
        
        df = pd.DataFrame(dns_packets)
        df.to_csv(output_path, mode='a', header=write_header, index=False)
    
    def _append_tcp_csv(self, tcp_packets: List[Dict], output_path: Path, write_header: bool = False):
        """
        Append TCP packets to TCP CSV file.
        
        Args:
            tcp_packets: List of TCP packet dictionaries
            output_path: Path for output CSV
            write_header: Whether to write header (first batch)
        """
        if not tcp_packets:
            return
        
        df = pd.DataFrame(tcp_packets)
        df.to_csv(output_path, mode='a', header=write_header, index=False)
    
    def process_pcap_file(self, file_path: Path) -> bool:
        """
        Process a single pcap file through the complete pipeline.
        
        Args:
            file_path: Path to pcap file
            
        Returns:
            True if processing succeeded, False otherwise
        """
        if file_path in self.processed_files:
            logger.debug(f"File {file_path.name} already processed, skipping")
            return False
        
        logger.info(f"Processing file: {file_path.name}")
        
        try:
            # Check if file is still being written (wait if file size changes)
            if not self._wait_for_file_stable(file_path):
                logger.warning(f"File {file_path.name} appears to be incomplete, skipping")
                return False
            
            # Get total packet count for progress bar
            total_packets = self._get_packet_count(file_path)
            if total_packets > 0:
                logger.info(f"Total packets to process: {total_packets}")
            
            # Use streaming processing for large files (> 1M packets)
            if total_packets > 1000000:
                logger.info(f"Large file detected ({total_packets} packets), using streaming mode")
                return self._process_pcap_streaming(file_path, total_packets)
            
            # Run tshark to extract data
            json_data = self._run_tshark(file_path)
            if not json_data:
                logger.error(f"No data extracted from {file_path.name}")
                return False
            
            # Save JSON if requested
            json_output_path = self.json_dir / f"{file_path.stem}.json"
            if self.keep_json:
                with open(json_output_path, 'w') as f:
                    json.dump(json_data, f, indent=2)
                logger.info(f"Saved JSON to {json_output_path}")
            
            # Extract DNS data
            dns_packets, non_dns_tcp_packets = self.extract_dns_data(json_data, total_packets)
            
            logger.info(f"Extracted {len(dns_packets)} DNS packets and {len(non_dns_tcp_packets)} non-DNS TCP packets")
            
            # Generate CSV files
            base_name = file_path.stem
            
            if dns_packets:
                detailed_path = self.detailed_dir / f"{base_name}_detailed.csv"
                summary_path = self.summary_dir / f"{base_name}_summary.csv"
                
                self.generate_detailed_csv(dns_packets, detailed_path)
                self.generate_summary_csv(dns_packets, summary_path)
            
            if non_dns_tcp_packets:
                tcp_path = self.detailed_dir / f"{base_name}_non_dns_tcp.csv"
                self.generate_tcp_csv(non_dns_tcp_packets, tcp_path)
            
            self.processed_files.add(file_path)
            logger.info(f"Successfully processed {file_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {file_path.name}: {e}", exc_info=True)
            return False
    
    def _wait_for_file_stable(self, file_path: Path, max_wait: int = 30, check_interval: int = 2) -> bool:
        """
        Wait for file to stabilize (stop being written).
        
        Args:
            file_path: Path to file
            max_wait: Maximum seconds to wait
            check_interval: Seconds between checks
            
        Returns:
            True if file is stable, False if timeout
        """
        if not file_path.exists():
            return False
        
        start_time = time.time()
        last_size = file_path.stat().st_size
        
        while time.time() - start_time < max_wait:
            time.sleep(check_interval)
            current_size = file_path.stat().st_size
            
            if current_size == last_size:
                return True
            
            last_size = current_size
        
        return False
    
    def _run_tshark(self, file_path: Path) -> List[Dict]:
        """
        Run tshark to extract packet data as JSON.
        
        Args:
            file_path: Path to pcap file
            
        Returns:
            List of packet dictionaries
        """
        # Build tshark command
        cmd = [
            'tshark',
            '-r', str(file_path),
            '-T', 'json',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ipv6.src',
            '-e', 'ipv6.dst',
            '-e', 'dns.flags.response',
            '-e', 'dns.qry.name',
            '-e', 'dns.resp.name',
            '-e', 'dns.resp.ttl',
            '-e', 'dns.a',
            '-e', 'dns.aaaa',
            '-e', 'dns.txt',
            '-e', 'dns.cname',
            '-e', 'frame.time',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-Y', 'dns or (tcp and not dns)'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout for large files
                check=True
            )
            
            # Parse JSON output
            json_data = json.loads(result.stdout)
            return json_data
            
        except subprocess.TimeoutExpired:
            logger.error(f"tshark timeout processing {file_path.name}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"tshark error: {e.stderr}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            raise
    
    def generate_detailed_csv(self, dns_packets: List[Dict], output_path: Path):
        """
        Generate detailed CSV with one row per DNS packet.
        
        Args:
            dns_packets: List of DNS packet dictionaries
            output_path: Path for output CSV
        """
        df = pd.DataFrame(dns_packets)
        df.to_csv(output_path, index=False)
        logger.info(f"Generated detailed CSV: {output_path}")
    
    def generate_summary_csv(self, dns_packets: List[Dict], output_path: Path):
        """
        Generate summary CSV with aggregated data and query rates (tab-delimited).
        
        Args:
            dns_packets: List of DNS packet dictionaries
            output_path: Path for output CSV
        """
        if not dns_packets:
            return
        
        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame(dns_packets)
        
        # Parse timestamps for rate calculation
        df['parsed_time'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Group by client, DNS server, domain, and query type
        summary_data = []
        
        for (client_ip, dns_server, domain, query_type), group in df.groupby(
            ['source_ip', 'destination_ip', 'domain', 'query_response']
        ):
            count = len(group)
            
            # Calculate time range
            valid_times = group['parsed_time'].dropna()
            if len(valid_times) > 0:
                first_seen = valid_times.min()
                last_seen = valid_times.max()
                time_window = (last_seen - first_seen).total_seconds()
                
                # Calculate rate (queries per second)
                if time_window > 0:
                    rate_qps = count / time_window
                else:
                    rate_qps = count  # All queries in same second
                
                first_seen_str = first_seen.strftime('%Y-%m-%d %H:%M:%S')
                last_seen_str = last_seen.strftime('%Y-%m-%d %H:%M:%S')
            else:
                first_seen_str = group['timestamp'].iloc[0]
                last_seen_str = group['timestamp'].iloc[-1]
                time_window = 0
                rate_qps = 0
            
            summary_data.append({
                'Client IP': client_ip,
                'DNS Server IP': dns_server,
                'Domain': domain,
                'Query Type': query_type,
                'Total Count': count,
                'Rate (qps)': f"{rate_qps:.4f}",
                'First Seen': first_seen_str,
                'Last Seen': last_seen_str,
                'Time Window (s)': f"{time_window:.2f}"
            })
        
        # Create summary DataFrame
        summary_df = pd.DataFrame(summary_data)
        
        # Sort by count (descending) to highlight high-volume queries
        summary_df = summary_df.sort_values('Total Count', ascending=False)
        
        # Save as tab-delimited CSV
        summary_df.to_csv(output_path, sep='\t', index=False)
        logger.info(f"Generated summary CSV: {output_path}")
    
    def generate_tcp_csv(self, tcp_packets: List[Dict], output_path: Path):
        """
        Generate CSV for non-DNS TCP packets.
        
        Args:
            tcp_packets: List of TCP packet dictionaries
            output_path: Path for output CSV
        """
        df = pd.DataFrame(tcp_packets)
        df.to_csv(output_path, index=False)
        logger.info(f"Generated TCP CSV: {output_path}")
    
    def calculate_query_rates(self, dns_packets: List[Dict]) -> Dict:
        """
        Calculate query rates per unique domain name for volumetric analysis.
        
        Args:
            dns_packets: List of DNS packet dictionaries
            
        Returns:
            Dictionary with rate analysis
        """
        domain_stats = defaultdict(lambda: {'count': 0, 'timestamps': []})
        
        for packet in dns_packets:
            domain = packet.get('domain', 'N/A')
            timestamp = packet.get('timestamp')
            
            domain_stats[domain]['count'] += 1
            if timestamp:
                try:
                    dt = pd.to_datetime(timestamp, errors='coerce')
                    if pd.notna(dt):
                        domain_stats[domain]['timestamps'].append(dt)
                except:
                    pass
        
        # Calculate rates
        rate_analysis = {}
        for domain, stats in domain_stats.items():
            count = stats['count']
            timestamps = stats['timestamps']
            
            if len(timestamps) > 1:
                time_span = (max(timestamps) - min(timestamps)).total_seconds()
                rate = count / time_span if time_span > 0 else count
            else:
                rate = count
            
            rate_analysis[domain] = {
                'total_queries': count,
                'rate_qps': rate,
                'first_seen': min(timestamps) if timestamps else None,
                'last_seen': max(timestamps) if timestamps else None
            }
        
        return rate_analysis


class PcapFileHandler(FileSystemEventHandler):
    """File system event handler for pcap files."""
    
    def __init__(self, analyzer: DNSAnalyzer):
        """
        Initialize handler.
        
        Args:
            analyzer: DNSAnalyzer instance
        """
        self.analyzer = analyzer
    
    def on_created(self, event):
        """Handle file creation event."""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix.lower() in ['.pcap', '.pcapng']:
                # Small delay to ensure file is fully written
                time.sleep(2)
                self.analyzer.process_pcap_file(file_path)


def watch_directory(analyzer: DNSAnalyzer):
    """
    Start watching directory for new pcap files.
    
    Args:
        analyzer: DNSAnalyzer instance
    """
    event_handler = PcapFileHandler(analyzer)
    observer = Observer()
    observer.schedule(event_handler, str(analyzer.input_dir), recursive=False)
    observer.start()
    
    logger.info(f"Watching directory: {analyzer.input_dir}")
    logger.info("Press Ctrl+C to stop")
    
    try:
        # Process any existing pcap files
        for pcap_file in list(analyzer.input_dir.glob('*.pcap')) + list(analyzer.input_dir.glob('*.pcapng')):
            if pcap_file not in analyzer.processed_files:
                analyzer.process_pcap_file(pcap_file)
        
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping directory watcher...")
        observer.stop()
    
    observer.join()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='DNS Packet Analyzer - Process pcap files for DNS attack analysis'
    )
    parser.add_argument(
        '--input-dir',
        type=str,
        required=True,
        help='Directory to watch for pcap files'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./output',
        help='Directory for output files (default: ./output)'
    )
    parser.add_argument(
        '--keep-json',
        action='store_true',
        default=True,
        help='Keep intermediate JSON files (default: True)'
    )
    parser.add_argument(
        '--no-keep-json',
        action='store_false',
        dest='keep_json',
        help='Delete JSON files after CSV generation'
    )
    
    args = parser.parse_args()
    
    # Validate input directory
    input_path = Path(args.input_dir)
    if not input_path.exists():
        logger.error(f"Input directory does not exist: {args.input_dir}")
        sys.exit(1)
    
    if not input_path.is_dir():
        logger.error(f"Input path is not a directory: {args.input_dir}")
        sys.exit(1)
    
    try:
        # Initialize analyzer
        analyzer = DNSAnalyzer(
            input_dir=str(input_path),
            output_dir=args.output_dir,
            keep_json=args.keep_json
        )
        
        # Start watching directory
        watch_directory(analyzer)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

