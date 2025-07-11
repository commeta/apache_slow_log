#!/usr/bin/env python3

"""
Apache Slow Request Analyzer
Analyzes Apache logs to identify the slowest requests.
"""

import os
import re
import heapq
import logging
import argparse
import json
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Iterator
from dataclasses import dataclass, asdict
from collections import defaultdict
import subprocess
import sys
from datetime import datetime
import gzip
import bz2


@dataclass
class LogEntry:
    """Structure for storing log data"""
    duration: int
    domain: str
    url: str
    ip: str
    timestamp: Optional[str] = None
    status_code: Optional[int] = None
    
    @property
    def duration_seconds(self) -> float:
        """Converts microseconds to seconds"""
        return self.duration / 1_000_000
    
    @property
    def full_url(self) -> str:
        """Full URL of the request"""
        return f"{self.domain}{self.url}"


@dataclass
class Config:
    """Application configuration"""
    log_files_glob: str = "/etc/apache2/sites-enabled/*/*.conf"
    slow_log_path: str = "/var/log/apache2/slow.log"
    top_n: int = 100
    min_duration: int = 100000  # minimum duration in microseconds (0.1 sec)
    log_format: str = "combined"  # combined, common, custom
    custom_pattern: Optional[str] = None
    output_format: str = "text"  # text, json, csv
    include_stats: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """Loads configuration from JSON file"""
        if not os.path.exists(config_path):
            return cls()
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return cls(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logging.warning(f"Configuration loading error: {e}")
            return cls()


class LogPatterns:
    """Patterns for parsing various log formats"""
    
    # Standard combined format with %D
    COMBINED_WITH_DURATION = re.compile(
        r'(\S+) - - \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" (\d+)'
    )
    
    # Common format with %D
    COMMON_WITH_DURATION = re.compile(
        r'(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) (\d+)'
    )
    
    # Custom pattern
    CUSTOM_PATTERN = None
    
    @classmethod
    def set_custom_pattern(cls, pattern: str):
        """Sets custom pattern"""
        try:
            cls.CUSTOM_PATTERN = re.compile(pattern)
        except re.error as e:
            logging.error(f"Invalid pattern: {e}")
            raise


class ApacheLogAnalyzer:
    """Main class for analyzing Apache logs"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = self._setup_logging()
        self.stats = defaultdict(int)
        
    def _setup_logging(self) -> logging.Logger:
        """Logging setup"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def get_log_files(self) -> List[str]:
        """Gets list of log files from Apache configuration"""
        try:
            # Use subprocess instead of os.popen for security
            result = subprocess.run(
                f"grep -r 'CustomLog' {self.config.log_files_glob} | "
                f"awk -F'CustomLog ' '{{print $2}}' | awk '{{print $1}}'",
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            
            log_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
            self.logger.info(f"Found {len(log_files)} log files")
            return log_files
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting list of files: {e}")
            return []
    
    def _open_log_file(self, filepath: str):
        """Opens log file considering compression"""
        path = Path(filepath)
        
        if not path.exists():
            self.logger.warning(f"File not found: {filepath}")
            return None
        
        try:
            if path.suffix == '.gz':
                return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            elif path.suffix == '.bz2':
                return bz2.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            else:
                return open(filepath, 'r', encoding='utf-8', errors='ignore')
        except IOError as e:
            self.logger.error(f"Error opening file {filepath}: {e}")
            return None
    
    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        """Parses log line and returns LogEntry"""
        line = line.strip()
        if not line:
            return None
        
        # Choose pattern based on format
        if self.config.custom_pattern and LogPatterns.CUSTOM_PATTERN:
            pattern = LogPatterns.CUSTOM_PATTERN
        elif self.config.log_format == "combined":
            pattern = LogPatterns.COMBINED_WITH_DURATION
        else:
            pattern = LogPatterns.COMMON_WITH_DURATION
        
        match = pattern.match(line)
        if not match:
            self.stats['unparsed_lines'] += 1
            return None
        
        try:
            groups = match.groups()
            
            if self.config.log_format == "combined":
                ip, timestamp, method, url, status_code, size, referer, user_agent, duration = groups
            else:
                ip, timestamp, request, status_code, size, duration = groups
                # Extract method and URL from request
                request_parts = request.split(' ')
                method = request_parts[0] if request_parts else 'GET'
                url = request_parts[1] if len(request_parts) > 1 else '/'
            
            duration = int(duration)
            status_code = int(status_code)
            
            # Filter by minimum duration
            if duration < self.config.min_duration:
                return None
            
            # Clean URL from parameters
            url = url.split('?')[0]
            
            return LogEntry(
                duration=duration,
                domain="",  # Will be filled later
                url=url,
                ip=ip,
                timestamp=timestamp,
                status_code=status_code
            )
            
        except (ValueError, IndexError) as e:
            self.stats['parse_errors'] += 1
            self.logger.debug(f"Line parsing error: {e}")
            return None
    
    def extract_domain_from_path(self, path: str) -> Optional[str]:
        """Extracts domain from log file path"""
        # Extended patterns for different directory structures
        patterns = [
            r'/var/www/([^/]+)/data/logs/([^/]+)-backend\.access\.log',
            r'/var/log/httpd/([^/]+)\.access\.log',
            r'/var/log/apache2/([^/]+)\.access\.log',
            r'/([^/]+)\.access\.log',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, path)
            if match:
                return match.group(1) if match.lastindex == 1 else match.group(2)
        
        # Fallback - use filename
        filename = os.path.basename(path)
        domain = filename.replace('.access.log', '').replace('.log', '')
        return domain if domain else None
    
    def process_log_file(self, log_file: str) -> Iterator[LogEntry]:
        """Processes one log file"""
        domain = self.extract_domain_from_path(log_file)
        if not domain:
            self.logger.warning(f"Failed to extract domain from path: {log_file}")
            return
        
        self.logger.info(f"Processing file: {log_file} (domain: {domain})")
        
        file_handle = self._open_log_file(log_file)
        if not file_handle:
            return
        
        try:
            lines_processed = 0
            with file_handle:
                for line in file_handle:
                    lines_processed += 1
                    if lines_processed % 10000 == 0:
                        self.logger.debug(f"Processed {lines_processed} lines from {log_file}")
                    
                    entry = self.parse_log_line(line)
                    if entry:
                        entry.domain = domain
                        self.stats['valid_entries'] += 1
                        yield entry
                    
            self.stats['files_processed'] += 1
            self.logger.info(f"Processed {lines_processed} lines from {log_file}")
            
        except Exception as e:
            self.logger.error(f"Error processing file {log_file}: {e}")
            self.stats['file_errors'] += 1
    
    def get_top_requests(self, log_files: List[str]) -> List[Tuple[int, str]]:
        """Gets top slow requests"""
        self.logger.info("Starting analysis of slow requests")
        
        # Use min-heap for efficient top-N search
        top_requests = []
        request_stats = defaultdict(lambda: {'max_duration': 0, 'count': 0, 'total_duration': 0})
        
        for log_file in log_files:
            for entry in self.process_log_file(log_file):
                full_url = entry.full_url
                
                # Update statistics for URL
                request_stats[full_url]['count'] += 1
                request_stats[full_url]['total_duration'] += entry.duration
                request_stats[full_url]['max_duration'] = max(
                    request_stats[full_url]['max_duration'], 
                    entry.duration
                )
                
                # Maintain heap with top-N requests
                if len(top_requests) < self.config.top_n:
                    heapq.heappush(top_requests, (entry.duration, full_url))
                else:
                    heapq.heappushpop(top_requests, (entry.duration, full_url))
        
        # Sort by descending time
        result = sorted(top_requests, reverse=True, key=lambda x: x[0])
        
        self.logger.info(f"Found {len(result)} slow requests")
        return result
    
    def read_existing_slow_log(self) -> List[Tuple[int, str]]:
        """Reads existing slow requests file"""
        if not os.path.exists(self.config.slow_log_path):
            return []
        
        existing_entries = []
        try:
            with open(self.config.slow_log_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            duration, domain_url = parts
                            existing_entries.append((int(duration), domain_url))
                    except ValueError:
                        self.logger.warning(f"Invalid format in line {line_num}: {line}")
                        
        except IOError as e:
            self.logger.error(f"Error reading file {self.config.slow_log_path}: {e}")
        
        return existing_entries
    
    def write_slow_log(self, entries: List[Tuple[int, str]]):
        """Writes results to file"""
        try:
            # Create directory if not exists
            os.makedirs(os.path.dirname(self.config.slow_log_path), exist_ok=True)
            
            if self.config.output_format == "json":
                self._write_json_output(entries)
            elif self.config.output_format == "csv":
                self._write_csv_output(entries)
            else:
                self._write_text_output(entries)
                
        except IOError as e:
            self.logger.error(f"Error writing to file: {e}")
            raise
    
    def _write_text_output(self, entries: List[Tuple[int, str]]):
        """Writes in text format"""
        with open(self.config.slow_log_path, 'w', encoding='utf-8') as f:
            for duration, domain_url in entries:
                f.write(f"{duration} {domain_url}\n")
    
    def _write_json_output(self, entries: List[Tuple[int, str]]):
        """Writes in JSON format"""
        json_path = self.config.slow_log_path.replace('.log', '.json')
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_entries': len(entries),
            'config': dict(self.config),
            'entries': [
                {
                    'duration_microseconds': duration,
                    'duration_seconds': duration / 1_000_000,
                    'url': domain_url
                }
                for duration, domain_url in entries
            ]
        }
        
        if self.config.include_stats:
            data['stats'] = dict(self.stats)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _write_csv_output(self, entries: List[Tuple[int, str]]):
        """Writes in CSV format"""
        csv_path = self.config.slow_log_path.replace('.log', '.csv')
        
        with open(csv_path, 'w', encoding='utf-8') as f:
            f.write("duration_microseconds,duration_seconds,url\n")
            for duration, domain_url in entries:
                f.write(f"{duration},{duration/1_000_000},{domain_url}\n")
    
    def merge_entries(self, existing: List[Tuple[int, str]], 
                     new: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
        """Merges existing and new entries"""
        # Use dictionary to store maximum time for each URL
        combined_dict = {}
        
        for duration, domain_url in existing + new:
            if domain_url not in combined_dict or combined_dict[domain_url] < duration:
                combined_dict[domain_url] = duration
        
        # Sort and limit to top-N
        combined_entries = [(duration, domain_url) 
                          for domain_url, duration in combined_dict.items()]
        combined_entries.sort(reverse=True, key=lambda x: x[0])
        
        return combined_entries[:self.config.top_n]
    
    def print_stats(self):
        """Prints execution statistics"""
        if not self.config.include_stats:
            return
            
        self.logger.info("=== Execution Statistics ===")
        for key, value in self.stats.items():
            self.logger.info(f"{key}: {value}")
    
    def run(self):
        """Main execution method"""
        try:
            self.logger.info("Starting Apache log analysis")
            
            # Get list of log files
            log_files = self.get_log_files()
            if not log_files:
                self.logger.warning("Log files not found")
                return
            
            # Analyze log files
            new_top_requests = self.get_top_requests(log_files)
            
            # Read existing entries
            existing_entries = self.read_existing_slow_log()
            
            # Merge entries
            combined_entries = self.merge_entries(existing_entries, new_top_requests)
            
            # Write results
            self.write_slow_log(combined_entries)
            
            # Print statistics
            self.print_stats()
            
            self.logger.info(f"Analysis completed. Results saved to {self.config.slow_log_path}")
            
        except Exception as e:
            self.logger.error(f"Critical error: {e}")
            sys.exit(1)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Apache Slow Request Analyzer")
    parser.add_argument("--config", "-c", help="Path to JSON configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--top-n", "-n", type=int, help="Number of top requests")
    parser.add_argument("--output-format", "-f", choices=["text", "json", "csv"], 
                       help="Output format")
    parser.add_argument("--min-duration", "-d", type=int, 
                       help="Minimum duration in microseconds")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = Config.from_file(args.config) if args.config else Config()
    
    # Override parameters from command line
    if args.top_n:
        config.top_n = args.top_n
    if args.output_format:
        config.output_format = args.output_format
    if args.min_duration:
        config.min_duration = args.min_duration
    
    # Run analyzer
    analyzer = ApacheLogAnalyzer(config)
    analyzer.run()


if __name__ == "__main__":
    main()
