# Apache Slow Request Analyzer

[Русский](README_RU.md)

This script analyzes Apache logs to identify the slowest requests to the server. It extracts request information from configuration files, finds corresponding logs, and creates a list of the 100 slowest requests based on server response time recorded in microseconds.

## Features

- **Modern Architecture**: Built with Python 3.8+ using dataclasses, type hints, and modern libraries
- **Robust Error Handling**: Comprehensive error handling and logging
- **Multiple Output Formats**: Support for text, JSON, and CSV output formats
- **Configurable**: JSON-based configuration with command-line overrides
- **Memory Efficient**: Streaming processing for large log files
- **Compressed Log Support**: Handles gzip and bzip2 compressed log files
- **Flexible Log Parsing**: Support for different Apache log formats
- **Statistics**: Detailed processing statistics
- **Security**: Uses subprocess instead of os.popen for shell commands

## Functionality

1. **Log Discovery**: Searches for all Apache configuration files containing CustomLog directive to determine log file locations
2. **Log Parsing**: Analyzes each log line to extract IP address and request execution time
3. **Domain Extraction**: Extracts domain from log file path using flexible patterns
4. **Top Request Search**: Collects request data and maintains only the top 100 slowest using heapq for efficient memory management
5. **Data Merging**: Compares new data with existing slow.log entries, updating records if new requests are slower
6. **Output Writing**: Saves results in multiple formats (text, JSON, CSV)

## Installation and Usage

### Requirements

- Python 3.8 or higher
- Access to Apache logs
- Standard library modules (no external dependencies)

### Installation

1. Copy the script to your server:
```bash
wget https://raw.githubusercontent.com/commeta/apache_slow_log/main/apache_slow_log.py
chmod +x apache_slow_log.py
```

2. Optional: Create a configuration file:
```bash
cp config.json.example config.json
```

### Basic Usage

```bash
# Basic usage with default settings
python3 apache_slow_log.py

# With custom configuration
python3 apache_slow_log.py --config config.json

# With command-line options
python3 apache_slow_log.py --top-n 50 --output-format json --verbose

# Set minimum duration threshold (in microseconds)
python3 apache_slow_log.py --min-duration 500000  # 0.5 seconds
```

### Configuration Options

Create a `config.json` file:

```json
{
  "log_files_glob": "/etc/httpd/sites-enabled/*/*.conf",
  "slow_log_path": "/var/log/apache2/slow.log",
  "top_n": 100,
  "min_duration": 100000,
  "log_format": "combined",
  "output_format": "text",
  "include_stats": true
}
```

**Configuration Parameters:**

- `log_files_glob`: Pattern for finding Apache configuration files
- `slow_log_path`: Output file path
- `top_n`: Number of slowest requests to track
- `min_duration`: Minimum request duration in microseconds to consider
- `log_format`: Apache log format (`combined`, `common`, or `custom`)
- `output_format`: Output format (`text`, `json`, or `csv`)
- `include_stats`: Whether to include processing statistics

## Time Format

Request execution time is recorded in microseconds. To convert this value to seconds, use:

**Time (in seconds) = Time (in microseconds) / 1,000,000**

## Output Formats

### Text Format (default)
```
5385806 site1.ru/
5315441 site2.ru/1.html
4991294 site3.ru/
```

### JSON Format
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "total_entries": 100,
  "entries": [
    {
      "duration_microseconds": 5385806,
      "duration_seconds": 5.385806,
      "url": "site1.ru/"
    }
  ],
  "stats": {
    "files_processed": 15,
    "valid_entries": 1250
  }
}
```

### CSV Format
```csv
duration_microseconds,duration_seconds,url
5385806,5.385806,site1.ru/
5315441,5.315441,site2.ru/1.html
```

## Apache Log Format Configuration

The script works with Apache logs that include the `%D` parameter in the LogFormat directive:

```apache
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined
```

**Key Parameters:**
- `%a`: Client IP address
- `%l`: Client login (usually -)
- `%u`: Username (if authentication is used)
- `%t`: Request time
- `%r`: Request line (e.g., GET /index.html HTTP/1.1)
- `%>s`: HTTP status code
- `%b`: Response size in bytes
- `%{Referer}i`: Referer header
- `%{User-Agent}i`: User-Agent header
- `%D`: Request processing time in microseconds

## Advanced Features

### Custom Log Patterns

For non-standard log formats, you can specify a custom regex pattern:

```json
{
  "log_format": "custom",
  "custom_pattern": "^(\\S+) .* (\\d+)$"
}
```

### Compressed Log Support

The script automatically handles compressed log files:
- `.gz` files (gzip)
- `.bz2` files (bzip2)

### Error Handling

The script includes comprehensive error handling:
- File access errors
- Log parsing errors
- Configuration errors
- Memory management

## Performance Considerations

- **Memory Usage**: Uses streaming processing to handle large log files efficiently
- **Processing Speed**: Optimized with heap-based top-N selection
- **Disk I/O**: Minimal disk operations with buffered reading
- **Scalability**: Can process millions of log entries

## Command Line Options

```bash
python3 apache_slow_log.py --help
```

**Available Options:**
- `--config`, `-c`: Path to JSON configuration file
- `--verbose`, `-v`: Enable verbose logging
- `--top-n`, `-n`: Number of top requests to track
- `--output-format`, `-f`: Output format (text, json, csv)
- `--min-duration`, `-d`: Minimum duration threshold in microseconds

## Monitoring and Automation

### Cron Job Example

```bash
# Run every hour
0 * * * * /usr/bin/python3 /path/to/apache_slow_log.py --config /path/to/config.json

# Run daily with email notification
0 2 * * * /usr/bin/python3 /path/to/apache_slow_log.py --verbose 2>&1 | mail -s "Apache Slow Log Analysis" admin@example.com
```

### Log Rotation

The script works with log rotation systems. Configure your logrotate to preserve timestamps:

```bash
/var/log/apache2/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/bin/python3 /path/to/apache_slow_log.py --config /path/to/config.json
    endscript
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the script has read access to log files
2. **No Log Files Found**: Check the `log_files_glob` pattern
3. **Parsing Errors**: Verify your log format matches the expected pattern
4. **Memory Issues**: Increase `min_duration` to filter out fast requests

### Debug Mode

Run with verbose logging to diagnose issues:

```bash
python3 apache_slow_log.py --verbose
```

---

This script is designed for server administrators who want to optimize their web application performance by analyzing slow requests and identifying bottlenecks in their Apache web server configuration.
