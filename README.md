# Description of the apache_slow_log.py script

[На Русском](README_RU.md)


This script analyzes Apache logs to identify the slowest requests to the server. It extracts request information from configuration files, locates corresponding logs, and creates a list of the 100 slowest requests based on the server response time recorded in microseconds.
## Functionality

- Log Retrieval: The script searches all Apache configuration files for the CustomLog directive to determine the locations of the log files.
- Log Parsing: Each log line is analyzed to extract the IP address and request execution time.
- Domain Extraction: The domain is extracted from the log file path.
- Top Request Identification: The script collects request data and stores only the 100 slowest, using the heapq data structure for efficient memory management.
- Data Aggregation: The script compares new data with existing data in slow.log, updating entries if new requests are slower than older ones.
- File Writing: The results are saved to the slow.log file.

## Time Format

Request execution times are recorded in microseconds. To convert this value to seconds, use the following formula:

Time (in seconds) = Time (in microseconds) / 1,000,000
## Example Output

The output of the script may look like this:

- 5385806 site1.ru/
- 5315441 site2.ru/1.html
- 4991294 site3.ru/
- 4703806 site1.ru/3.html
- 4699142 site1.ru/10.html

## Installation and Usage

- Copy the script to the server with Python 3 installed.

- Ensure you have access to the Apache logs.

- Configure the LOG_FILES_GLOB and SLOW_LOG_PATH variables if necessary.

- Run the script:

`python3 apache_slow_log.py`

## Dependencies

- Python 3
- Standard library modules: os, re, heapq

Description of the %D Parameter in Apache Log Format Configuration (LogFormat)

- %D: This parameter outputs the time taken to process the request in microseconds. This value includes all stages of request processing, including the time spent executing application code and the time needed to transmit the response to the client.

## Example Log Format

In the example, the log format looks like this:

LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined

Here:

- %a: Client IP address.
- %l: Client login (usually -).
- %u: Username (if authentication is used).
- %t: Request time.
- %r: Request that was executed (e.g., GET /index.html HTTP/1.1).
- %>s: HTTP status code.
- %b: Response size in bytes.
- %{Referer}i: Referer header from the request.
- %{User-Agent}i: User-Agent header from the request.
- %D: Request execution time in microseconds.

## How it Relates to the Script

- Log Parsing: The apache_slow_log.py script reads lines from Apache logs with the format shown above. During parsing, it searches for the %D value to determine how long each request took to process.

- Slow Request Analysis: The script collects data about all requests and their execution times to compile a list of the 100 slowest. Because %D provides execution time in microseconds, the script can easily compare and sort these values.

- Result Saving: After analysis, the script saves the results to the slow.log file, which lists the slowest requests, allowing server administrators to quickly identify problem areas and optimize performance.

Therefore, the %D parameter is key to the script’s operation, as it provides the necessary information about request processing times, enabling the efficient identification and analysis of slow requests to the server.
## License

This project is licensed under the MIT License.

This script is intended for server administrators who want to optimize the performance of their web applications by analyzing slow requests.
