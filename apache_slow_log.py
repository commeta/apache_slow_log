#!/usr/bin/env python3

import os
import re
import heapq

LOG_FILES_GLOB = "/etc/httpd/sites/*/*.conf"
SLOW_LOG_PATH = "/var/log/httpd/slow.log"
TOP_N = 100

def get_log_files():
    grep_command = f"grep -r 'CustomLog' {LOG_FILES_GLOB} | awk -F'CustomLog ' '{{print $2}}' | awk '{{print $1}}'"
    log_files = os.popen(grep_command).read().splitlines()
    return log_files

def parse_log_line(line):
    pattern = re.compile(r'(\S+) - - \[.*\] ".*" \d+ \d+ ".*" ".*" (\d+)')
    match = pattern.match(line)
    if match:
        ip, duration = match.groups()
        return int(duration)
    return None

def extract_domain_from_path(path):
    match = re.search(r'/var/www/([^/]+)/data/logs/([^/]+)-backend.access.log', path)
    if match:
        return match.group(2)
    return None

def get_top_requests(log_files):
    top_requests = []
    
    for log_file in log_files:
        domain = extract_domain_from_path(log_file)
        if not domain:
            continue
        
        with open(log_file, 'r') as f:
            for line in f:
                duration = parse_log_line(line)
                if duration:
                    url_match = re.search(r'"GET (\S+)', line)
                    if url_match:
                        url = url_match.group(1).split('?')[0]
                        request_entry = (duration, f"{domain}{url}")
                        if len(top_requests) < TOP_N:
                            heapq.heappush(top_requests, request_entry)
                        else:
                            heapq.heappushpop(top_requests, request_entry)

    top_requests.sort(reverse=True, key=lambda x: x[0])
    return top_requests

def read_existing_slow_log():
    if not os.path.exists(SLOW_LOG_PATH):
        return []

    existing_entries = []
    with open(SLOW_LOG_PATH, 'r') as f:
        for line in f:
            duration, domain_url = line.strip().split(' ', 1)
            existing_entries.append((int(duration), domain_url))
    
    return existing_entries

def write_slow_log(entries):
    with open(SLOW_LOG_PATH, 'w') as f:
        for duration, domain_url in entries:
            f.write(f"{duration} {domain_url}\n")

def main():
    log_files = get_log_files()
    new_top_requests = get_top_requests(log_files)
    
    existing_entries = read_existing_slow_log()
    
    combined_entries_dict = {}
    
    for duration, domain_url in existing_entries + new_top_requests:
        if domain_url not in combined_entries_dict or combined_entries_dict[domain_url] < duration:
            combined_entries_dict[domain_url] = duration
    
    combined_entries = [(duration, domain_url) for domain_url, duration in combined_entries_dict.items()]
    combined_entries.sort(reverse=True, key=lambda x: x[0])
    
    if len(combined_entries) > TOP_N:
        combined_entries = combined_entries[:TOP_N]
    
    write_slow_log(combined_entries)

if __name__ == "__main__":
    main()
