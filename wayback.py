#!/usr/bin/env python3
"""
Roger Wayback - Wayback Machine scanner for bug bounty hunting.
"""

import argparse
import concurrent.futures
import requests
import urllib3
import re
import json
import sys
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAYBACK_API = "http://web.archive.org/cdx/search/cdx"


class RogerWayback:
    def __init__(self, target, extensions=None, endpoints_only=False, 
                 threads=10, depth=1000, quiet=False, output=None):
        self.target = target
        self.extensions = extensions or []
        self.endpoints_only = endpoints_only
        self.threads = threads
        self.depth = depth
        self.quiet = quiet
        self.output = output
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.findings = []
        
    def get_wayback_urls(self):
        """Get all archived URLs for target."""
        params = {
            "url": f"*.{self.target}/*",
            "output": "json",
            "limit": self.depth,
            "matchType": "prefix",
            "filter": "statuscode:200",
            "collapse": "urlkey"
        }
        
        try:
            response = self.session.get(WAYBACK_API, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data:
                    # Skip header row
                    return [row[2] for row in data[1:] if len(row) >= 3]
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error fetching Wayback data: {e}")
        
        return []
    
    def filter_urls(self, urls):
        """Filter URLs by extensions and patterns."""
        filtered = []
        
        for url in urls:
            # Filter by extension
            if self.extensions:
                ext_match = False
                for ext in self.extensions:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    if url.endswith(ext):
                        ext_match = True
                        break
                if not ext_match:
                    continue
            
            # Filter endpoints if requested
            if self.endpoints_only:
                endpoint_patterns = [
                    '/api/', '/v1/', '/v2/', '/v3/', '/graphql', 
                    '/rest/', '/admin/', '/internal/', '/private/',
                    '/debug/', '/cgi-bin/', '/ajax/', '/wp-json/'
                ]
                if not any(pattern in url for pattern in endpoint_patterns):
                    continue
            
            filtered.append(url)
        
        return filtered
    
    def analyze_urls(self, urls):
        """Analyze URLs for interesting patterns."""
        patterns = {
            "API Endpoints": [],
            "Admin Panels": [],
            "Backup Files": [],
            "Source Code": [],
            "Debug Pages": [],
            "Parameters": [],
            "JavaScript": [],
            "Other": []
        }
        
        # Patterns to look for
        api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']
        admin_patterns = ['/admin', '/administrator', '/manage', '/panel', '/control']
        backup_patterns = ['.bak', '.backup', '.old', '.tmp', '.swp', '.save']
        source_patterns = ['.js.map', '.ts', '.vue', '.jsx', '.scss', '.sass']
        debug_patterns = ['/debug', '/test', '/staging', '/dev', '/sandbox']
        param_pattern = r'\?(\w+)='
        
        for url in urls:
            categorized = False
            
            # API endpoints
            if any(p in url for p in api_patterns):
                patterns["API Endpoints"].append(url)
                categorized = True
            
            # Admin panels
            if any(p in url for p in admin_patterns):
                patterns["Admin Panels"].append(url)
                categorized = True
            
            # Backup files
            if any(p in url for p in backup_patterns):
                patterns["Backup Files"].append(url)
                categorized = True
            
            # Source code
            if any(p in url for p in source_patterns):
                patterns["Source Code"].append(url)
                categorized = True
            
            # Debug pages
            if any(p in url for p in debug_patterns):
                patterns["Debug Pages"].append(url)
                categorized = True
            
            # JavaScript
            if url.endswith('.js'):
                patterns["JavaScript"].append(url)
                categorized = True
            
            # Parameters
            params = re.findall(param_pattern, url)
            if params:
                for param in params[:5]:  # Limit params per URL
                    patterns["Parameters"].append(f"{url} -> {param}")
                categorized = True
            
            # Other
            if not categorized:
                patterns["Other"].append(url)
        
        return patterns
    
    def extract_params(self, urls):
        """Extract all unique parameters from URLs."""
        params = set()
        param_pattern = r'\?(\w+)='
        
        for url in urls:
            found = re.findall(param_pattern, url)
            params.update(found)
        
        return sorted(list(params))
    
    def scan(self):
        """Run the Wayback scanner."""
        print(f"[*] Starting Wayback scan for: {self.target}")
        print(f"[*] Max results: {self.depth}")
        if self.extensions:
            print(f"[*] Extensions filter: {', '.join(self.extensions)}")
        print("=" * 60)
        
        # Fetch archived URLs
        print("[*] Fetching Wayback Machine data...")
        urls = self.get_wayback_urls()
        
        if not urls:
            print("[!] No archived URLs found!")
            return []
        
        print(f"[*] Found {len(urls)} archived URLs")
        
        # Filter URLs
        filtered = self.filter_urls(urls)
        print(f"[*] After filtering: {len(filtered)} URLs")
        
        # Analyze
        print("[*] Analyzing URLs...")
        patterns = self.analyze_urls(filtered)
        
        # Extract parameters
        all_params = self.extract_params(filtered)
        
        # Print results
        print()
        print("=" * 60)
        print("[+] Results:")
        print()
        
        total_findings = 0
        
        for category, urls_list in patterns.items():
            if urls_list:
                unique_urls = list(set(urls_list))
                print(f"[*] {category}: {len(unique_urls)}")
                
                for url in unique_urls[:20]:  # Show first 20
                    print(f"  - {url}")
                
                if len(unique_urls) > 20:
                    print(f"  ... and {len(unique_urls) - 20} more")
                
                print()
                total_findings += len(unique_urls)
        
        # Parameters
        if all_params:
            print(f"[*] Unique Parameters Found: {len(all_params)}")
            print(f"  {', '.join(all_params[:50])}")
            if len(all_params) > 50:
                print(f"  ... and {len(all_params) - 50} more")
            print()
        
        # Save results
        if self.output:
            with open(self.output, 'w') as f:
                f.write(f"# Wayback Scan Results for {self.target}\n\n")
                f.write(f"Total archived URLs: {len(urls)}\n")
                f.write(f"After filtering: {len(filtered)}\n\n")
                
                for category, urls_list in patterns.items():
                    if urls_list:
                        unique_urls = list(set(urls_list))
                        f.write(f"## {category} ({len(unique_urls)})\n\n")
                        for url in unique_urls:
                            f.write(f"- {url}\n")
                        f.write("\n")
                
                if all_params:
                    f.write(f"## Parameters Found ({len(all_params)})\n\n")
                    f.write(", ".join(all_params) + "\n")
        
        print(f"[*] Total findings: {total_findings}")
        
        return patterns


def main():
    parser = argparse.ArgumentParser(
        description="Roger Wayback - Wayback Machine scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target domain (e.g., target.com)")
    parser.add_argument("-e", "--extensions", help="Filter by extensions (comma-separated)")
    parser.add_argument("-E", "--endpoints", action="store_true", help="Only show API endpoints")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-d", "--depth", type=int, default=1000, help="Max results to fetch")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    
    args = parser.parse_args()
    
    # Parse extensions
    extensions = []
    if args.extensions:
        extensions = [e.strip() for e in args.extensions.split(',')]
    
    scanner = RogerWayback(
        target=args.target,
        extensions=extensions,
        endpoints_only=args.endpoints,
        threads=args.threads,
        depth=args.depth,
        quiet=args.quiet,
        output=args.output
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()