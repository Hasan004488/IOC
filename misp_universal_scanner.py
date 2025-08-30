#!/usr/bin/env python3
"""
Universal MISP Scanner for Multiple Indicator Types
Handles IP addresses, SHA256, MD5, hostnames, and domains
"""
import sys
import json
import time
import re
import requests
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# --- Configuration ---
@dataclass
class MispConfig:
    url: str = os.getenv('MISP_URL', 'http://localhost:8080') # Default to a common local MISP URL
    api_key: str = os.getenv('MISP_API_KEY', 'YOUR_MISP_API_KEY')
    verify_ssl: bool = os.getenv('MISP_VERIFY_SSL', 'False').lower() in ('true', '1', 't')
    timeout: int = int(os.getenv('MISP_TIMEOUT', '60'))
    max_workers: int = int(os.getenv('MISP_MAX_WORKERS', '10'))

# --- Logging Setup (Disabled) ---
# **FIX**: All logging has been removed to prevent log file creation.
logging.getLogger(__name__).addHandler(logging.NullHandler())

# --- Main Scanner Class ---
class MispScanner:
    def __init__(self, config: MispConfig):
        self.config = config
        if not config.api_key or config.api_key == 'YOUR_MISP_API_KEY':
            raise ValueError("MISP_API_KEY is not configured. Please set it in your .env file.")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': config.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'Universal-MISP-Scanner/2.3'
        })
        self.session.verify = config.verify_ssl
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def detect_indicator_type(indicator: str) -> Optional[str]:
        indicator = indicator.strip()
        if re.match(r'^[a-fA-F0-9]{64}$', indicator): return 'sha256'
        if re.match(r'^[a-fA-F0-9]{32}$', indicator): return 'md5'
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', indicator): return 'ip'
        if ':' in indicator: return 'ip' # Basic IPv6 check
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
            if indicator.count('.') > 1:
                return 'hostname'
            return 'domain'
        return None

    def query_misp(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        result = {'indicator': indicator, 'type': indicator_type, 'mispEventCount': 0, 'attributes': [], 'error': None}
        search_url = f"{self.config.url}/attributes/restSearch"
        search_payload = {'value': indicator, 'includeEventTags': True}

        try:
            response = self.session.post(search_url, json=search_payload, timeout=self.config.timeout)
            response.raise_for_status()
            
            data = response.json()
            if 'response' in data and data['response']:
                attributes = data['response'].get('Attribute', [])
                result['mispEventCount'] = len(attributes)
                result['attributes'] = attributes
                if len(attributes) >= 5: result['threatLevel'] = 'high'
                elif len(attributes) > 0: result['threatLevel'] = 'medium'
                else: result['threatLevel'] = 'low'
        
        except requests.exceptions.RequestException as e:
            result['error'] = "Request error"
        except Exception as e:
            result['error'] = "Unexpected error"
            
        return result

    def scan_indicators(self, indicators: List[str]) -> List[Dict[str, Any]]:
        results = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_indicator = {}
            for indicator in indicators:
                indicator_type = self.detect_indicator_type(indicator)
                if indicator_type:
                    future_to_indicator[executor.submit(self.query_misp, indicator, indicator_type)] = indicator
                else:
                    results.append({'indicator': indicator, 'type': 'unknown', 'error': 'Unknown type'})

            for future in as_completed(future_to_indicator):
                indicator = future_to_indicator[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({'indicator': indicator, 'error': str(e)})
        return results

def main():
    if len(sys.argv) < 2:
        print(json.dumps([{"error": "No indicators provided"}]))
        sys.exit(1)
        
    indicators = list(set(sys.argv[1:]))
    
    try:
        config = MispConfig()
        scanner = MispScanner(config)
        results = scanner.scan_indicators(indicators)
        print(json.dumps(results, separators=(',', ':')))
        
    except Exception as e:
        print(json.dumps([{"error": str(e)}]))
        sys.exit(1)

if __name__ == "__main__":
    main()
