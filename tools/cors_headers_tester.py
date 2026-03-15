"""
CORS & Security Headers Tester
Tests for CORS misconfigurations, caching issues, and missing security headers
"""

from langchain.tools import tool
import subprocess
import json


SECURITY_HEADERS = {
    "X-Frame-Options": "DENY or SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "restrictive policy",
    "Strict-Transport-Security": "max-age > 0",
    "Referrer-Policy": "no-referrer or strict-origin",
    "Permissions-Policy": "geolocation=()",
    "X-Permitted-Cross-Domain-Policies": "none",
}

CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@tool
def test_cors_misconfiguration(target_url: str) -> dict:
    """
    Test for CORS (Cross-Origin Resource Sharing) vulnerabilities
    
    Args:
        target_url: Target URL to test
    
    Returns:
        Dictionary with CORS findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Test 1: Credentials with wildcard origin
    origins_to_test = [
        "http://attacker.com",
        "http://anything.example.com",
        "null",
    ]
    
    for origin in origins_to_test:
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-m", "5", "-H",
                    f"Origin: {origin}",
                    "-H", "Access-Control-Request-Method: GET",
                    "-X", "OPTIONS",
                    target_url
                ],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response_lower = result.stdout.lower()
            
            # Check for CORS headers
            if "access-control-allow-origin" in response_lower:
                if "*" in result.stdout or origin in result.stdout:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"CORS allows origin: {origin}")
                    
                    # Check if credentials are allowed
                    if "access-control-allow-credentials: true" in response_lower:
                        findings["vulnerable"] = True
                        findings["findings"].append(f"CORS credentials exposed to: {origin}")
                
                findings["evidence"].append({
                    "origin": origin,
                    "response": result.stdout[:300]
                })
        
        except Exception:
            pass
    
    # Test 2: Preflight bypass
    try:
        result = subprocess.run(
            [
                "curl", "-s", "-m", "5",
                "-H", "Origin: http://attacker.com",
                "-H", "Access-Control-Request-Headers: X-Custom-Header",
                target_url
            ],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "access-control-allow-headers" in result.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Preflight request allows custom headers")
    
    except Exception:
        pass
    
    return findings


@tool
def test_missing_security_headers(target_url: str) -> dict:
    """
    Test for missing or weak security headers
    
    Args:
        target_url: Target URL to test
    
    Returns:
        Dictionary with missing headers findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "missing_headers": [],
        "weak_headers": []
    }
    
    try:
        # Get response headers
        result = subprocess.run(
            ["curl", "-s", "-m", "5", "-i", target_url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        response_lower = result.stdout.lower()
        
        # Check for missing security headers
        for header, description in SECURITY_HEADERS.items():
            if header.lower() not in response_lower:
                findings["vulnerable"] = True
                findings["missing_headers"].append(header)
                findings["findings"].append(f"Missing header: {header}")
        
        # Check for weak CSP
        if "content-security-policy" in response_lower:
            if "unsafe-inline" in response_lower or "unsafe-eval" in response_lower:
                findings["vulnerable"] = True
                findings["weak_headers"].append("CSP: unsafe-inline or unsafe-eval detected")
                findings["findings"].append("Weak CSP allows inline/eval scripts")
        
        # Check for missing HSTS
        if "strict-transport-security" not in response_lower:
            findings["vulnerable"] = True
            findings["missing_headers"].append("Strict-Transport-Security")
            findings["findings"].append("Missing HSTS header - vulnerable to downgrade attacks")
        
        # Check for missing X-Frame-Options
        if "x-frame-options" not in response_lower:
            findings["vulnerable"] = True
            findings["missing_headers"].append("X-Frame-Options")
            findings["findings"].append("Missing X-Frame-Options - vulnerable to clickjacking")
        
    except Exception:
        pass
    
    return findings


@tool
def test_cache_poisoning(target_url: str) -> dict:
    """
    Test for cache poisoning and caching vulnerabilities
    
    Args:
        target_url: Target URL to test
    
    Returns:
        Dictionary with caching findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    try:
        # Check Cache-Control headers
        result = subprocess.run(
            ["curl", "-s", "-m", "5", "-i", target_url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        response_lower = result.stdout.lower()
        
        # Test 1: Caching of sensitive data
        if "cache-control" not in response_lower:
            findings["vulnerable"] = True
            findings["findings"].append("No Cache-Control header - may cache sensitive data")
            findings["evidence"].append("Missing Cache-Control directive")
        
        elif "public" in response_lower:
            # Check if sensitive endpoint is cached publicly
            if any(keyword in target_url.lower() for keyword in ["api", "user", "account", "admin"]):
                findings["vulnerable"] = True
                findings["findings"].append(f"Sensitive endpoint cached publicly: {target_url}")
        
        # Test 2: Unvalidated cache parameters
        cache_params = [
            "?cache=1",
            "?debug=1",
            "?X-Original-URL=/admin",
        ]
        
        for param in cache_params:
            test_url = target_url + param
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                if len(result.stdout) > 100:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"Cache bypass via parameter: {param}")
            
            except Exception:
                pass
        
        # Test 3: Cache key manipulation
        headers_to_test = [
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Forwarded-For", "127.0.0.1"),
        ]
        
        for header, value in headers_to_test:
            try:
                result = subprocess.run(
                    [
                        "curl", "-s", "-m", "5",
                        "-H", f"{header}: {value}",
                        target_url
                    ],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                if len(result.stdout) > 100 and "error" not in result.stdout.lower():
                    findings["vulnerable"] = True
                    findings["findings"].append(f"Cache key manipulation via {header}")
                    findings["evidence"].append({"header": header, "value": value})
            
            except Exception:
                pass
    
    except Exception:
        pass
    
    return findings


@tool
def test_http_response_splitting(target_url: str) -> dict:
    """
    Test for HTTP Response Splitting vulnerabilities
    
    Args:
        target_url: Target URL to test
    
    Returns:
        Dictionary with response splitting findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Response splitting payloads
    payloads = [
        "test%0d%0aSet-Cookie: admin=true",
        "test%0d%0aX-Injected-Header: injected",
        "test%0aX-Injected: value",
    ]
    
    for payload in payloads:
        test_url = f"{target_url}?param={payload}"
        
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-i", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout
            
            # Check if injection succeeded
            if "X-Injected" in response or "Set-Cookie: admin" in response:
                findings["vulnerable"] = True
                findings["findings"].append(f"HTTP Response Splitting via param injection")
                findings["evidence"].append({
                    "payload": payload,
                    "response": response[:300]
                })
        
        except Exception:
            pass
    
    return findings


@tool
def test_host_header_injection(target_url: str) -> dict:
    """
    Test for Host header injection vulnerabilities
    
    Args:
        target_url: Target URL to test
    
    Returns:
        Dictionary with host header injection findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    malicious_hosts = [
        "attacker.com",
        "localhost",
        "internal-server",
        "127.0.0.1",
    ]
    
    for host in malicious_hosts:
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-m", "5",
                    "-H", f"Host: {host}",
                    target_url
                ],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            
            # Check if host is reflected or causes behavior change
            if host in response or "welcome" in response:
                findings["vulnerable"] = True
                findings["findings"].append(f"Host header injection detected: {host}")
                findings["evidence"].append({
                    "host": host,
                    "response_contains": host in response
                })
        
        except Exception:
            pass
    
    return findings
