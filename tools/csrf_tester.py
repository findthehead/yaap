"""
CSRF (Cross-Site Request Forgery) Vulnerability Tester
Tests for CSRF token validation and protection mechanisms
"""

from langchain.tools import tool
import subprocess
import re
from urllib.parse import urlparse


CSRF_TEST_PAYLOADS = {
    "no_token": {
        "description": "Submit form without CSRF token",
        "payload": "no_token"
    },
    "token_reuse": {
        "description": "Reuse CSRF token from different origin",
        "payload": "reuse"
    },
    "token_removal": {
        "description": "Remove CSRF token parameter",
        "payload": "remove"
    },
    "token_tampering": {
        "description": "Modify CSRF token value",
        "payload": "alter"
    },
    "different_origin": {
        "description": "Submit from different origin",
        "payload": "cors"
    },
    "get_to_post": {
        "description": "Convert GET request to POST",
        "payload": "method_change"
    }
}


@tool
def test_csrf_protection(url: str, form_name: str = None) -> dict:
    """
    Test endpoint for CSRF vulnerabilities
    
    Args:
        url: Target URL with form submission endpoint
        form_name: Name of form to test (if multiple forms)
    
    Returns:
        Dictionary with CSRF findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "csrf_tokens_found": [],
        "evidence": []
    }
    
    try:
        # First request: Get the page and extract CSRF tokens
        result = subprocess.run(
            ["curl", "-s", "-c", "/tmp/cookies.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        response = result.stdout
        
        # Look for common CSRF token patterns
        csrf_patterns = [
            r'csrf["\']?\s*[:=]\s*["\']?([a-f0-9]+)',
            r'_token["\']?\s*[:=]\s*["\']?([a-f0-9]+)',
            r'authenticity_token["\']?\s*[:=]\s*["\']?([a-f0-9]+)',
            r'token["\']?\s*[:=]\s*["\']?([a-f0-9]+)',
            r'_csrf["\']?\s*[:=]\s*["\']?([a-f0-9]+)',
        ]
        
        csrf_tokens = []
        for pattern in csrf_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            csrf_tokens.extend(matches)
        
        if csrf_tokens:
            findings["csrf_tokens_found"] = list(set(csrf_tokens))
        else:
            # No token found = vulnerable
            findings["vulnerable"] = True
            findings["findings"].append("No CSRF token found in form")
            findings["evidence"].append({
                "issue": "Missing CSRF Protection",
                "severity": "High",
                "description": "Form does not implement CSRF tokens"
            })
        
        # Test form submission without token
        if csrf_tokens:
            # Try with altered token
            test_token = csrf_tokens[0][:-2] + "XX"
            
            result2 = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-b", "/tmp/cookies.txt",
                 "-X", "POST", "-d", f"csrf_token={test_token}", url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result2.stdout[-3:] if len(result2.stdout) >= 3 else "000"
            
            # If 200 with tampered token = vulnerable
            if status == "200":
                findings["vulnerable"] = True
                findings["findings"].append("CSRF token validation is weak or missing")
                findings["evidence"].append({
                    "test": "Token tampering",
                    "status": status,
                    "severity": "High"
                })
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_samesite_cookie_enforcement(url: str) -> dict:
    """
    Test for SameSite cookie attribute enforcement
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with SameSite findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "cookies_checked": 0
    }
    
    try:
        result = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout.lower()
        
        # Check for Set-Cookie headers
        if "set-cookie" in headers:
            # Count cookies without SameSite
            if "samesite" not in headers.split("set-cookie")[1]:
                findings["vulnerable"] = True
                findings["findings"].append("Cookies missing SameSite attribute")
                findings["vulnerable"] = True
        
        # Check for CSRF protection headers
        if "x-csrf-token" not in headers and "x-xsrf-token" not in headers:
            findings["findings"].append("No CSRF token in response headers")
    
    except Exception:
        pass
    
    return findings
