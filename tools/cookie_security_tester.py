"""
Cookie Security Tester
Tests for cookie misconfiguration, insecure transmission, and sensitive data exposure
"""

from langchain.tools import tool
import subprocess
import re


COOKIE_SECURITY_FLAGS = {
    "secure": {
        "description": "Cookie not transmitted over HTTPS",
        "severity": "High"
    },
    "httponly": {
        "description": "Cookie accessible to JavaScript (XSS risk)",
        "severity": "High"
    },
    "samesite": {
        "description": "Cookie lacks SameSite attribute (CSRF risk)",
        "severity": "Medium"
    },
    "domain": {
        "description": "Cookie domain overly permissive",
        "severity": "Medium"
    },
    "expiration": {
        "description": "Cookie lacking proper expiration",
        "severity": "Low"
    }
}


@tool
def test_cookie_security(url: str) -> dict:
    """
    Test cookie security attributes and configuration
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with cookie security findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "cookies_analyzed": [],
        "evidence": []
    }
    
    try:
        result = subprocess.run(
            ["curl", "-s", "-i", "-k", "-m", "10", url],
            capture_output=True,
            timeout=15,
            text=True
        )
        
        headers = result.stdout
        
        # Extract Set-Cookie headers
        cookie_matches = re.findall(r'set-cookie:\s*([^\n]+)', headers, re.IGNORECASE)
        
        for cookie in cookie_matches:
            cookie_analysis = {
                "name": None,
                "issues": [],
                "severity": "Low"
            }
            
            # Parse cookie name
            if "=" in cookie:
                name_part = cookie.split("=")[0].strip()
                cookie_analysis["name"] = name_part
            
            # Check security flags
            cookie_lower = cookie.lower()
            
            # Secure flag
            if "secure" not in cookie_lower:
                cookie_analysis["issues"].append("Missing Secure flag")
                cookie_analysis["severity"] = "High"
                findings["vulnerable"] = True
            
            # HttpOnly flag  
            if "httponly" not in cookie_lower:
                cookie_analysis["issues"].append("Missing HttpOnly flag (XSS risk)")
                if cookie_analysis["severity"] != "High":
                    cookie_analysis["severity"] = "High"
                findings["vulnerable"] = True
            
            # SameSite attribute
            if "samesite" not in cookie_lower:
                cookie_analysis["issues"].append("Missing SameSite attribute (CSRF risk)")
                findings["vulnerable"] = True
            
            # Check for sensitive data in cookie value
            if "=" in cookie:
                value = cookie.split("=")[1].split(";")[0]
                
                sensitive_patterns = [
                    ("password", r"pass|pwd|secret"),
                    ("credentials", r"token|auth|credential"),
                    ("userdata", r"user|email|id|name"),
                ]
                
                for sensitive_type, pattern in sensitive_patterns:
                    if re.search(pattern, cookie_analysis["name"].lower() if cookie_analysis["name"] else ""):
                        cookie_analysis["issues"].append(
                            f"Sensitive data in cookie name: {sensitive_type}"
                        )
                        findings["vulnerable"] = True
            
            if cookie_analysis["issues"]:
                findings["cookies_analyzed"].append(cookie_analysis)
                findings["findings"].extend(cookie_analysis["issues"])
                findings["evidence"].append({
                    "cookie": cookie_analysis["name"],
                    "issues": cookie_analysis["issues"],
                    "severity": cookie_analysis["severity"]
                })
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_cookie_reuse(url: str) -> dict:
    """
    Test for cookie reuse and session fixation via cookies
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with cookie reuse findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "reusable_cookies": []
    }
    
    try:
        # First request
        result1 = subprocess.run(
            ["curl", "-s", "-c", "/tmp/cookies.txt", "-m", "5", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        # Read cookies from file
        with open("/tmp/cookies.txt", "r") as f:
            cookies = f.read()
        
        # Extract session-like cookies
        session_cookies = re.findall(r'^[^#].*\t([^\t]+)$', cookies, re.MULTILINE)
        
        for cookie in session_cookies:
            # Try reusing cookie from different IP/User-Agent
            result2 = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-b", f"Cookie={cookie}",
                 "-H", "User-Agent: Different-Agent", "-m", "5", url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result2.stdout[-3:] if len(result2.stdout) >= 3 else "000"
            
            if status == "200":
                findings["vulnerable"] = True
                findings["reusable_cookies"].append(cookie)
                findings["findings"].append(
                    "Session cookie reusable from different clients (no IP/User-Agent binding)"
                )
    
    except Exception:
        pass
    
    findings["evidence"] = {
        "reusable_count": len(findings["reusable_cookies"])
    }
    
    return findings


@tool
def test_cookie_disclosure(url: str) -> dict:
    """
    Test for cookie disclosure in HTTP responses
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with cookie disclosure findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "disclosure_vectors": []
    }
    
    try:
        # Test for various disclosure vectors
        
        # 1. Cookies in URL parameters (logs, referrer)
        result = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", f"{url}?session=test123&token=abc"],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "session=" in result.stdout or "token=" in result.stdout:
            findings["vulnerable"] = True
            findings["findings"].append("Sensitive data transmitted in URL parameters")
            findings["disclosure_vectors"].append("URL parameters")
        
        # 2. Cookies in GET requests (should use POST)
        result2 = subprocess.run(
            ["curl", "-s", "-i", "-X", "GET", "-b", "session=test", "-m", "5", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "cookie" in result2.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Session cookies used in GET requests (cacheable)")
            findings["disclosure_vectors"].append("Cacheable GET requests")
        
        # 3. Cookies in error messages
        result3 = subprocess.run(
            ["curl", "-s", "-m", "5", f"{url}?error=invalid"],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "session" in result3.stdout.lower() or "token" in result3.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Session identification in error responses")
            findings["disclosure_vectors"].append("Error messages")
    
    except Exception:
        pass
    
    return findings
