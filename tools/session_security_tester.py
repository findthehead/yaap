"""
Session Security Tester
Tests for session management vulnerabilities including fixation, hijacking, and timeout
"""

from langchain.tools import tool
import subprocess
import re
import time


@tool
def test_session_security(url: str) -> dict:
    """
    Test session management security
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with session security findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "cookie_analysis": {},
        "evidence": []
    }
    
    try:
        # Make request and capture cookies
        result = subprocess.run(
            ["curl", "-s", "-i", "-c", "/tmp/session_cookies.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        response = result.stdout
        headers = response.lower()
        
        # Check for secure session cookie attributes
        security_issues = {
            "httponly": ("HttpOnly flag missing on session cookie", "High"),
            "secure": ("Secure flag missing (transmits over HTTP)", "Critical"),
            "samesite": ("SameSite attribute missing", "Medium"),
        }
        
        for flag, (message, severity) in security_issues.items():
            if f"{flag}" not in headers:
                findings["vulnerable"] = True
                findings["findings"].append(message)
                findings["evidence"].append({
                    "issue": message,
                    "severity": severity
                })
        
        # Check cookie length and randomness
        if "set-cookie" in headers:
            cookies = re.findall(r'set-cookie:\s*([^;\n]+)', headers)
            for cookie in cookies:
                if "session" in cookie.lower() or "sid" in cookie.lower():
                    value = cookie.split("=")[1] if "=" in cookie else ""
                    
                    # Check if value is too short (weak randomness)
                    if len(value) < 16:
                        findings["vulnerable"] = True
                        findings["findings"].append(f"Session token too short ({len(value)} chars)")
                        findings["evidence"].append({
                            "issue": "Weak session token generation",
                            "severity": "High",
                            "token_length": len(value)
                        })
        
        findings["cookie_analysis"] = {
            "total_headers": len(response.split('\n')),
            "has_set_cookie": "set-cookie" in headers
        }
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_session_fixation(url: str) -> dict:
    """
    Test for session fixation vulnerabilities
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with session fixation findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "session_changes": []
    }
    
    try:
        # First request: Get initial session
        result1 = subprocess.run(
            ["curl", "-s", "-i", "-c", "/tmp/session1.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        # Extract session ID from first request
        session1_match = re.search(r'set-cookie:\s*([^;\n]+)', result1.stdout, re.IGNORECASE)
        session1 = session1_match.group(1) if session1_match else None
        
        # Second request: Anonymous request
        result2 = subprocess.run(
            ["curl", "-s", "-i", "-b", "/tmp/session1.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        session2_match = re.search(r'set-cookie:\s*([^;\n]+)', result2.stdout, re.IGNORECASE)
        session2 = session2_match.group(1) if session2_match else None
        
        # If session remains the same after navigation = fixation vulnerability
        if session1 and session2 and session1 == session2:
            findings["vulnerable"] = True
            findings["findings"].append("Session ID not regenerated on page navigation")
            findings["session_changes"].append({
                "before": session1[:20],
                "after": session2[:20],
                "changed": False
            })
        
    except Exception:
        pass
    
    return findings


@tool
def test_session_timeout(url: str, timeout_seconds: int = 5) -> dict:
    """
    Test session timeout behavior
    
    Args:
        url: Target URL to test
        timeout_seconds: Seconds to wait before second request
    
    Returns:
        Dictionary with session timeout findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "timeout_behavior": {}
    }
    
    try:
        # First request
        result1 = subprocess.run(
            ["curl", "-s", "-i", "-c", "/tmp/session_timeout.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        session1 = result1.stdout
        
        # Wait for timeout
        time.sleep(timeout_seconds)
        
        # Second request with same cookies
        result2 = subprocess.run(
            ["curl", "-s", "-i", "-b", "/tmp/session_timeout.txt", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        session2 = result2.stdout
        
        # Check if session is still valid
        if "401" not in session2 and "403" not in session2:
            # Session still valid after timeout
            findings["vulnerable"] = True
            findings["findings"].append(f"Session not invalidated after {timeout_seconds}s inactivity")
            findings["evidence"] = {
                "timeout_behavior": "Session remained valid",
                "severity": "Medium"
            }
        else:
            findings["timeout_behavior"] = {
                "timeout_enforced": True,
                "timeout_seconds": timeout_seconds
            }
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings
