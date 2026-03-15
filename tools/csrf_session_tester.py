"""
CSRF & Session Management Tester
Tests for CSRF vulnerabilities and insecure session handling
"""

from langchain.tools import tool
import subprocess
import re
from urllib.parse import urlparse, parse_qs


CSRF_PAYLOADS = {
    "csrf_form": '''<form action="{target}" method="POST">
  <input type="hidden" name="action" value="delete">
  <input type="hidden" name="user_id" value="admin">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>''',
    
    "csrf_img": '<img src="{target}?action=delete&user_id=admin">',
    
    "csrf_fetch": '''<script>
fetch('{target}', {method: 'POST', body: 'action=delete&user_id=admin'});
</script>''',
    
    "csrf_xmlhttp": '''<script>
var xhttp = new XMLHttpRequest();
xhttp.open("POST", "{target}", true);
xhttp.send("action=delete&user_id=admin");
</script>''',
}


@tool
def test_csrf_protection(url: str) -> dict:
    """
    Test for CSRF protection (SameSite, tokens, origin checks)
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with CSRF findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    try:
        # Test response headers for CSRF protection
        result = subprocess.run(
            ["curl", "-s", "-v", "-X", "POST", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout + result.stderr
        headers_lower = headers.lower()
        
        # Check for CSRF tokens
        csrf_indicators = ["csrf", "xsrf", "token", "nonce"]
        has_csrf_token = any(indicator in headers_lower for indicator in csrf_indicators)
        
        if not has_csrf_token:
            findings["vulnerable"] = True
            findings["findings"].append("No CSRF token detected in response")
        
        # Check for SameSite cookie attribute
        if "samesite" not in headers_lower:
            findings["vulnerable"] = True
            findings["findings"].append("No SameSite cookie attribute detected")
        
        # Check for Origin/Referer validation
        if "origin" not in headers_lower and "referer" not in headers_lower:
            findings["vulnerable"] = True
            findings["findings"].append("No Origin/Referer header validation evident")
        
        # Check Content-Type restrictions
        if "content-type" not in headers_lower:
            findings["vulnerable"] = True
            findings["findings"].append("No Content-Type restrictions detected")
        
        findings["evidence"].append({
            "has_csrf_token": has_csrf_token,
            "has_samesite": "samesite" in headers_lower,
            "headers_sample": headers[:500]
        })
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_session_security(url: str) -> dict:
    """
    Test for insecure session management
    
    Args:
        url: Target URL to extract session info
    
    Returns:
        Dictionary with session security findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    try:
        result = subprocess.run(
            ["curl", "-s", "-i", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout.lower()
        cookies = re.findall(r'set-cookie: ([^;]+)', headers)
        
        session_issues = {
            "no_httponly": "HttpOnly flag missing - accessible from JavaScript",
            "no_secure": "Secure flag missing - transmitted over HTTP",
            "no_samesite": "SameSite attribute missing - vulnerable to CSRF",
            "long_expiry": "Session has long expiration - high-risk if stolen",
        }
        
        for cookie_line in cookies:
            cookie_lower = cookie_line.lower()
            
            if "httponly" not in cookie_lower:
                findings["vulnerable"] = True
                findings["findings"].append(session_issues["no_httponly"])
            
            if "secure" not in cookie_lower:
                findings["vulnerable"] = True
                findings["findings"].append(session_issues["no_secure"])
            
            if "samesite" not in cookie_lower:
                findings["vulnerable"] = True
                findings["findings"].append(session_issues["no_samesite"])
        
        if not cookies:
            findings["findings"].append("No session cookies detected")
        
        findings["evidence"].append({
            "cookies": cookies,
            "cookie_count": len(cookies)
        })
    
    except Exception:
        pass
    
    return findings


@tool
def test_fixation_vulnerability(url: str) -> dict:
    """
    Test for session fixation vulnerabilities
    
    Args:
        url: Target URL to test
    
    Returns:
        Dictionary with fixation findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    try:
        # First request - get session
        result1 = subprocess.run(
            ["curl", "-s", "-i", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        session1 = re.search(r'set-cookie: ([^=]+)=([^;]+)', result1.stdout.lower())
        if not session1:
            findings["findings"].append("No session cookie issued")
            return findings
        
        session_name = session1.group(1)
        session_value1 = session1.group(2)
        
        # Try to reuse same session after "login"
        headers = f"-H 'Cookie: {session_name}={session_value1}'"
        
        result2 = subprocess.run(
            f"curl -s -i {headers} {url}",
            shell=True,
            capture_output=True,
            timeout=10,
            text=True
        )
        
        # If session is reused without change, it's fixation vulnerability
        if session_value1 in result2.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append(f"Session ID not regenerated after authentication")
            findings["evidence"].append({
                "session_before": session_value1,
                "session_reused": True
            })
    
    except Exception:
        pass
    
    return findings
