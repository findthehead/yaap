"""
Authentication Security Tester
Tests for weak authentication mechanisms, credential enumeration, and brute force resistance
"""

from langchain.tools import tool
import subprocess
import time


COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]

PASSWORD_RESET_PAYLOADS = {
    "no_email_verification": "Password reset without email verification",
    "expired_token": "Using expired password reset token",
    "reusable_token": "Reusing password reset token multiple times",
    "token_predictable": "Password reset token is predictable/sequential",
    "account_enumeration": "Enumerate valid accounts via password reset",
}


@tool
def test_authentication_strength(url: str, username_field: str = "username",
                                 password_field: str = "password") -> dict:
    """
    Test authentication mechanism strength
    
    Args:
        url: Login form URL
        username_field: HTML field name for username
        password_field: HTML field name for password
    
    Returns:
        Dictionary with authentication findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "tested_credentials": 0,
        "successful_logins": [],
        "evidence": []
    }
    
    for username, password in COMMON_CREDENTIALS:
        findings["tested_credentials"] += 1
        
        try:
            # Test login attempt
            result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-X", "POST",
                 "-d", f"{username_field}={username}&{password_field}={password}",
                 "-L", url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            content = result.stdout[:-3] if len(result.stdout) > 3 else ""
            
            # Check for successful login indicators
            if status == "200" and ("logout" in content.lower() or 
                                   "dashboard" in content.lower() or
                                   "welcome" in content.lower()):
                findings["vulnerable"] = True
                findings["successful_logins"].append(f"{username}:{password}")
                findings["findings"].append(f"Weak default credentials: {username}:{password}")
                findings["evidence"].append({
                    "username": username,
                    "password": password,
                    "status": status,
                    "severity": "Critical"
                })
        
        except Exception:
            pass
    
    return findings


@tool
def test_credential_enumeration(url: str, username_field: str = "username") -> dict:
    """
    Test for username enumeration vulnerability
    
    Args:
        url: Login form URL
        username_field: HTML field name for username
    
    Returns:
        Dictionary with enumeration findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "enumerated_users": [],
        "evidence": []
    }
    
    common_usernames = ["admin", "root", "test", "guest", "user", "support"]
    response_times = {}
    
    try:
        for username in common_usernames:
            start = time.time()
            
            result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-X", "POST",
                 "-d", f"{username_field}={username}&password=wrong",
                 url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            elapsed = time.time() - start
            response_times[username] = elapsed
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            content = result.stdout[:-3] if len(result.stdout) > 3 else ""
            
            # Different responses for valid vs invalid users
            if "user not found" in content.lower() or "invalid user" in content.lower():
                findings["vulnerable"] = True
                findings["enumerated_users"].append(username)
                findings["findings"].append(f"User enumeration possible: '{username}' is not registered")
            
            # Timing-based enumeration
            if elapsed > 1.0:
                findings["vulnerable"] = True
                findings["findings"].append(f"Timing-based user enumeration detected ({elapsed:.2f}s for {username})")
    
    except Exception:
        pass
    
    findings["evidence"] = {
        "timing_analysis": response_times,
        "enumerated_count": len(findings["enumerated_users"])
    }
    
    return findings


@tool
def test_brute_force_protection(url: str, username: str = "admin",
                               test_attempts: int = 10) -> dict:
    """
    Test for brute force protection mechanisms
    
    Args:
        url: Login form URL
        username: Username to test
        test_attempts: Number of attempts to make
    
    Returns:
        Dictionary with brute force protection findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "attempts": test_attempts,
        "blocked_after": None,
        "evidence": []
    }
    
    try:
        for attempt in range(test_attempts):
            result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-X", "POST",
                 "-d", f"username={username}&password=wrongpass{attempt}",
                 url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            content = result.stdout[:-3] if len(result.stdout) > 3 else ""
            
            # Check for rate limiting (429, 503) or account lockout (403)
            if status in ["429", "503"]:
                findings["blocked_after"] = attempt + 1
                findings["findings"].append(f"Rate limiting enabled after {attempt + 1} attempts")
                break
            
            if "locked" in content.lower() or "too many" in content.lower():
                findings["blocked_after"] = attempt + 1
                findings["findings"].append(f"Account locked after {attempt + 1} attempts")
                break
            
            # If all attempts succeed, no protection
            if attempt == test_attempts - 1 and status == "200":
                findings["vulnerable"] = True
                findings["findings"].append(f"No brute force protection (all {test_attempts} attempts succeeded)")
        
        findings["evidence"] = {
            "total_attempts": test_attempts,
            "protected": findings["blocked_after"] is not None,
            "threshold": findings["blocked_after"]
        }
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_password_policy(url: str) -> dict:
    """
    Test password policy strength
    
    Args:
        url: Login/registration page URL
    
    Returns:
        Dictionary with password policy findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "requirements": []
    }
    
    try:
        result = subprocess.run(
            ["curl", "-s", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        content = result.stdout.lower()
        
        # Check for password requirements in page
        requirements = {
            "minimum_length": ("password.*must.*[0-9]+|min.*length", "Minimum length requirement"),
            "uppercase": ("uppercase|capital|[A-Z]", "Uppercase character requirement"),
            "lowercase": ("lowercase|small|[a-z]", "Lowercase character requirement"),
            "numbers": ("number|digit|[0-9]", "Number requirement"),
            "special": ("special|symbol|[!@#$%]", "Special character requirement"),
        }
        
        for req_key, (pattern, description) in requirements.items():
            import re
            if re.search(pattern, content):
                findings["requirements"].append(description)
        
        # No requirements found = weak policy
        if not findings["requirements"]:
            findings["vulnerable"] = True
            findings["findings"].append("No password policy constraints detected")
        
        findings["evidence"] = {
            "requirements_found": len(findings["requirements"]),
            "requirements": findings["requirements"]
        }
    
    except Exception:
        pass
    
    return findings
