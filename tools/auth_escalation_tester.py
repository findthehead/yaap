"""
Authentication & Privilege Escalation Tester
Tests for broken authentication, weak credentials, and privilege escalation vulnerabilities
"""

from langchain.tools import tool
import subprocess
import base64
import json


DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "admin123"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "password"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
    {"username": "operator", "password": "operator"},
    {"username": "support", "password": "support123"},
]

COMMON_USERNAMES = [
    "admin", "root", "test", "guest", "user", "operator",
    "administrator", "superuser", "sysadmin", "webadmin"
]

WEAK_PASSWORD_PATTERNS = [
    r"^password", r"^123456", r"^12345", r"^111111", 
    r"^1q2w3e", r"^welcome", r"^letmein", r"^admin"
]


@tool
def test_default_credentials(login_url: str, username_param: str = "username", password_param: str = "password") -> dict:
    """
    Test for weak default credentials
    
    Args:
        login_url: Login endpoint URL
        username_param: Username parameter name
        password_param: Password parameter name
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "valid_credentials": []
    }
    
    for cred in DEFAULT_CREDENTIALS:
        username = cred["username"]
        password = cred["password"]
        
        try:
            # Try POST login
            data = f"{username_param}={username}&{password_param}={password}"
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-X", "POST", "-d", data, login_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            
            # Check for successful login indicators
            success_indicators = [
                "dashboard",
                "welcome",
                "logout",
                "authenticated",
                "success",
                "home",
                "profile",
            ]
            
            # Check for failure indicators
            failure_indicators = [
                "invalid",
                "incorrect",
                "failed",
                "unauthorized",
                "denied",
            ]
            
            if any(indicator in response for indicator in success_indicators) and \
               not any(indicator in response for indicator in failure_indicators):
                findings["vulnerable"] = True
                findings["valid_credentials"].append({
                    "username": username,
                    "password": password
                })
                findings["findings"].append(f"Default credentials found: {username}:{password}")
        
        except Exception:
            pass
    
    return findings


@tool
def test_broken_authentication(login_url: str, auth_header: str = "Authorization") -> dict:
    """
    Test for broken authentication patterns
    
    Args:
        login_url: Login/authentication endpoint
        auth_header: Authentication header name
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Test 1: No authentication required
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "5", login_url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if len(result.stdout) > 100 and "error" not in result.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("No authentication required for protected resource")
            findings["evidence"].append("GET request without auth header succeeded")
    except Exception:
        pass
    
    # Test 2: Weak token generation
    weak_tokens = [
        "1", "1234567890", "admin", "user123", 
        "test", base64.b64encode(b"admin").decode()
    ]
    
    for token in weak_tokens:
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-m", "5",
                    "-H", f"{auth_header}: {token}",
                    login_url
                ],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            if "unauthorized" not in response and len(result.stdout) > 100:
                findings["vulnerable"] = True
                findings["findings"].append(f"Weak token accepted: {token}")
        except Exception:
            pass
    
    # Test 3: Session fixation
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "5", "-i", login_url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        # Check for Set-Cookie header
        if "set-cookie" not in result.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("No session cookie set after login")
            findings["evidence"].append("Missing Set-Cookie header")
    except Exception:
        pass
    
    return findings


@tool
def test_privilege_escalation(admin_url: str, user_headers: dict = None) -> dict:
    """
    Test for privilege escalation vulnerabilities
    
    Args:
        admin_url: Admin/privileged endpoint URL
        user_headers: User authentication headers
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    if user_headers is None:
        user_headers = {"Cookie": "session=user_token"}
    
    # Test 1: Direct access without elevation
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "5", admin_url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "admin" in result.stdout.lower() or "dashboard" in result.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Admin panel accessible without authentication")
    except Exception:
        pass
    
    # Test 2: Parameter tampering for privilege escalation
    escalation_params = [
        "?admin=1",
        "?role=admin",
        "?level=1",
        "?privileged=true",
        "?isadmin=1",
    ]
    
    for param in escalation_params:
        test_url = admin_url + param
        try:
            headers = " ".join([f'-H "{k}: {v}"' for k, v in user_headers.items()])
            result = subprocess.run(
                f'curl -s -m 5 {headers} "{test_url}"',
                shell=True,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            if any(word in response for word in ["admin", "dashboard", "users", "settings"]):
                findings["vulnerable"] = True
                findings["findings"].append(f"Privilege escalation via parameter: {param}")
                findings["evidence"].append({"param": param, "response": response[:200]})
        except Exception:
            pass
    
    # Test 3: Horizontal privilege escalation (access other users' data)
    user_endpoints = [
        f"{admin_url.rsplit('/', 1)[0]}/user/1",
        f"{admin_url.rsplit('/', 1)[0]}/user/2",
        f"{admin_url.rsplit('/', 1)[0]}/profile/1",
    ]
    
    for endpoint in user_endpoints:
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", endpoint],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if "email" in result.stdout or "password" in result.stdout:
                findings["vulnerable"] = True
                findings["findings"].append(f"Horizontal privilege escalation: {endpoint}")
                findings["evidence"].append({"endpoint": endpoint})
        except Exception:
            pass
    
    return findings


@tool
def test_access_control_bypass(protected_url: str) -> dict:
    """
    Test for Access Control (IDOR/Privilege) vulnerabilities
    
    Args:
        protected_url: Protected resource URL with ID parameter
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Extract base URL and ID parameter
    bypass_techniques = [
        f"{protected_url.replace('/1', '/2')}",  # ID enumeration
        f"{protected_url}/../admin",  # Path traversal
        f"{protected_url}?admin=true",  # Parameter injection
        f"{protected_url}#/admin",  # Fragment bypass
    ]
    
    for bypass_url in bypass_techniques:
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", bypass_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout
            
            # Check for access to other user's data
            if len(response) > 200 and "error" not in response.lower():
                findings["vulnerable"] = True
                findings["findings"].append(f"Access control bypass detected")
                findings["evidence"].append({
                    "technique": bypass_url,
                    "response_length": len(response)
                })
        except Exception:
            pass
    
    return findings


@tool
def test_password_reset_flaws(password_reset_url: str) -> dict:
    """
    Test for password reset vulnerabilities
    
    Args:
        password_reset_url: Password reset endpoint URL
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Test 1: Weak reset token
    weak_tokens = ["1", "reset", "123456", "admin123"]
    
    for token in weak_tokens:
        try:
            test_url = f"{password_reset_url}?token={token}"
            result = subprocess.run(
                ["curl", "-s", "-m", "5", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if "invalid" not in result.stdout.lower() and len(result.stdout) > 100:
                findings["vulnerable"] = True
                findings["findings"].append(f"Weak password reset token: {token}")
        except Exception:
            pass
    
    # Test 2: Token reuse
    try:
        result = subprocess.run(
            [
                "curl", "-s", "-m", "5", "-X", "POST",
                "-d", "token=same&password=newpass&confirm=newpass",
                password_reset_url
            ],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if "success" in result.stdout.lower() or "changed" in result.stdout.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Password reset token reuse possible")
    except Exception:
        pass
    
    return findings
