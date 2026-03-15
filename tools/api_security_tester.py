"""
API Security Tester
Tests for GraphQL, REST API, JWT, and OAuth vulnerabilities
"""

from langchain.tools import tool
import subprocess
import json
import re
from urllib.parse import urlparse


# GraphQL introspection query
GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
"""

GRAPHQL_PAYLOADS = {
    "introspection": {
        "description": "GraphQL introspection exposure",
        "query": GRAPHQL_INTROSPECTION
    },
    "alias_limits": {
        "description": "Query alias DoS",
        "query": "query {a:user{id} b:user{id} c:user{id}}"
    },
    "batch_query": {
        "description": "Batch query processing",
        "query": "[{query: 'query{user{id}}'}, {query: 'query{user{id}}'}]"
    },
    "fragment_cycles": {
        "description": "Fragment cycle DoS",
        "query": """
        fragment A on User {
          id
          friend {
            ...B
          }
        }
        fragment B on User {
          id
          friend {
            ...A
          }
        }
        query {
          user {
            ...A
          }
        }
        """
    }
}


@tool
def test_graphql_security(url: str) -> dict:
    """
    Test GraphQL endpoints for vulnerabilities
    
    Args:
        url: GraphQL endpoint URL
    
    Returns:
        Dictionary with GraphQL findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    graphql_endpoints = [url, url.rstrip('/') + '/graphql', url.rstrip('/') + '/api/graphql']
    
    for endpoint in graphql_endpoints:
        for payload_name, payload_info in GRAPHQL_PAYLOADS.items():
            query = payload_info["query"]
            description = payload_info["description"]
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", "-H", "Content-Type: application/json",
                     "-d", json.dumps({"query": query}), endpoint],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                response = result.stdout
                
                # Check for GraphQL schema exposure
                if "__schema" in response or "__type" in response:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"GraphQL introspection exposed: {description}")
                    findings["evidence"].append({
                        "test": payload_name,
                        "endpoint": endpoint,
                        "evidence": response[:500]
                    })
                
                # Check for GraphQL errors indicating execution
                if "errors" in response and ("query" in response or "mutation" in response):
                    findings["findings"].append(f"GraphQL endpoint accessible: {description}")
            
            except Exception:
                pass
    
    return findings


@tool
def test_jwt_security(url: str, auth_header: str = None) -> dict:
    """
    Test JWT token security
    
    Args:
        url: Protected endpoint URL
        auth_header: Authorization header value (e.g., 'Bearer <token>')
    
    Returns:
        Dictionary with JWT findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    if not auth_header:
        findings["error"] = "No JWT token provided"
        return findings
    
    # Extract token
    token_match = re.search(r'Bearer\s+(.+)', auth_header)
    if not token_match:
        findings["error"] = "Invalid JWT format"
        return findings
    
    token = token_match.group(1)
    
    try:
        # Check for common JWT vulnerabilities
        import base64
        
        parts = token.split('.')
        if len(parts) != 3:
            findings["error"] = "Invalid JWT structure"
            return findings
        
        # Decode header and payload (unverified)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        # Check for weak algorithm
        if header.get('alg') == 'none':
            findings["vulnerable"] = True
            findings["findings"].append("JWT uses 'none' algorithm (signature not verified)")
        
        if header.get('alg') == 'HS256' and 'kid' in header:
            findings["vulnerable"] = True
            findings["findings"].append("JWT uses HS256 with 'kid' field (potential algorithm confusion)")
        
        # Check for exposed sensitive claims
        sensitive_claims = ['password', 'secret', 'api_key', 'token', 'credit_card']
        for claim in sensitive_claims:
            if any(claim in str(k).lower() for k in payload.keys()):
                findings["vulnerable"] = True
                findings["findings"].append(f"Sensitive claim '{claim}' found in JWT payload")
        
        # Check expiration
        if 'exp' not in payload:
            findings["vulnerable"] = True
            findings["findings"].append("JWT has no expiration claim")
        
        findings["evidence"].append({
            "header": header,
            "payload": {k: v for k, v in payload.items() if k not in ['password', 'secret']},
            "token_length": len(token)
        })
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def test_api_rate_limiting(url: str, requests_count: int = 50) -> dict:
    """
    Test API rate limiting protection
    
    Args:
        url: API endpoint to test
        requests_count: Number of requests to send
    
    Returns:
        Dictionary with rate limiting findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "response_codes": {}
    }
    
    rate_limit_headers = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'ratelimit-limit', 'retry-after']
    status_codes = []
    
    try:
        for i in range(requests_count):
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-w", "%{http_code}", url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            status_codes.append(status)
            
            if status not in findings["response_codes"]:
                findings["response_codes"][status] = 0
            findings["response_codes"][status] += 1
        
        # Check if rate limiting header present
        result = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", url],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout.lower()
        has_rate_limit = any(h in headers for h in rate_limit_headers)
        
        if not has_rate_limit:
            findings["vulnerable"] = True
            findings["findings"].append("No rate limiting headers detected")
        
        # Check for 429 status code
        if "429" not in findings["response_codes"] and status_codes[-5:].count("200") == 5:
            findings["vulnerable"] = True
            findings["findings"].append("No rate limiting enforcement detected (no 429 responses)")
        
    except Exception:
        pass
    
    return findings


@tool
def test_api_authentication_bypass(url: str) -> dict:
    """
    Test API for authentication bypass vulnerabilities
    
    Args:
        url: Protected API endpoint
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    bypass_techniques = {
        "no_auth": {"method": "GET", "headers": {}},
        "empty_token": {"method": "GET", "headers": {"Authorization": "Bearer "}},
        "invalid_token": {"method": "GET", "headers": {"Authorization": "Bearer invalid"}},
        "token_in_param": {"method": "GET?token=invalid", "headers": {}},
        "case_manipulation": {"method": "GET", "headers": {"authorization": "bearer invalid"}},
    }
    
    for technique, config in bypass_techniques.items():
        try:
            cmd = ["curl", "-s", "-w", "%{http_code}", url]
            
            if config.get("headers"):
                for header, value in config["headers"].items():
                    cmd.extend(["-H", f"{header}: {value}"])
            
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            
            if status == "200":
                findings["vulnerable"] = True
                findings["findings"].append(f"Authentication bypass via {technique}")
                findings["evidence"].append({"technique": technique, "status": status})
        
        except Exception:
            pass
    
    return findings
