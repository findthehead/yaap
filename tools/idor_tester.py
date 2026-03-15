"""
Insecure Direct Object Reference (IDOR) Tester  
Tests for IDOR vulnerabilities with ID enumeration
"""

from langchain.tools import tool
import subprocess
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@tool
def test_idor_vulnerabilities(url: str, id_param: str = "id") -> dict:
    """
    Test URL for IDOR vulnerabilities by enumerating object IDs
    
    Args:
        url: Target URL with ID parameter
        id_param: Name of ID parameter (default: 'id')
    
    Returns:
        Dictionary with IDOR findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "tested_ids": [],
        "evidence": []
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    if id_param not in params:
        findings["error"] = f"Parameter '{id_param}' not found in URL"
        return findings
    
    # Get original value
    original_value = params[id_param][0]
    responses = {}
    
    # Test sequential IDs
    sequential_ids = [str(int(original_value) - 1 + i) for i in range(-2, 5)]
    
    for test_id in sequential_ids:
        if not test_id.isdigit():
            continue
            
        findings["tested_ids"].append(test_id)
        
        # Replace ID parameter
        test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params_dict[id_param] = test_id
        
        # Reconstruct URL
        test_query = urlencode(test_params_dict)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-w", "%{http_code}", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout
            status_code = response[-3:] if len(response) >= 3 else "000"
            content = response[:-3]
            
            # Store response for comparison
            responses[test_id] = {
                "status": status_code,
                "content_length": len(content),
                "content": content[:200]
            }
            
            # 200 OK with different content = potential IDOR
            if status_code == "200" and test_id != original_value:
                # Check if content is different from original
                if content != response:  # Basic heuristic
                    findings["vulnerable"] = True
                    findings["findings"].append(f"Accessible resource via ID {test_id} (status {status_code})")
                    findings["evidence"].append({
                        "id": test_id,
                        "status": status_code,
                        "content_preview": content[:300]
                    })
        
        except Exception:
            pass
    
    findings["responses"] = responses
    return findings


@tool
def test_idor_with_uuid(url: str, id_param: str = "id") -> dict:
    """
    Test IDOR by trying common UUID variations
    
    Args:
        url: Target URL with ID parameter
        id_param: Name of ID parameter
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "tested_ids": [],
        "evidence": []
    }
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    # Common UUID patterns
    uuid_patterns = [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
        "123e4567-e89b-12d3-a456-426614174000",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    ]
    
    for test_uuid in uuid_patterns:
        findings["tested_ids"].append(test_uuid)
        
        test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params_dict[id_param] = test_uuid
        
        test_query = urlencode(test_params_dict)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-w", "%{http_code}", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status_code = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            
            if status_code == "200":
                findings["vulnerable"] = True
                findings["findings"].append(f"Accessible resource via UUID {test_uuid}")
                findings["evidence"].append({"uuid": test_uuid, "status": status_code})
        
        except Exception:
            pass
    
    return findings
