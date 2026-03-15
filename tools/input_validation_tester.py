"""
Input Validation & Data Type Vulnerability Tester
Tests for insufficient input validation, type mismatch, and boundary issues
"""

from langchain.tools import tool
import subprocess


INPUT_VALIDATION_PAYLOADS = {
    "type_mismatch": {
        "string_to_int": ["abc", "abc123", "null", "undefined"],
        "float_to_int": ["3.14", "1.5"],
        "boolean_attack": ["true/false", "yes/no", "on/off"],
    },
    "boundary_conditions": {
        "negative_numbers": ["-1", "-999", "-2147483648"],
        "zero": ["0"],
        "large_numbers": ["999999999", "2147483647", "9223372036854775807"],
        "empty": ["", "null", "None"],
    },
    "special_characters": {
        "sql": ["'", "\"", "--", ";", "/**/"],
        "path": ["/", "\\", "..", "..\\"],
        "control": ["\n", "\r", "\t", "\0"],
    },
    "length_attacks": {
        "very_long": "A" * 10000,
        "unicode_expansion": "\u00e9" * 1000,
        "null_terminator": "test\x00extra",
    }
}


@tool
def test_input_validation(url: str, param_name: str = None) -> dict:
    """
    Test for input validation vulnerabilities
    
    Args:
        url: Target URL with parameter(s)
        param_name: Specific parameter to test
    
    Returns:
        Dictionary with validation findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "payloads_tested": 0,
        "invalid_inputs_accepted": [],
        "evidence": []
    }
    
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    if not params:
        findings["error"] = "No URL parameters found"
        return findings
    
    test_params = [param_name] if param_name else list(params.keys())
    
    # Test boundary conditions
    for param in test_params:
        if param not in params:
            continue
        
        for payload_type, payloads in INPUT_VALIDATION_PAYLOADS.items():
            if isinstance(payloads, dict):
                for payload_group, payload_list in payloads.items():
                    if isinstance(payload_list, list):
                        for payload in payload_list:
                            findings["payloads_tested"] += 1
                            
                            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                            test_params_dict[param] = str(payload)
                            
                            test_query = urlencode(test_params_dict)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                                 parsed.params, test_query, parsed.fragment))
                            
                            try:
                                result = subprocess.run(
                                    ["curl", "-s", "-w", "%{http_code}", "-m", "3", test_url],
                                    capture_output=True,
                                    timeout=5,
                                    text=True
                                )
                                
                                status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
                                
                                # 200 with invalid input = vulnerability
                                if status == "200":
                                    findings["vulnerable"] = True
                                    findings["invalid_inputs_accepted"].append({
                                        "param": param,
                                        "payload": str(payload)[:50],
                                        "type": payload_group
                                    })
                                    findings["findings"].append(
                                        f"Parameter '{param}' accepts invalid {payload_group}"
                                    )
                            
                            except Exception:
                                pass
    
    findings["evidence"] = {
        "total_payloads_tested": findings["payloads_tested"],
        "invalid_accepted": len(findings["invalid_inputs_accepted"])
    }
    
    return findings


@tool
def test_length_constraints(url: str, param_name: str = None) -> dict:
    """
    Test for length validation bypass (buffer overflow, DoS)
    
    Args:
        url: Target URL
        param_name: Parameter to test
    
    Returns:
        Dictionary with length validation findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "max_accepted_length": None,
        "evidence": []
    }
    
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    test_params = [param_name] if param_name else (list(params.keys())[0] if params else None)
    
    if not test_params:
        return findings
    
    # Binary search for max accepted length
    test_lengths = [100, 1000, 10000, 100000, 1000000]
    
    for length in test_lengths:
        payload = "A" * length
        
        test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params_dict[test_params[0]] = payload
        
        test_query = urlencode(test_params_dict)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                              parsed.params, test_query, parsed.fragment))
        
        try:
            result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-m", "5", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            
            if status == "200":
                findings["max_accepted_length"] = length
        
        except Exception:
            break
    
    if findings["max_accepted_length"] and findings["max_accepted_length"] > 10000:
        findings["vulnerable"] = True
        findings["findings"].append(
            f"Excessive input length accepted ({findings['max_accepted_length']} chars)"
        )
        findings["evidence"].append({
            "issue": "Buffer overflow / DoS potential",
            "max_length": findings["max_accepted_length"],
            "severity": "Medium"
        })
    
    return findings


@tool
def test_type_coercion(url: str, param_name: str = None) -> dict:
    """
    Test for type coercion vulnerabilities
    
    Args:
        url: Target URL
        param_name: Parameter to test
    
    Returns:
        Dictionary with type coercion findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "coercion_tests": []
    }
    
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    test_params = [param_name] if param_name else (list(params.keys())[0] if params else None)
    
    if not test_params:
        return findings
    
    type_exploits = {
        "true_variations": ["true", "1", "yes", "on"],
        "false_variations": ["false", "0", "no", "off"],
        "null_variations": ["null", "nil", "None", "undefined"],
        "type_juggling": ["1+1", "2-1", "true+true"],
    }
    
    for type_class, payloads in type_exploits.items():
        for payload in payloads:
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[test_params[0]] = payload
            
            test_query = urlencode(test_params_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                 parsed.params, test_query, parsed.fragment))
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-w", "%{http_code}", "-m", "3", test_url],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
                
                if status == "200":
                    findings["coercion_tests"].append({
                        "type_class": type_class,
                        "payload": payload,
                        "accepted": True
                    })
                    
                    if type_class in ["true_variations", "null_variations"]:
                        findings["vulnerable"] = True
                        findings["findings"].append(
                            f"Type coercion: {type_class} variant '{payload}' accepted"
                        )
            
            except Exception:
                pass
    
    return findings
