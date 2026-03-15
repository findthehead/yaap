"""
Template Injection / SSTI Tester
Tests for Server-Side Template Injection vulnerabilities
"""

from langchain.tools import tool
import subprocess
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


SSTI_PAYLOADS = {
    # Jinja2 / Flask
    "jinja2_math": {
        "payload": "{{7*7}}",
        "indicator": "49",
        "engine": "Jinja2"
    },
    "jinja2_rce": {
        "payload": "{{config.items()}}",
        "indicator": "config",
        "engine": "Jinja2"
    },
    
    # Freemaker
    "freemarker_math": {
        "payload": "${7*7}",
        "indicator": "49",
        "engine": "Freemarker"
    },
    
    # Velocity
    "velocity_math": {
        "payload": "#set($x=7*7)$x",
        "indicator": "49",
        "engine": "Velocity"
    },
    
    # Thymeleaf
    "thymeleaf_math": {
        "payload": "[(${7*7})]",
        "indicator": "49",
        "engine": "Thymeleaf"
    },
    
    # ASP.NET
    "aspnet_math": {
        "payload": "<%= 7*7 %>",
        "indicator": "49",
        "engine": "ASP.NET"
    },
    
    # Ruby ERB
    "erb_math": {
        "payload": "<%= 7*7 %>",
        "indicator": "49",
        "engine": "ERB"
    },
    
    # Twig (PHP)
    "twig_math": {
        "payload": "{{7*7}}",
        "indicator": "49",
        "engine": "Twig"
    },
}


@tool
def test_ssti_injection(url: str, param_name: str = None) -> dict:
    """
    Test parameters for Server-Side Template Injection
    
    Args:
        url: Target URL with parameter(s)
        param_name: Specific parameter to test (if None, test all)
    
    Returns:
        Dictionary with SSTI findings
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
    
    test_params = [param_name] if param_name else list(params.keys())
    
    for param in test_params:
        if param not in params:
            continue
        
        for payload_name, payload_info in SSTI_PAYLOADS.items():
            payload = payload_info["payload"]
            indicator = payload_info["indicator"]
            engine = payload_info["engine"]
            
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
                
                # Check for successful template execution
                if indicator in response:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"SSTI ({engine}): Template expression executed")
                    findings["evidence"].append({
                        "engine": engine,
                        "payload": payload,
                        "evidence": response[:300]
                    })
            
            except Exception:
                pass
    
    return findings


@tool
def test_template_error_based(url: str, param_name: str = None) -> dict:
    """
    Test for template injection via error messages
    
    Args:
        url: Target URL
        param_name: Parameter to test
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    error_payloads = [
        ("{{", "Jinja2"),
        ("${", "Freemarker/EL"),
        ("<%", "ASP/JSP"),
        ("#{", "Ruby/Groovy"),
    ]
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    
    for param in list(params.keys())[:1]:  # Test first param
        for error_char, engine in error_payloads:
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[param] = error_char
            
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
                
                # Check for template engine errors
                error_indicators = [
                    "unexpected eof",
                    "syntax error",
                    "template",
                    "jinja",
                    "mako",
                    "velocity",
                    "freemarker"
                ]
                
                if any(indicator in response for indicator in error_indicators):
                    findings["vulnerable"] = True
                    findings["findings"].append(f"Template error revealed: {engine}")
                    findings["evidence"].append({
                        "engine": engine,
                        "error_char": error_char
                    })
            
            except Exception:
                pass
    
    return findings
