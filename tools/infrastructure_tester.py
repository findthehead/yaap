"""
Infrastructure Security Tester
Tests for TLS/SSL, subdomain enumeration, WAF detection, and server misconfiguration
"""

from langchain.tools import tool
import subprocess
import re
import socket
from urllib.parse import urlparse


@tool
def test_tls_ssl_security(domain: str) -> dict:
    """
    Test TLS/SSL certificate and protocol security
    
    Args:
        domain: Domain name to test
    
    Returns:
        Dictionary with TLS/SSL findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    try:
        # Test SSL/TLS configuration
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
            input="Q\n",
            capture_output=True,
            timeout=10,
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Check for deprecated protocols
        if "SSLv2" in output or "SSLv3" in output:
            findings["vulnerable"] = True
            findings["findings"].append("Deprecated SSL/TLS protocol supported")
        
        # Check for weak ciphers
        weak_ciphers = ["DES", "RC4", "MD5", "EXPORT"]
        if any(cipher in output for cipher in weak_ciphers):
            findings["vulnerable"] = True
            findings["findings"].append(f"Weak cipher suite detected")
        
        # Extract certificate info
        cert_pattern = r'subject=(.+?)issuer='
        cert_match = re.search(cert_pattern, output)
        if cert_match:
            findings["evidence"].append({
                "certificate_subject": cert_match.group(1).strip()
            })
        
        # Check for self-signed cert
        if "self signed" in output.lower():
            findings["vulnerable"] = True
            findings["findings"].append("Self-signed certificate detected")
        
        # Check certificate validity
        if "notBefore" in output and "notAfter" in output:
            findings["evidence"].append({
                "certificate_valid": True
            })
    
    except subprocess.TimeoutExpired:
        findings["findings"].append("TLS handshake timeout")
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


@tool
def enumerate_subdomains(domain: str) -> dict:
    """
    Enumerate subdomains using DNS queries and common wordlists
    
    Args:
        domain: Root domain to enumerate
    
    Returns:
        Dictionary with discovered subdomains
    """
    findings = {
        "discovered_subdomains": [],
        "active_subdomains": [],
        "evidence": []
    }
    
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns",
        "admin", "api", "staging", "dev", "test", "demo", "blog", "shop",
        "downloads", "cdn", "app", "images", "static", "upload", "files",
        "support", "help", "docs", "dashboard", "panel", "backup", "server"
    ]
    
    for subdomain in common_subdomains:
        test_domain = f"{subdomain}.{domain}"
        
        try:
            # Attempt DNS resolution
            ip = socket.gethostbyname(test_domain)
            findings["discovered_subdomains"].append({
                "subdomain": test_domain,
                "ip": ip,
                "method": "DNS"
            })
            
            # Further test for HTTP/HTTPS
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "3", "-I", f"https://{test_domain}"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                if result.returncode == 0:
                    findings["active_subdomains"].append(test_domain)
                    findings["evidence"].append({
                        "subdomain": test_domain,
                        "type": "HTTPS_Active"
                    })
            
            except Exception:
                pass
        
        except socket.gaierror:
            pass
        except Exception:
            pass
    
    return findings


@tool
def detect_waf(domain: str) -> dict:
    """
    Detect Web Application Firewall (WAF) presence
    
    Args:
        domain: Domain to test for WAF
    
    Returns:
        Dictionary with WAF detection findings
    """
    findings = {
        "waf_detected": False,
        "waf_type": None,
        "findings": [],
        "evidence": []
    }
    
    waf_signatures = {
        "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "akamai": ["akamai-x-cache", "x-akamai-transformed"],
        "modsecurity": ["mod_security", "modsecurity"],
        "f5": ["f5", "bigip"],
        "barracuda": ["barracuda", "barra"],
        "imperva": ["imperva", "incapsula"],
        "aws_waf": ["x-amzn", "aws-waf"],
        "sucuri": ["sucuri", "cloudproxy"],
    }
    
    try:
        # Send normal request
        result = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", f"https://{domain}"],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout.lower()
        
        # Check for WAF signatures
        for waf_name, signatures in waf_signatures.items():
            if any(sig.lower() in headers for sig in signatures):
                findings["waf_detected"] = True
                findings["waf_type"] = waf_name.upper()
                findings["findings"].append(f"WAF detected: {waf_name.upper()}")
        
        # Check response behavior to malicious request
        result2 = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", f"https://{domain}/?test=<script>alert(1)</script>"],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        # Unusual response = WAF blocking
        if result2.stdout != result.stdout:
            findings["waf_detected"] = True
            findings["findings"].append("WAF behavior detected on malicious request")
        
        findings["evidence"].append({
            "status_code": result.stdout.split('\n')[0] if result.stdout else "Unknown"
        })
    
    except Exception:
        pass
    
    return findings


@tool
def test_server_misconfiguration(domain: str) -> dict:
    """
    Test for common server misconfigurations
    
    Args:
        domain: Domain to test
    
    Returns:
        Dictionary with misconfiguration findings
    """
    findings = {
        "vulnerable": False,
        "findings": [],
        "evidence": []
    }
    
    misconfig_tests = {
        "directory_listing": "/.git, /admin, /backup",
        "git_exposure": "/.git/config, /.git/HEAD",
        "common_files": "/.htaccess, /web.config, /robots.txt",
        "debug_enabled": "/debug, /console, /?debug=1",
        "version_disclosure": "/version.txt, /?version=1",
    }
    
    test_paths = [
        "/.git/config", "/.git/HEAD", "/admin", "/admin.php", 
        "/.htaccess", "/web.config", "/robots.txt",
        "/?debug=1", "/debug", "/?test=1",
        "/version.txt", "/VERSION", "/?version=1",
        "/backup.zip", "/backup.tar.gz", "/config.bak"
    ]
    
    try:
        for path in test_paths:
            result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", "-m", "3", f"https://{domain}{path}"],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            status = result.stdout[-3:] if len(result.stdout) >= 3 else "000"
            content = result.stdout[:-3]
            
            if status == "200" and len(content) > 0:
                findings["vulnerable"] = True
                findings["findings"].append(f"Accessible: {path} (HTTP {status})")
                findings["evidence"].append({
                    "path": path,
                    "status": status,
                    "content_preview": content[:200]
                })
    
    except Exception:
        pass
    
    return findings


@tool
def test_security_headers(domain: str) -> dict:
    """
    Test for presence of security headers
    
    Args:
        domain: Domain to test
    
    Returns:
        Dictionary with security header findings
    """
    findings = {
        "missing_headers": [],
        "weak_headers": [],
        "good_headers": []
    }
    
    required_headers = {
        "strict-transport-security": "HSTS",
        "x-frame-options": "Clickjacking protection",
        "x-content-type-options": "MIME sniffing protection",
        "content-security-policy": "XSS protection",
        "x-xss-protection": "XSS filter",
        "referrer-policy": "Referrer control",
        "permissions-policy": "Feature policy"
    }
    
    try:
        result = subprocess.run(
            ["curl", "-s", "-i", "-m", "5", f"https://{domain}"],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        headers = result.stdout.lower()
        
        for header, description in required_headers.items():
            if header in headers:
                findings["good_headers"].append(description)
            else:
                findings["missing_headers"].append(description)
        
        findings["evidence"] = {
            "missing_count": len(findings["missing_headers"]),
            "present_count": len(findings["good_headers"])
        }
    
    except Exception:
        pass
    
    return findings
