"""
Observer Agent - Monitors injection results and detects vulnerability indicators
Reports findings back to injector/checklist for next steps
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import BLUE, GREEN, RED, YELLOW, CYAN, RESET
from utils.reasoning import ReasoningDisplay
import json
import re
import urllib.parse
import subprocess


def verify_vulnerability_with_curl(url: str, payload: str, vuln_type: str) -> dict:
    """
    VERIFICATION LAYER: Use curl to actually test if vulnerability exists
    Returns verification result with proof
    """
    verification = {
        'verified': False,
        'proof': '',
        'method': 'curl_verification'
    }
    
    try:
        # Test the actual URL with curl
        result = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '10', url],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        response = result.stdout
        
        # Type-specific verification
        if vuln_type == 'XSS':
            # Verify payload is in response AND not encoded
            if payload in response:
                # Check it's not HTML encoded
                if '&lt;' in response or '&#' in response or '&gt;' in response:
                    verification['proof'] = 'Payload reflected but HTML-encoded (safe)'
                    return verification
                
                # Check if in executable context
                if '<html' in response.lower() or '<body' in response.lower():
                    # Find context around payload
                    idx = response.find(payload)
                    context = response[max(0, idx-200):min(len(response), idx+200)]
                    
                    # Check if NOT in safe contexts
                    if '<textarea' in context or '<!--' in context or 'value="' in context:
                        verification['proof'] = 'Payload in safe context (textarea/comment/attribute value)'
                        return verification
                    
                    # Appears to be in executable context
                    verification['verified'] = True
                    verification['proof'] = f'XSS payload in executable HTML context: {context[:100]}'
            else:
                verification['proof'] = 'Payload not found in response'
        
        elif vuln_type == 'SQLi':
            # Look for actual database information, not just errors
            db_indicators = [
                (r'available databases.*\[\d+\]', 'Database enumeration'),
                (r'table.*\[.*?\]', 'Table listing'),
                (r'dumped.*entries', 'Data dump'),
                (r'database\s+version:\s*\d', 'Version disclosure'),
            ]
            
            for pattern, description in db_indicators:
                if re.search(pattern, response, re.IGNORECASE):
                    verification['verified'] = True
                    verification['proof'] = f'SQLi confirmed: {description}'
                    break
            
            if not verification['verified']:
                # Check for SQL errors (weaker evidence)
                if re.search(r'sql syntax|mysql|postgresql|ora-\d+', response, re.IGNORECASE):
                    verification['proof'] = 'SQL error found but no data extraction - likely false positive'
        
        elif vuln_type == 'Command Injection':
            # Look for actual command output
            cmd_patterns = [
                (r'uid=\d+.*gid=\d+', 'id command output'),
                (r'root:x:0:0:', '/etc/passwd contents'),
                (r'total\s+\d+.*drwx', 'ls command output'),
            ]
            
            for pattern, description in cmd_patterns:
                if re.search(pattern, response):
                    # Make sure it's not just the payload being echoed
                    if payload not in response[response.find(pattern):response.find(pattern)+100]:
                        verification['verified'] = True
                        verification['proof'] = f'Command injection confirmed: {description}'
                        break
            
            if not verification['verified']:
                verification['proof'] = 'No actual command output found - likely false positive'
        
        elif vuln_type == 'Path Traversal':
            # Look for actual file contents
            if 'root:x:0:' in response and '/bin/' in response:
                # Verify it's actual /etc/passwd format
                if re.search(r'root:x:0:0:[^:]*:/root:/bin/', response):
                    verification['verified'] = True
                    verification['proof'] = '/etc/passwd contents confirmed'
                else:
                    verification['proof'] = 'Contains "root" but not /etc/passwd format'
            elif '[drivers]' in response or '[extensions]' in response:
                verification['verified'] = True
                verification['proof'] = 'Windows system file contents confirmed'
            else:
                verification['proof'] = 'No file contents found - likely false positive'
        
        elif vuln_type == 'SSRF':
            # Look for internal service responses
            if '169.254.169.254' in response and ('ami-id' in response or 'instance-id' in response):
                verification['verified'] = True
                verification['proof'] = 'AWS metadata service accessed'
            elif re.search(r'Server:\s*(Apache|nginx|IIS)', response):
                verification['verified'] = True
                verification['proof'] = 'Internal server header received'
            else:
                verification['proof'] = 'No internal service response - likely false positive'
        
        elif vuln_type == 'IDOR':
            # For IDOR, check if we got actual user data
            if re.search(r'"(email|username|password)":', response):
                verification['verified'] = True
                verification['proof'] = 'User data accessible via ID manipulation'
            elif 'invalid' in response.lower() or 'not found' in response.lower():
                verification['proof'] = 'Normal validation error - NOT a vulnerability'
            else:
                verification['proof'] = 'No unauthorized data access confirmed'
    
    except Exception as e:
        verification['proof'] = f'Verification failed: {str(e)}'
    
    return verification


def observer_node(state: AgentState, orch=None):
    """
    Observer agent that:
    1. Receives injection result from injector
    2. Analyzes response for vulnerability indicators
    3. Determines if vulnerability was found
    4. Provides feedback to injector/checklist
    5. Decides next action (continue, modify payload, move to next test)
    """
    
    print(f"{BLUE}[>][observer]{RESET} Analyzing injection results...", flush=True)
    
    # Load observer prompt for strict verification guidelines
    observer_prompt_path = 'prompts/observer.md'
    observer_guidelines = ""
    try:
        with open(observer_prompt_path, 'r') as f:
            observer_guidelines = f.read()
    except Exception as e:
        print(f"{YELLOW}[!][observer]{RESET} Could not load observer.md guidelines: {e}", flush=True)
        observer_guidelines = "Use strict verification - require actual exploitation proof, not just indicators."
    
    # Get injection details
    injection_plan = state.get('injection_plan', {})
    injection_result = state.get('injection_result', '')
    
    # Get tool execution results from state
    tools_runs = state.get('tools_runs', [])
    recent_run = tools_runs[-1] if tools_runs else {}
    
    # Extract response data
    tool_output = str(recent_run.get('output', injection_result))
    
    # Get test category from multiple sources (with fallbacks)
    checklist_state = state.get('checklist_state', {})
    test_category = (
        state.get('checklist_directive', {}).get('next_test', {}).get('category') or
        checklist_state.get('current_category') or
        injection_plan.get('test_category') or
        'Unknown'
    )
    
    expected_indicators = injection_plan.get('expected_indicators', [])
    payload_used = injection_plan.get('payload_selected', '')
    target_url = injection_plan.get('target_url', state.get('current_test_url', ''))
    
    print(f"{BLUE}[?][observer]{RESET} Looking for {test_category} indicators in response ({len(tool_output)} bytes)...", flush=True)
    
    # Analyze payload reflection for encoder agent
    reflection_context = analyze_payload_reflection(tool_output, payload_used, injection_plan.get('injection_method', 'GET'))
    print(f"{BLUE}[*][observer]{RESET} Reflection analysis: {reflection_context.get('location', 'none')} | Reflected: {reflection_context.get('is_reflected', False)}", flush=True)
    
    # Build observation prompt with strict guidelines from observer.md
    prompt = f"""{observer_guidelines}

---

CURRENT TEST TO ANALYZE:

INJECTION DETAILS:
- Test Category: {test_category}
- Payload Used: {payload_used}
- Target URL: {target_url}
- Expected Indicators: {json.dumps(expected_indicators)}
- Injection Method: {injection_plan.get('injection_method', 'Unknown')}

RESPONSE DATA TO ANALYZE:
```
{tool_output[:3000]}
```

YOUR TASK:
1. **FIRST**: Determine if this looks like a vulnerability based on the response
2. **IF potential vulnerability**: You MUST use curl to verify by constructing the actual URL
3. **PARSE the curl response**: Look for EXPLOITATION PROOF (not just errors/reflection)
4. **DECIDE**: Confirmed (with proof) | False Positive (no proof) | Try different payload

MANDATORY VERIFICATION STEPS:
1. Construct test URL: {target_url} with payload: {payload_used}
2. Use verify_vulnerability_with_curl() internally OR describe curl command needed
3. Check curl response for ACTUAL exploitation (database data, command output, file contents)
4. Only mark "Confirmed" if exploitation PROVEN

CRITICAL REMINDERS:
- Error messages alone = NOT vulnerable
- Reflection alone = NOT vulnerable  
- "Invalid ID" / "Not found" = Normal behavior, NOT vulnerable
- Must see DATABASE NAMES for SQLi, COMMAND OUTPUT for RCE, EXECUTABLE CONTEXT for XSS

OUTPUT FORMAT (JSON ONLY):
{{
  "vulnerability_found": true/false,
  "confidence": "Confirmed" | "Likely" | "Possible" | "Not Found" | "False Positive",
  "evidence": ["Specific exploitation proof from verification"],
  "vulnerability_type": "{test_category}",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "next_action": "report_finding" | "try_different_payload" | "use_encoder" | "move_to_next_test",
  "reasoning": "Why confirmed OR why false positive with curl verification details",
  "verification_needed": true/false,
  "curl_verification": {{
    "url": "Exact URL to test",
    "expected_proof": "What to look for in response",
    "result": "What was found in curl response"
  }}
}}

Analyze the response and determine if vulnerability exists. REQUIRE PROOF.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"Analyze this {test_category} test response. Use STRICT verification. Return ONLY JSON.")
    ]
    
    display = ReasoningDisplay("observer", CYAN)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. observer", flush=True)
        print(f"     • Analyzing injection results ({len(injection_result)} bytes)", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
        
        if response:
            content = response.content
            
            # Extract observation result
            try:
                # Try multiple JSON extraction methods
                if '```json' in content:
                    json_start = content.find('```json') + 7
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                elif '```' in content:
                    # Handle plain code blocks without 'json' marker
                    json_start = content.find('```') + 3
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                elif '{' in content and '}' in content:
                    # Extract JSON object directly
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    json_str = content[json_start:json_end].strip()
                else:
                    json_str = content.strip()
                
                observation = json.loads(json_str)
                
                # Ensure required fields exist
                if 'next_action' not in observation:
                    observation['next_action'] = 'try_different_payload'
                if 'vulnerability_found' not in observation:
                    observation['vulnerability_found'] = False
                
                # Print findings
                if observation.get('vulnerability_found', False):
                    print(f"{GREEN}[+][observer]{RESET} VULNERABILITY FOUND: {observation.get('vulnerability_type', 'Unknown')} ({observation.get('confidence', 'Unknown')})", flush=True)
                    print(f"{GREEN}    Evidence: {observation.get('evidence', [])[:2]}{RESET}", flush=True)
                else:
                    print(f"{YELLOW}[!][observer]{RESET} No vulnerability detected - {observation.get('next_action', 'continue')}", flush=True)
                
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                print(f"{YELLOW}[!][observer]{RESET} Could not parse observation, using heuristics", flush=True)
                # Fallback heuristic detection
                observation = heuristic_detection(tool_output, test_category, payload_used)
                observation['raw_response'] = content
                
                # Set next_action for iteration
                if not observation.get('vulnerability_found', False):
                    current_round = state.get('checklist_state', {}).get('current_payload_round', 1)
                    
                    # Check if payload is reflected - if so, suggest encoder
                    if reflection_context.get('is_reflected', False):
                        observation['next_action'] = 'use_encoder'
                        print(f"{YELLOW}[!][observer]{RESET} Payload reflected but not exploited - suggesting encoder", flush=True)
                    elif current_round < 5:
                        observation['next_action'] = 'try_different_payload'
                    else:
                        observation['next_action'] = 'move_to_next_test'
            
            # CRITICAL VERIFICATION STEP: Use curl to verify the vulnerability actually exists
            if observation.get('vulnerability_found', False) and observation.get('confidence') in ['Confirmed', 'Likely']:
                print(f"{CYAN}[>][observer]{RESET} VERIFYING vulnerability with curl...", flush=True)
                
                target_url = injection_plan.get('target_url', '')
                vuln_type = observation.get('vulnerability_type', test_category)
                
                verification = verify_vulnerability_with_curl(target_url, payload_used, vuln_type)
                
                if verification['verified']:
                    print(f"{GREEN}[+][observer]{RESET} VERIFICATION PASSED: {verification['proof']}", flush=True)
                    observation['verification'] = verification
                    observation['confidence'] = 'Confirmed'
                else:
                    print(f"{RED}[-][observer]{RESET} VERIFICATION FAILED: {verification['proof']}", flush=True)
                    print(f"{YELLOW}[!][observer]{RESET} Marking as FALSE POSITIVE - not reporting", flush=True)
                    observation['vulnerability_found'] = False
                    observation['confidence'] = 'False Positive'
                    observation['next_action'] = 'try_different_payload'
                    observation['verification_failed'] = verification['proof']
                
        else:
            content = "Observer unavailable"
            observation = {'vulnerability_found': False, 'next_action': 'continue'}
            
    except Exception as e:
        print(f"{RED}[-][observer]{RESET} Error: {e}", flush=True)
        content = f"Observer error: {e}"
        observation = {'vulnerability_found': False, 'error': str(e)}
    
    # Update findings if vulnerability confirmed
    findings = state.get('findings', []) or []
    if observation.get('vulnerability_found', False) and observation.get('confidence') in ['Confirmed', 'Likely']:
        finding_text = (
            f"{observation.get('severity', 'Unknown')} - {observation.get('vulnerability_type', 'Unknown Vulnerability')}\n"
            f"Target: {injection_plan.get('target_url', 'Unknown')}\n"
            f"Parameter: {state.get('checklist_directive', {}).get('next_test', {}).get('parameter', 'Unknown')}\n"
            f"Payload: {payload_used}\n"
            f"Evidence: {'; '.join(observation.get('evidence', [])[:3])}\n"
            f"Confidence: {observation.get('confidence', 'Unknown')}"
        )
        findings.append(finding_text)
        print(f"{GREEN}[+][observer]{RESET} Added to findings list", flush=True)
    
    return {
        'observer': content,
        'observation': observation,
        'findings': findings,
        'reflection_context': reflection_context  # Add reflection data for encoder
    }


def analyze_payload_reflection(response_text: str, payload: str, injection_method: str) -> dict:
    """
    Analyze how and where the payload is reflected in the response
    This helps the encoder agent determine appropriate encoding strategy
    """
    
    reflection_data = {
        'is_reflected': False,
        'location': 'none',  # url, html, js, attribute, stored, header
        'is_stored': False,
        'raw_reflection': '',
        'encoded_in_response': False,
        'encoding_type': 'none',  # url, html, mixed
        'context': ''
    }
    
    if not payload or not response_text:
        return reflection_data
    
    # Check if payload appears verbatim in response
    if payload in response_text:
        reflection_data['is_reflected'] = True
        payload_pos = response_text.find(payload)
        reflection_data['raw_reflection'] = response_text[max(0, payload_pos - 100):min(len(response_text), payload_pos + 150)]
        
        # Determine reflection context
        before = response_text[max(0, payload_pos - 200):payload_pos]
        after = response_text[payload_pos + len(payload):min(len(response_text), payload_pos + len(payload) + 200)]
        
        # Check if in URL
        if 'http://' in before or 'https://' in before or 'href=' in before or 'src=' in before:
            reflection_data['location'] = 'url'
            reflection_data['context'] = 'Payload reflected in URL/link'
        
        # Check if in JavaScript context
        elif '<script' in before.lower() or 'javascript:' in before.lower():
            reflection_data['location'] = 'js'
            reflection_data['context'] = 'Payload reflected in JavaScript context'
        
        # Check if in HTML attribute
        elif re.search(r'<\w+[^>]*\s+\w+\s*=\s*["\']?[^"\']*$', before):
            reflection_data['location'] = 'attribute'
            reflection_data['context'] = 'Payload reflected in HTML attribute'
        
        # Check if in HTML body
        elif '<' in before or '>' in after:
            reflection_data['location'] = 'html'
            reflection_data['context'] = 'Payload reflected in HTML body'
        
        # Check if in header (for CRLF injection)
        elif payload_pos < 500 and ('\r\n' in before or 'HTTP/' in before):
            reflection_data['location'] = 'header'
            reflection_data['context'] = 'Payload reflected in HTTP header'
        
        else:
            reflection_data['location'] = 'text'
            reflection_data['context'] = 'Payload reflected in plain text'
    
    # Check if payload is encoded in response
    url_encoded = urllib.parse.quote(payload)
    url_double_encoded = urllib.parse.quote(url_encoded)
    html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    html_entity_encoded = ''.join(f'&#x{ord(c):x};' for c in payload[:10])  # Check first 10 chars
    
    if url_encoded in response_text:
        reflection_data['is_reflected'] = True
        reflection_data['encoded_in_response'] = True
        reflection_data['encoding_type'] = 'url_single'
        reflection_data['context'] = 'Payload URL-encoded in response'
    elif url_double_encoded in response_text:
        reflection_data['is_reflected'] = True
        reflection_data['encoded_in_response'] = True
        reflection_data['encoding_type'] = 'url_double'
        reflection_data['context'] = 'Payload double URL-encoded in response'
    elif html_encoded in response_text:
        reflection_data['is_reflected'] = True
        reflection_data['encoded_in_response'] = True
        reflection_data['encoding_type'] = 'html'
        reflection_data['context'] = 'Payload HTML-encoded in response'
    elif html_entity_encoded in response_text:
        reflection_data['is_reflected'] = True
        reflection_data['encoded_in_response'] = True
        reflection_data['encoding_type'] = 'html_entity'
        reflection_data['context'] = 'Payload HTML-entity-encoded in response'
    
    # Heuristic for stored vs reflected
    # If POST method and payload reflected, likely stored
    if injection_method.upper() == 'POST' and reflection_data['is_reflected']:
        reflection_data['is_stored'] = True
        reflection_data['context'] += ' (potentially stored)'
    
    # Check for common stored XSS indicators
    stored_indicators = [
        'comment', 'review', 'profile', 'message', 'post', 'article',
        'description', 'bio', 'status', 'feedback'
    ]
    if any(indicator in response_text.lower() for indicator in stored_indicators):
        if reflection_data['is_reflected']:
            reflection_data['is_stored'] = True
            reflection_data['context'] += ' (stored in user content)'
    
    return reflection_data


def heuristic_detection(response_text: str, test_category: str, payload: str) -> dict:
    """
    Fallback heuristic-based vulnerability detection
    STRICT MODE: Only report if exploitation is proven, not just indicators
    """
    response_lower = response_text.lower()
    
    # CRITICAL: Filter out normal error messages that are NOT vulnerabilities
    normal_errors = [
        'invalid', 'not found', 'does not exist', 'access denied',
        'unauthorized', 'forbidden', 'bad request', 'error',
        'failed', 'incorrect', 'wrong', 'missing', 'required'
    ]
    
    # If response only contains normal error messages, it's NOT a vulnerability
    if any(err in response_lower for err in normal_errors):
        # Check if there's actual exploitation evidence alongside the error
        has_exploitation = False
        if 'uid=' in response_text or 'root:x:' in response_text:
            has_exploitation = True
        if 'database' in response_lower and ('[' in response_text or 'table' in response_lower):
            has_exploitation = True
        
        if not has_exploitation:
            # Just a normal error message, not a vulnerability
            return {
                'vulnerability_found': False,
                'confidence': 'Not Found',
                'evidence': [],
                'vulnerability_type': test_category,
                'next_action': 'try_different_payload',
                'reasoning': f"Normal application error detected, not a security vulnerability"
            }
    
    # CRITICAL: Higher threshold for confirmation
    critical_indicators = {
        'XSS': [
            # Only confirm if JavaScript actually executed
            ('alert box displayed' in response_lower or 'console output:' in response_lower, "JavaScript execution confirmed"),
            ('<script>' in response_text and payload in response_text and 'executed' in response_lower, "Script tag executed"),
        ],
        'SQLi': [
            # Only confirm if database data is extracted
            (re.search(r'database.*\[.*?\]', response_lower) and 'available databases' in response_lower, "Database names enumerated"),
            (re.search(r'table.*\[.*?\]', response_lower), "Tables enumerated"),
            (re.search(r'dumped.*entries', response_lower), "Data dumped successfully"),
        ],
        'Command Injection': [
            # Only confirm if command output is visible
            (re.search(r'uid=\d+.*gid=\d+', response_text), "User ID output (uid/gid)"),
            ('root:x:0:0' in response_text, "/etc/passwd contents"),
            (re.search(r'total\s+\d+.*drwx', response_text), "Directory listing output"),
        ],
        'SSRF': [
            # Only confirm if internal service response received
            ('169.254.169.254' in response_text and ('ami-id' in response_lower or 'instance-id' in response_lower), "AWS metadata accessed"),
            ('127.0.0.1' in response_text and ('Server:' in response_text or 'Apache' in response_text or 'nginx' in response_text), "Internal service response"),
        ],
        'IDOR': [
            # Only confirm if OTHER USER's data is accessed
            (re.search(r'user.*:.*(?:email|password|token)', response_lower) and 'admin' in response_lower, "Admin data accessed"),
            (re.search(r'"id":\s*\d+.*"email":', response_text) and payload in response_text, "User data enumeration"),
        ]
    }
    
    # Warning indicators - suggest further testing but don't confirm
    warning_indicators = {
        'XSS': [
            (payload in response_text and '<' in payload and '&lt;' not in response_text, "Payload reflected with HTML"),
            ('onerror=' in response_lower or 'onload=' in response_lower, "Event handler present"),
        ],
        'SQLi': [
            (re.search(r'sql syntax.*mysql', response_lower), "MySQL syntax error"),
            (re.search(r'postgresql.*error', response_lower), "PostgreSQL error"),
            (re.search(r'ora-\d+', response_lower), "Oracle error"),
        ],
        'Command Injection': [
            (re.search(r'sh:|bash:|cmd\.exe', response_lower), "Shell error message"),
            ('/bin/' in response_text or '\\system32' in response_lower, "System path visible"),
        ],
        'SSRF': [
            ('169.254.169.254' in response_text, "Metadata IP detected"),
            ('127.0.0.1' in response_text or 'localhost' in response_lower, "Localhost detected"),
        ]
    }
    
    # Check critical indicators first
    critical_evidence = []
    for check, description in critical_indicators.get(test_category, []):
        if check:
            critical_evidence.append(description)
    
    # Check warning indicators
    warning_evidence = []
    for check, description in warning_indicators.get(test_category, []):
        if check:
            warning_evidence.append(description)
    
    # STRICT: Only confirm if critical evidence exists
    if critical_evidence:
        return {
            'vulnerability_found': True,
            'confidence': 'Confirmed',
            'evidence': critical_evidence,
            'vulnerability_type': test_category,
            'severity': 'Critical',
            'next_action': 'report_finding',
            'reasoning': f"EXPLOITATION PROVEN: {len(critical_evidence)} critical indicators"
        }
    elif warning_evidence:
        return {
            'vulnerability_found': False,  # Don't report warnings as vulnerabilities
            'confidence': 'Possible',
            'evidence': warning_evidence,
            'vulnerability_type': test_category,
            'severity': 'Unknown',
            'next_action': 'try_different_payload',
            'reasoning': f"Weak indicators found ({len(warning_evidence)}) - need stronger proof of exploitation"
        }
    else:
        return {
            'vulnerability_found': False,
            'confidence': 'Not Found',
            'evidence': [],
            'vulnerability_type': test_category,
            'next_action': 'try_different_payload',
            'reasoning': "No vulnerability indicators detected"
        }
