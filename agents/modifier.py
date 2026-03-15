"""
Modifier Agent - Encodes and transforms payloads when Observer reports no findings
Provides alternative payload encodings to Injector for retry
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import GREEN, RED, YELLOW, RESET
from utils.reasoning import ReasoningDisplay
import json
import base64
import urllib.parse
from typing import List, Dict


def modifier_node(state: AgentState, orch=None):
    """
    Modifier agent that:
    1. Receives failed payload from observer
    2. Analyzes why it might have failed (WAF, encoding, filtering)
    3. Generates alternative encoded/modified versions
    4. Provides suggestions back to injector
    """
    
    print(f"{YELLOW}[>][modifier]{RESET} Analyzing failed payload and generating alternatives...", flush=True)
    
    # Get observation results
    observation = state.get('observation', {})
    injection_plan = state.get('injection_plan', {})
    original_payload = injection_plan.get('payload_selected', '')
    test_category = state.get('checklist_directive', {}).get('next_test', {}).get('category', 'Unknown')
    
    # Get response for analysis
    tools_runs = state.get('tools_runs', [])
    recent_response = str(tools_runs[-1].get('output', '')) if tools_runs else ''
    
    print(f"{YELLOW}[*][modifier]{RESET} Original payload failed: {original_payload[:50]}...", flush=True)
    
    # Build modification prompt
    prompt = f"""You are a Payload Modification Specialist creating evasion techniques.

FAILED PAYLOAD:
{original_payload}

TEST CATEGORY: {test_category}

RESPONSE ANALYSIS:
{recent_response[:1000]}

OBSERVER FEEDBACK:
- Vulnerability Found: {observation.get('vulnerability_found', False)}
- Confidence: {observation.get('confidence', 'Unknown')}
- Reasoning: {observation.get('reasoning', 'N/A')}

COMMON FILTERING/BLOCKING PATTERNS:
1. WAF Detection: Keywords blocked (script, alert, select, union, exec, etc.)
2. HTML Encoding: < becomes &lt;, > becomes &gt;
3. Keyword Blacklists: Specific dangerous functions blocked
4. Length Limits: Payload truncated
5. Content-Type Validation: Only certain data types accepted
6. Character Filtering: Special characters stripped

PAYLOAD MODIFICATION TECHNIQUES:

1. URL ENCODING:
   - Single: <script> → %3Cscript%3E
   - Double: <script> → %253Cscript%253E
   - Mixed: <ScRiPt> with partial encoding

2. CASE VARIATION:
   - Original: <script>alert(1)</script>
   - Modified: <ScRiPt>alert(1)</sCrIpT>
   - Mixed: <sCrIpT>alert(1)</ScRiPt>

3. NULL BYTE INJECTION:
   - Original: <script>
   - Modified: <script%00>
   - Alternative: <script\x00>

4. UNICODE/UTF-8 ENCODING:
   - Original: <script>
   - Unicode: \u003cscript\u003e
   - UTF-8: %u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e

5. HTML ENTITY ENCODING:
   - Original: <script>
   - Decimal: &#60;script&#62;
   - Hex: &#x3c;script&#x3e;

6. CONCATENATION/SPLITTING:
   - Original: ' OR '1'='1
   - Modified: ' OR '1'='1' OR '1'='1
   - Split: ' OR (SELECT 1)='1

7. COMMENT INSERTION (SQL):
   - Original: ' OR '1'='1
   - Modified: ' OR/**/'1'='1
   - Alternative: ' OR/*comment*/'1'='1

8. ALTERNATIVE SYNTAX:
   XSS: <img src=x onerror=alert(1)> → <svg/onload=alert(1)>
   SQLi: ' OR 1=1-- → ' OR 'a'='a
   Command: ; whoami → | whoami → ` whoami ` → $(whoami)

YOUR TASK:
Generate 5 alternative payload modifications based on why the original likely failed.

OUTPUT FORMAT (JSON):
{{
  "analysis": "Why original payload likely failed (WAF, encoding, filtering)",
  "modified_payloads": [
    {{
      "payload": "modified payload string",
      "technique": "URL encoding" | "Case variation" | etc,
      "encoding_level": "none" | "single" | "double",
      "explanation": "Why this might bypass filters",
      "priority": 1-5
    }}
  ],
  "recommendations": [
    "Try payload 1 first because...",
    "If that fails, payload 3 uses different vector"
  ]
}}

Generate payload modifications for bypass.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"Modify this failed {test_category} payload: {original_payload}")
    ]
    
    display = ReasoningDisplay("modifier", YELLOW)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. modifier", flush=True)
        print(f"     • Generating alternative payloads", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
        
        if response:
            content = response.content
            
            # Extract modifications
            try:
                if '```json' in content:
                    json_start = content.find('```json') + 7
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                else:
                    json_str = content
                
                modifications = json.loads(json_str)
                modified_payloads = modifications.get('modified_payloads', [])
                
                print(f"{GREEN}[+][modifier]{RESET} Generated {len(modified_payloads)} alternative payloads", flush=True)
                
                # Show top 3 modifications
                for i, mod in enumerate(modified_payloads[:3], 1):
                    print(f"{YELLOW}    {i}. {mod.get('technique', 'Unknown')}: {mod.get('payload', 'N/A')[:50]}...{RESET}", flush=True)
                
            except json.JSONDecodeError:
                print(f"{YELLOW}[!][modifier]{RESET} Could not parse JSON, using fallback encoding", flush=True)
                # Fallback: generate basic encodings
                modifications = {
                    'modified_payloads': generate_basic_encodings(original_payload, test_category),
                    'raw_response': content
                }
                modified_payloads = modifications['modified_payloads']
                
        else:
            content = "Modifier unavailable"
            modifications = {'modified_payloads': []}
            modified_payloads = []
            
    except Exception as e:
        print(f"{RED}[-][modifier]{RESET} Error: {e}", flush=True)
        content = f"Modifier error: {e}"
        modifications = {'modified_payloads': []}
        modified_payloads = []
    
    return {
        'modifier': content,
        'modifier_suggestions': modified_payloads,
        'modification_analysis': modifications.get('analysis', '')
    }


def generate_basic_encodings(payload: str, test_category: str) -> List[Dict]:
    """
    Fallback function to generate basic payload encodings
    """
    encodings = []
    
    # URL encoding
    encodings.append({
        'payload': urllib.parse.quote(payload),
        'technique': 'URL Encoding (single)',
        'encoding_level': 'single',
        'explanation': 'Standard URL encoding to bypass basic filters',
        'priority': 1
    })
    
    # Double URL encoding
    encodings.append({
        'payload': urllib.parse.quote(urllib.parse.quote(payload)),
        'technique': 'URL Encoding (double)',
        'encoding_level': 'double',
        'explanation': 'Double encoding for nested decoding scenarios',
        'priority': 2
    })
    
    # Case variation
    case_varied = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    encodings.append({
        'payload': case_varied,
        'technique': 'Case Variation',
        'encoding_level': 'none',
        'explanation': 'Alternating case to bypass case-sensitive filters',
        'priority': 3
    })
    
    # Base64 (if applicable)
    if test_category in ['Command Injection', 'SSRF']:
        b64_payload = base64.b64encode(payload.encode()).decode()
        encodings.append({
            'payload': b64_payload,
            'technique': 'Base64 Encoding',
            'encoding_level': 'base64',
            'explanation': 'Base64 encoding for command/data obfuscation',
            'priority': 4
        })
    
    # HTML entity encoding (for XSS)
    if test_category == 'XSS':
        html_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
        encodings.append({
            'payload': html_encoded,
            'technique': 'HTML Entity Encoding',
            'encoding_level': 'html',
            'explanation': 'HTML entities to bypass XSS filters',
            'priority': 2
        })
    
    return encodings[:5]  # Return top 5
