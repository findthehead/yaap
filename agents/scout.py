from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, AIMessage, ChatMessage
from states.agent_state import AgentState
from utils.parser import markdown_parse
from utils.extractor import formater
from utils.text import sanitize_model_text
from utils.ansi import CYAN, GREEN, RED, YELLOW, RESET, BOLD, MAGENTA
from utils.toolbind import run_tool_loop
from utils.reasoning import ReasoningDisplay, show_llm_response
from tools.executor import execute
from tools.websearch import research
from tools.directory_discovery import discover_directories_feroxbuster, identify_injection_points
from tools.form_discovery import discover_forms, test_form_injection
import time
import json



def scout_node(state: AgentState, orch = None):
    prompt_lines = markdown_parse('prompts/recon_prompt.md')
    prompt_content = '\n'.join(prompt_lines) if isinstance(prompt_lines, list) else str(prompt_lines)
    try:
        tools_overview = formater(orch=orch)
        if tools_overview:
            prompt_content += "\n\nAvailable tools you may leverage (local executor handles actual runs):\n" + tools_overview
    except Exception:
        pass
    
    task_text = state.get('task') or f"Assess {getattr(orch, 'host', '')}"
    if not isinstance(task_text, str) or not task_text.strip():
        task_text = f"Assess {getattr(orch, 'host', '')}"
    
    # Initialize reasoning display
    display = ReasoningDisplay("scout", GREEN)
    
    messages = [
        SystemMessage(content=prompt_content), 
        HumanMessage(content=task_text)
    ]
    try:
        print(f"\n{GREEN}{'='*80}{RESET}", flush=True)
        print(f"{GREEN}[>] SCOUT AGENT{RESET} {BOLD}Reconnaissance and Information Gathering{RESET}", flush=True)
        print(f"{GREEN}{'='*80}{RESET}\n", flush=True)
        time.sleep(0.5)
        
        display.thinking(f"Beginning reconnaissance on {getattr(orch, 'host', 'target')}. I'll use various tools to map the attack surface, identify technologies, and discover potential entry points.")
        
        display.plan([
            "Run feroxbuster to discover directories and endpoints",
            "Identify injection-prone endpoints (forms, parameters)",
            "Enumerate subdomains and DNS records",
            "Identify web technologies and versions",
            "Map the application structure",
            "Gather initial intelligence for research phase"
        ])
        
        # Step 1: Directory discovery with feroxbuster
        print(f"\n{YELLOW}[*] Phase 1: Directory Discovery with feroxbuster{RESET}\n")
        target_url = getattr(orch, 'host', '')
        session_data = state.get('session_data', {})
        
        ferox_result = discover_directories_feroxbuster(
            url=target_url,
            threads=50,
            timeout=30,
            session_data=session_data if session_data else None
        )
        
        ferox_data = json.loads(ferox_result)
        discovered_endpoints = []
        state['discovered_injection_points'] = []
        state['feroxbuster_endpoints'] = []
        
        if ferox_data.get('success'):
            discovery_tool = ferox_data.get('discovery_tool', 'feroxbuster')
            print(f"{GREEN}[+] {discovery_tool} discovered {ferox_data.get('endpoints_discovered', 0)} endpoints{RESET}\n")
            discovered_endpoints = ferox_result
            state['feroxbuster_endpoints'] = ferox_data.get('endpoints', [])
            state['endpoint_discovery_success'] = True
            state['endpoint_discovery_tool'] = discovery_tool
            state['endpoint_discovery_error'] = ''
            
            # Step 2: Identify injection points from discovered endpoints
            print(f"{YELLOW}[*] Phase 2: Analyzing endpoints for injection points{RESET}\n")
            injection_result = identify_injection_points(discovered_endpoints, target_url)
            injection_data = json.loads(injection_result)
            
            if injection_data.get('success'):
                candidates = injection_data.get('injection_candidates', [])
                print(f"{GREEN}[+] Identified {len(candidates)} potential injection points{RESET}\n")
                
                # Store injection points in state for injector agent
                state['discovered_injection_points'] = candidates
        else:
            error_msg = ferox_data.get('error', 'Unknown error')
            print(f"{RED}[!] endpoint discovery failed:{RESET}")
            print(f"{RED}    Error: {error_msg}{RESET}")
            # Print detailed error info
            if 'stderr' in ferox_data:
                print(f"{RED}    Stderr: {ferox_data['stderr']}{RESET}")
            if 'json_error' in ferox_data:
                print(f"{RED}    JSON Error: {ferox_data['json_error']}{RESET}")
            print(f"{YELLOW}[!] Cannot proceed without endpoint discovery!{RESET}")
            print(f"{YELLOW}[*] Fix: Install feroxbuster or katana fallback:{RESET}")
            print(f"{YELLOW}    feroxbuster: brew install feroxbuster | cargo install feroxbuster{RESET}")
            print(f"{YELLOW}    katana: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest{RESET}\n")
            
            # Return failure instead of falling back
            state['discovered_injection_points'] = []
            state['feroxbuster_endpoints'] = []
            state['endpoint_discovery_success'] = False
            state['endpoint_discovery_tool'] = ''
            state['endpoint_discovery_error'] = error_msg

            raise Exception(f"❌ CIRCUIT BREAKER ACTIVATED: endpoint discovery failed - {error_msg}")
        
        # Proceed if discovery tool executed successfully, even if it found 0 endpoints.
        # Circuit breaker should trigger only when discovery itself fails (all fallback tools fail).
        if not ferox_data.get('success'):
            raise Exception("Cannot proceed: endpoint discovery is required")

        if len(state.get('feroxbuster_endpoints', [])) == 0:
            print(f"{YELLOW}[!] Endpoint discovery succeeded but returned 0 endpoints. Continuing with limited reconnaissance.{RESET}\n")
        
        # Step 2b: Discover HTML forms in discovered endpoints
        print(f"{YELLOW}[*] Phase 2b: Validating forms for injection points{RESET}\n")
        discovered_forms = []
        discovered_endpoints = state.get('feroxbuster_endpoints', [])
        
        # Test first 10 endpoints for HTML forms
        for endpoint in discovered_endpoints[:10]:
            endpoint_url = endpoint.get('url') or endpoint
            try:
                forms_result = discover_forms(endpoint_url, session_data=session_data if session_data else None)
                forms_data = json.loads(forms_result)
                
                # VALIDATION: Only process if discovery succeeded
                if not forms_data.get('success'):
                    continue
                
                # VALIDATION: Only process forms with injectable fields
                injectable_forms = forms_data.get('forms', [])
                if not injectable_forms:
                    continue
                
                # Each form in the response is already validated to have injection points
                discovered_forms.extend(injectable_forms)
                
                for form in injectable_forms:
                    validation = form.get('validation', {})
                    print(f"    ✓ Form endpoint: {form.get('full_action')}")
                    print(f"      Injectable fields: {validation.get('injectable_count', 0)}")
                    print(f"      Fields: {', '.join(f['name'] for f in validation.get('injectable_fields', []))}")
            except Exception as e:
                # Skip endpoints that can't be parsed or don't have forms
                print(f"    [!] {endpoint_url}: {str(e)[:50]}")
                pass
        
        if discovered_forms:
            print(f"\n{GREEN}[+] Validated {len(discovered_forms)} form(s) with confirmed injectable fields{RESET}\n")
            state['discovered_forms'] = discovered_forms
        else:
            print(f"\n{YELLOW}[!] No forms with injectable fields found in discovered endpoints{RESET}\n")
            state['discovered_forms'] = []
        
        # Step 3: Standard reconnaissance with LLM for technology identification (not endpoint discovery)
        print(f"{YELLOW}[*] Phase 3: Technology and infrastructure identification{RESET}\n")
        
        recon_prompt = f"""As a security researcher, analyze the web application for technology stack and vulnerabilities.

IMPORTANT: ENDPOINT DISCOVERY IS ALREADY COMPLETE
- feroxbuster has discovered {len(state.get('feroxbuster_endpoints', []))} real endpoints
- Do NOT guess or assume additional endpoints
- Do NOT test endpoints not in the discovered list
- Focus ONLY on technology identification

DISCOVERED ENDPOINTS:
{json.dumps(state.get('feroxbuster_endpoints', [])[:15], indent=2)}

YOUR TASKS:
1. Analyze the ACTUAL discovered endpoints (no making up new ones)
2. Identify web server software and versions from endpoints
3. Detect technology frameworks based on discovered URLs
4. Find known CVEs for identified technologies
5. Identify security misconfigurations in discovered URLs

CRITICAL: Only make findings based on the endpoints that actually exist above.
Do NOT suggest endpoints that were not discovered by feroxbuster."""
        
        start = time.perf_counter()
        messages = [
            SystemMessage(content=recon_prompt),
            HumanMessage(content=f"Analyze {target_url} based on discovered endpoints")
        ]
        ai, tool_outputs = run_tool_loop(orch.model, [execute, research], messages, max_iters=1)
        response = ai
        elapsed = time.perf_counter() - start
        
        # Show LLM reasoning
        time.sleep(0.4)
        show_llm_response("scout", response, GREEN)
        
        # Extract discovered inputs (forms, parameters) for checklist agent
        # CRITICAL: Only include endpoints actually discovered by feroxbuster
        discovered_inputs = extract_inputs_from_scout(
            response.content, 
            tool_outputs,
            discovered_endpoints=state.get('feroxbuster_endpoints', []),
            discovered_forms=state.get('discovered_forms', [])
        )
        
        # Validate: ensure all inputs come from feroxbuster results
        discovered_inputs = validate_inputs_against_feroxbuster(
            discovered_inputs,
            state.get('feroxbuster_endpoints', []),
            state.get('discovered_forms', [])
        )
        
        display.conclusion(f"Reconnaissance complete. Discovered {len(discovered_inputs)} real inputs/forms from feroxbuster. Data ready for research agent.")
        
        time.sleep(0.3)
        print(f"\n{GREEN}✓{RESET} [scout] Completed in {YELLOW}{elapsed:.1f}s{RESET}\n", flush=True)
    except Exception as e:
        print(f"\n{RED}✗{RESET} [scout] Failed: {e}\n", flush=True)
        raise
    
    return {
        "scout": sanitize_model_text(response.content),
        "discovered_inputs": discovered_inputs,
        "current_test_url": getattr(orch, 'host', ''),
        "discovered_injection_points": state.get('discovered_injection_points', []),
        "discovered_forms": state.get('discovered_forms', []),
        "feroxbuster_endpoints": state.get('feroxbuster_endpoints', []),
        "endpoint_discovery_success": state.get('endpoint_discovery_success', False),
        "endpoint_discovery_tool": state.get('endpoint_discovery_tool', ''),
        "endpoint_discovery_error": state.get('endpoint_discovery_error', ''),
        "session_data": state.get('session_data', {})  # Preserve authenticated session from early_auth
    }


def extract_inputs_from_scout(scout_content, tool_outputs: list, discovered_endpoints: list = None, discovered_forms: list = None) -> list:
    """
    Extract discovered forms and ACTUAL parameters from scout results.
    CRITICAL: ONLY return validated forms - NO PARAMETER GUESSING.
    
    Args:
        scout_content: LLM response content
        tool_outputs: Tool outputs from LLM execution
        discovered_endpoints: List of endpoints from feroxbuster (whitelist)
        discovered_forms: List of forms from form discovery (whitelist)
    
    Returns:
        List of input dictionaries (forms only - no blind parameter assumptions)
    """
    import re
    
    if discovered_endpoints is None:
        discovered_endpoints = []
    if discovered_forms is None:
        discovered_forms = []
    
    # Convert scout_content to string if needed
    if isinstance(scout_content, list):
        scout_content = '\n'.join(str(item) for item in scout_content)
    elif not isinstance(scout_content, str):
        scout_content = str(scout_content)
    
    discovered = []
    
    # ONLY PRIORITY 1: Use discovered forms with validated injectable fields
    # DO NOT guess parameters - only test forms we actually found
    for form in discovered_forms:
        form_url = form.get('url', '')
        validation = form.get('validation', {})
        
        # Only add forms that have injectable fields
        if not validation.get('has_injection_points'):
            continue
        
        for field in validation.get('injectable_fields', []):
            if field.get('name'):
                discovered.append({
                    'type': 'Form field',
                    'url': form_url,
                    'parameter': field.get('name'),
                    'method': form.get('method', 'POST'),
                    'form_action': form.get('full_action', form_url),
                    'field_type': field.get('type', 'text'),
                    'source': 'form_discovery',
                    'confidence': 'High',
                    'validated': True
                })
    
    # REMOVED: Parameter guessing from keywords
    # We DO NOT assume parameters exist just because a keyword appears in the response
    # Example: If "q" appears in LLM output, we don't test ?q on all endpoints
    
    # Remove duplicates while preserving order
    seen = set()
    unique_discovered = []
    for item in discovered:
        key = f"{item.get('parameter', '')}_{item.get('url', '')}"
        if key not in seen:
            seen.add(key)
            unique_discovered.append(item)
    
    return unique_discovered[:20]  # Limit to first 20


def validate_inputs_against_feroxbuster(discovered_inputs: list, feroxbuster_endpoints: list, discovered_forms: list) -> list:
    """
    Validate that all discovered inputs come from:
    1. feroxbuster-discovered endpoints (whitelist)
    2. Extracted HTML forms (whitelist)
    
    Rejects any inputs that reference non-existent endpoints.
    
    Args:
        discovered_inputs: Initial list of discovered inputs
        feroxbuster_endpoints: List of endpoints from feroxbuster
        discovered_forms: List of forms from HTML parsing
    
    Returns:
        Validated list of inputs (only from discovered sources)
    """
    if not feroxbuster_endpoints and not discovered_forms:
        print(f"{YELLOW}[!] WARNING: No verified endpoints/forms discovered; continuing with limited testing context{RESET}")
        return []
    
    # Build whitelist of valid URLs
    valid_urls = set()
    
    # Add feroxbuster URLs
    for endpoint in feroxbuster_endpoints:
        url = endpoint.get('url') if isinstance(endpoint, dict) else endpoint
        if url:
            valid_urls.add(url)
    
    # Add form URLs
    for form in discovered_forms:
        url = form.get('url', '')
        if url:
            valid_urls.add(url)
    
    # Filter inputs: only keep those with valid URLs
    validated = []
    for input_item in discovered_inputs:
        input_url = input_item.get('url', '')
        
        # Check if this URL is in our whitelist
        if input_url in valid_urls:
            validated.append(input_item)
        else:
            # Log rejection for debugging
            if input_url:
                print(f"{YELLOW}[!] Rejecting input with non-discovered endpoint: {input_url}{RESET}")
    
    if not validated:
        print(f"{RED}[!] No valid inputs after feroxbuster validation{RESET}")
    
    return validated

