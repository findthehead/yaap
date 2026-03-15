"""
Checklist Agent - Tracks testing progress through comprehensive security checklist
Maintains state of what's been tested, what needs testing, and coordinates with other agents
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import CYAN, GREEN, RED, YELLOW, RESET
from utils.reasoning import ReasoningDisplay
import json


def checklist_node(state: AgentState, orch=None):
    """
    Checklist agent that:
    1. Loads comprehensive testing checklist
    2. Tracks progress (tested/untested items)
    3. Provides current testing focus to other agents
    4. Updates status based on findings
    5. Suggests next test based on context
    """
    
    print(f"{CYAN}[>][checklist]{RESET} Loading testing checklist and tracking progress...", flush=True)
    
    # Get current checklist state or initialize
    checklist_state = state.get('checklist_state', {})
    if not checklist_state:
        # Define test queue: all vulnerability types to test per parameter
        test_queue = [
            {'category': 'XSS', 'description': 'Cross-Site Scripting'},
            {'category': 'SQLi', 'description': 'SQL Injection'},
            {'category': 'Command Injection', 'description': 'OS Command Injection'},
            {'category': 'SSRF', 'description': 'Server-Side Request Forgery'},
            {'category': 'Path Traversal', 'description': 'Directory Traversal'},
            {'category': 'Business Logic', 'description': 'IDOR and logic flaws'}
        ]
        
        checklist_state = {
            'test_queue': test_queue,
            'current_test_index': 0,
            'current_category': test_queue[0]['category'],
            'current_item': test_queue[0]['description'],
            'tested_items': [],  # Format: 'XSS_q', 'SQLi_q', etc
            'failed_attempts': {},
            'current_payload_round': 1,
            'max_payload_rounds': 5,
            'current_target': state.get('current_test_url', ''),
            'current_parameter': 'q',
            'vulnerabilities_found': []  # Track confirmed vulns
        }
    
    # Check if we need to move to next test type
    observation = state.get('observation', {})
    current_round = checklist_state.get('current_payload_round', 1)
    max_rounds = checklist_state.get('max_payload_rounds', 5)
    
    # If vulnerability found, mark test as complete and move to next test type
    if observation.get('vulnerability_found', False) and observation.get('confidence') in ['Confirmed', 'Likely']:
        current_param = checklist_state.get('current_parameter', 'q')
        current_test = checklist_state.get('current_category', 'XSS')
        test_id = f"{current_test}_{current_param}"
        
        if test_id not in checklist_state['tested_items']:
            checklist_state['tested_items'].append(test_id)
            checklist_state['vulnerabilities_found'].append(test_id)
        
        # Move to next test type
        current_index = checklist_state.get('current_test_index', 0)
        test_queue = checklist_state.get('test_queue', [])
        
        if current_index + 1 < len(test_queue):
            checklist_state['current_test_index'] = current_index + 1
            checklist_state['current_category'] = test_queue[current_index + 1]['category']
            checklist_state['current_item'] = test_queue[current_index + 1]['description']
            checklist_state['current_payload_round'] = 1
            print(f"{GREEN}[+][checklist]{RESET} Vulnerability found! Moving to next test: {test_queue[current_index + 1]['category']}", flush=True)
        else:
            print(f"{GREEN}[+][checklist]{RESET} All tests completed for parameter '{current_param}'", flush=True)
    
    # If all rounds failed for current test, move to next test type
    elif observation.get('next_action') == 'move_to_next_test' or current_round >= max_rounds:
        current_param = checklist_state.get('current_parameter', 'q')
        current_test = checklist_state.get('current_category', 'XSS')
        test_id = f"{current_test}_{current_param}"
        
        if test_id not in checklist_state['tested_items']:
            checklist_state['tested_items'].append(test_id)
        
        # Move to next test type
        current_index = checklist_state.get('current_test_index', 0)
        test_queue = checklist_state.get('test_queue', [])
        
        if current_index + 1 < len(test_queue):
            checklist_state['current_test_index'] = current_index + 1
            checklist_state['current_category'] = test_queue[current_index + 1]['category']
            checklist_state['current_item'] = test_queue[current_index + 1]['description']
            checklist_state['current_payload_round'] = 1
            print(f"{YELLOW}[*][checklist]{RESET} Test failed. Moving to: {test_queue[current_index + 1]['category']}", flush=True)
        else:
            # All test types done for this parameter, check if there are more parameters
            discovered_inputs = state.get('discovered_inputs', [])
            if len(discovered_inputs) > 1:
                # Move to next parameter and reset test queue
                checklist_state['current_test_index'] = 0
                checklist_state['current_category'] = test_queue[0]['category']
                checklist_state['current_item'] = test_queue[0]['description']
                checklist_state['current_payload_round'] = 1
                print(f"{CYAN}[*][checklist]{RESET} Moving to next parameter/endpoint", flush=True)
            else:
                print(f"{GREEN}[+][checklist]{RESET} All tests completed", flush=True)
    
    # If observer suggests trying different payload (not encoding), increment round
    elif observation.get('next_action') == 'try_different_payload':
        if current_round < max_rounds:
            checklist_state['current_payload_round'] = current_round + 1
            print(f"{YELLOW}[*][checklist]{RESET} Incrementing to round {current_round + 1}/{max_rounds}", flush=True)
        else:
            # Max rounds reached, handled above
            pass
    
    # Get discovered forms/inputs from scout/researcher
    discovered_inputs = state.get('discovered_inputs', [])
    current_url = state.get('current_test_url', orch.host if orch else '')
    feroxbuster_endpoints = state.get('feroxbuster_endpoints', [])
    endpoint_discovery_success = state.get('endpoint_discovery_success', None)
    endpoint_discovery_error = state.get('endpoint_discovery_error', '')
    endpoint_discovery_tool = state.get('endpoint_discovery_tool', 'unknown')
    
    # Circuit-break only when discovery explicitly failed upstream (all tools failed)
    if endpoint_discovery_success is False:
        print(f"{RED}[!][checklist] ERROR: Endpoint discovery failed upstream{RESET}")
        if endpoint_discovery_error:
            print(f"{RED}[!] Discovery error: {endpoint_discovery_error}{RESET}")
        return {
            "checklist": "ERROR: Endpoint discovery failed",
            "next_test": {},
            "checklist_progress": {"error": "Endpoint discovery failed"}
        }

    # Discovery may succeed with 0 endpoints; continue with constrained testing path.
    if not feroxbuster_endpoints:
        if endpoint_discovery_success is True:
            print(f"{YELLOW}[*][checklist] Endpoint discovery succeeded via {endpoint_discovery_tool} but returned 0 endpoints{RESET}")
            print(f"{YELLOW}[*] Continuing with limited testing using current target context{RESET}")
        else:
            print(f"{YELLOW}[!][checklist] WARNING: No endpoint whitelist in state{RESET}")
            print(f"{YELLOW}[*] Continuing with limited testing using current target context{RESET}")
    
    # Discovered validated inputs are preferred; empty input list is allowed.
    if not discovered_inputs:
        print(f"{YELLOW}[!][checklist] No validated discovered inputs found{RESET}")
        print(f"{YELLOW}[*] Discovered endpoints available: {len(feroxbuster_endpoints)}{RESET}")
        print(f"{YELLOW}[*] Continuing with controlled heuristic testing parameters{RESET}")
    
    # Build checklist prompt
    prompt = f"""You are a Security Testing Checklist Manager coordinating a comprehensive penetration test.

CURRENT STATE:
- Testing Category: {checklist_state.get('current_category', 'Unknown')}
- Current Focus: {checklist_state.get('current_item', 'Unknown')}
- Payload Round: {checklist_state.get('current_payload_round', 1)} of {checklist_state.get('max_payload_rounds', 5)}
- Target URL: {current_url}
- Discovered Inputs: {len(discovered_inputs)} forms/parameters
- Already Tested: {len(checklist_state.get('tested_items', []))} items

DISCOVERED INPUTS:
{json.dumps(discovered_inputs[:10], indent=2) if discovered_inputs else 'No forms discovered yet'}

FAILED ATTEMPTS (need different approach):
{json.dumps(checklist_state.get('failed_attempts', {}), indent=2)}

YOUR TASKS:
1. Review the comprehensive checklist from prompts/checklist.md
2. Determine what should be tested next based on:
   - Discovered attack surface (forms, parameters, endpoints)
   - Already tested items
   - Failed attempts that need different payloads
   - Current vulnerability category
3. Provide specific testing instructions including:
   - Vulnerability type to test
   - Target input/parameter
   - Payload category (which round: 1-5)
   - Expected indicators of success
4. Track progress and update checklist state

OUTPUT FORMAT (JSON):
{{
  "next_test": {{
    "category": "XSS" | "SQLi" | "Command Injection" | "SSRF" | etc,
    "target": "URL or form identifier",
    "parameter": "specific input field name",
    "payload_round": 1-5,
    "test_type": "reflected-xss" | "sql-injection" | etc,
    "success_indicators": ["alert box", "SQL error", "command output"],
    "reasoning": "Why this test next"
  }},
  "checklist_progress": {{
    "total_items": 400,
    "tested": 15,
    "remaining": 385,
    "current_focus": "Input Validation"
  }},
  "should_move_to_next_category": false,
  "recommendations": ["suggestion 1", "suggestion 2"]
}}

Analyze the current state and provide the next testing directive.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"What should we test next? Current context: {state.get('task', 'Initial assessment')}")
    ]
    
    display = ReasoningDisplay("checklist", CYAN)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. checklist", flush=True)
        print(f"     • Loading testing checklist", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
        
        if response:
            content = response.content
            print(f"{GREEN}[+][checklist]{RESET} Next test directive prepared", flush=True)
            
            print(f"\n{GREEN}✓ [checklist] Conclusion:{RESET}", flush=True)
            print(f"   Loaded next test from checklist\n", flush=True)
            
            # Try to extract JSON from response
            try:
                # Look for JSON in markdown code blocks or raw JSON
                if '```json' in content:
                    json_start = content.find('```json') + 7
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                elif '```' in content:
                    json_start = content.find('```') + 3
                    json_end = content.find('```', json_start)
                    json_str = content[json_start:json_end].strip()
                else:
                    json_str = content
                
                checklist_directive = json.loads(json_str)
                
                # Update checklist state
                if 'next_test' in checklist_directive:
                    next_test = checklist_directive['next_test']
                    checklist_state['current_category'] = next_test.get('category', checklist_state['current_category'])
                    checklist_state['current_item'] = next_test.get('test_type', checklist_state['current_item'])
                    checklist_state['current_target'] = next_test.get('target', current_url)
                    checklist_state['current_parameter'] = next_test.get('parameter', checklist_state.get('current_parameter', 'q'))
                
                # Ensure next_test has the category from checklist_state if missing
                if 'next_test' in checklist_directive and 'category' not in checklist_directive['next_test']:
                    checklist_directive['next_test']['category'] = checklist_state.get('current_category', 'XSS')
                
                current_test = checklist_state.get('current_category', 'XSS')
                current_param = checklist_state.get('current_parameter', 'q')
                current_round = checklist_state.get('current_payload_round', 1)
                test_index = checklist_state.get('current_test_index', 0) + 1
                test_total = len(checklist_state.get('test_queue', []))
                
                print(f"{CYAN}[#][checklist]{RESET} Test {test_index}/{test_total}: {current_test} on '{current_param}' (Round {current_round}/5)", flush=True)
                
            except json.JSONDecodeError:
                print(f"{YELLOW}[!][checklist]{RESET} Could not parse JSON, using text response", flush=True)
                checklist_directive = {
                    'raw_response': content,
                    'next_test': {
                        'category': checklist_state.get('current_category', 'XSS'),
                        'parameter': checklist_state.get('current_parameter', 'q'),
                        'payload_round': checklist_state.get('current_payload_round', 1)
                    }
                }
        else:
            content = "Checklist unavailable - proceed with standard testing"
            checklist_directive = {}
            
    except Exception as e:
        print(f"{RED}[-][checklist]{RESET} Error: {e}", flush=True)
        content = f"Checklist error: {e}"
        checklist_directive = {}
    
    return {
        'checklist': content,
        'checklist_state': checklist_state,
        'checklist_directive': checklist_directive,
        'feroxbuster_endpoints': feroxbuster_endpoints,  # Whitelist for injection testing
        'discovered_inputs': discovered_inputs  # Only feroxbuster-validated inputs
    }


def update_checklist_state(state: AgentState, test_result: dict):
    """
    Update checklist state based on test results
    
    Args:
        state: Current agent state
        test_result: {
            'test_type': 'xss',
            'target': 'http://example.com/search',
            'parameter': 'q',
            'payload': '<script>alert(1)</script>',
            'success': True/False,
            'evidence': 'response data'
        }
    """
    checklist_state = state.get('checklist_state', {})
    
    # Mark as tested
    test_id = f"{test_result.get('test_type', 'unknown')}_{test_result.get('parameter', 'unknown')}"
    if 'tested_items' not in checklist_state:
        checklist_state['tested_items'] = []
    
    if test_id not in checklist_state['tested_items']:
        checklist_state['tested_items'].append(test_id)
    
    # Track failed attempts for payload modification
    if not test_result.get('success', False):
        if 'failed_attempts' not in checklist_state:
            checklist_state['failed_attempts'] = {}
        
        if test_id not in checklist_state['failed_attempts']:
            checklist_state['failed_attempts'][test_id] = []
        
        checklist_state['failed_attempts'][test_id].append({
            'payload': test_result.get('payload', ''),
            'round': checklist_state.get('current_payload_round', 1),
            'evidence': test_result.get('evidence', '')[:200]
        })
    
    return checklist_state
