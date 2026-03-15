"""
Validator Agent - Classifies input types and determines injection strategy
Sits between checklist and injector to properly classify form types and parameters
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import CYAN, GREEN, RED, YELLOW, RESET
from utils.reasoning import ReasoningDisplay
import json
import re
import os
from urllib.parse import urlparse


def load_validator_guidelines():
    """Load comprehensive validator guidelines from validator.md"""
    try:
        guidelines_path = os.path.join(os.path.dirname(__file__), '..', 'prompts', 'validator.md')
        with open(guidelines_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"{YELLOW}[!][validator]{RESET} Could not load validator.md: {e}", flush=True)
        return ""


def validator_node(state: AgentState, orch=None):
    """
    Validator agent that:
    1. Receives test directive from checklist
    2. Analyzes the target to classify input type
    3. Determines if it's a login form, API endpoint, URL parameter, header, cookie
    4. Routes to appropriate handler (login_injector, bruteforce, or regular injector)
    """
    
    print(f"{CYAN}[>][validator]{RESET} Validating and classifying input type...", flush=True)
    
    # Get test directive from checklist
    checklist_directive = state.get('checklist_directive', {})
    next_test = checklist_directive.get('next_test', {})
    
    test_category = next_test.get('category', 'Unknown')
    target_url = next_test.get('target', state.get('current_test_url', orch.host if orch else ''))
    parameter = next_test.get('parameter', '')
    test_type = next_test.get('test_type', 'parameter')
    
    # Get tools run history to analyze forms
    tools_runs = state.get('tools_runs', [])
    recent_output = tools_runs[-1].get('output', '') if tools_runs else ''
    
    print(f"{CYAN}[*][validator]{RESET} Analyzing: {test_category} on '{parameter}' at {target_url[:50]}...", flush=True)
    
    # Load validator guidelines
    validator_guidelines = load_validator_guidelines()
    
    # Build validation prompt
    prompt = f"""You are an Input Validation Specialist analyzing web application inputs to classify their type and determine the proper testing approach.

COMPREHENSIVE GUIDELINES:
{validator_guidelines}

TARGET INFORMATION:
- URL: {target_url}
- Parameter: {parameter}
- Test Category: {test_category}
- Test Type: {test_type}

RECENT TOOL OUTPUT (for context):
```
{recent_output[:1000] if recent_output else 'No recent output'}
```

CRITICAL INSTRUCTIONS:
1. FIRST: Check if ANY entry points exist (URL params, forms, cookies, headers)
2. If NO entry points found → Return input_type: "NO_ENTRY_POINT" and routing_decision: "END_TESTING"
3. If entry points exist → Classify the input type using the guidelines above
4. Return ONLY valid JSON with all required fields

Follow the validator.md guidelines exactly for classification and routing decisions.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"Classify the input type for {parameter} at {target_url}. Return ONLY JSON.")
    ]
    
    display = ReasoningDisplay("validator", CYAN)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. validator", flush=True)
        print(f"     • Classifying input type: {parameter}", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        print(f"[*] Analyzing results and planning next action...\n", flush=True)
        
        if response:
            content = response.content
            
            # Extract validation result
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
                
                validation_result = json.loads(json_str)
                
                input_type = validation_result.get('input_type', 'URL_PARAMETER')
                routing = validation_result.get('routing_decision', 'regular_injector')
                requires_auth = validation_result.get('requires_authentication', False)
                has_entry_points = validation_result.get('has_entry_points', True)
                
                # Check if no entry points found
                if input_type == 'NO_ENTRY_POINT' or not has_entry_points:
                    print(f"{RED}[!][validator]{RESET} NO ENTRY POINTS FOUND - No forms, parameters, cookies, or headers to test", flush=True)
                    print(f"{YELLOW}[!][validator]{RESET} Testing will be stopped - static page with no injection points", flush=True)
                    validation_result['routing_decision'] = 'END_TESTING'
                    routing = 'END_TESTING'
                else:
                    print(f"{GREEN}[+][validator]{RESET} Input classified as: {input_type}", flush=True)
                    print(f"{CYAN}[*][validator]{RESET} Routing to: {routing}", flush=True)
                
                if requires_auth:
                    print(f"{YELLOW}[!][validator]{RESET} Authentication required - will handle credentials", flush=True)
                
            except json.JSONDecodeError as e:
                print(f"{YELLOW}[!][validator]{RESET} Could not parse validation, using defaults", flush=True)
                validation_result = {
                    'input_type': 'URL_PARAMETER',
                    'routing_decision': 'regular_injector',
                    'requires_authentication': False,
                    'injection_strategy': {
                        'method': 'GET',
                        'location': 'parameter',
                        'parameter_name': parameter
                    }
                }
        else:
            content = "Validator unavailable"
            validation_result = {
                'input_type': 'URL_PARAMETER',
                'routing_decision': 'regular_injector'
            }
            
    except Exception as e:
        print(f"{RED}[-][validator]{RESET} Error: {e}", flush=True)
        content = f"Validation error: {e}"
        validation_result = {
            'input_type': 'URL_PARAMETER',
            'routing_decision': 'regular_injector'
        }
    
    return {
        'validator': content,
        'validation_result': validation_result,
        'input_classification': validation_result.get('input_type', 'URL_PARAMETER'),
        'routing_decision': validation_result.get('routing_decision', 'regular_injector')
    }
