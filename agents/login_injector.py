"""
Login Injector Agent - Handles authentication and login form testing
Sub-agent of main injector, specialized for credential-based authentication
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import MAGENTA, GREEN, RED, YELLOW, CYAN, RESET
from utils.reasoning import ReasoningDisplay
from tools.executor import execute
import json
import os
from urllib.parse import urlparse
from datetime import datetime


def load_credentials(target_url):
    """Load credentials from configs/credentials.json for the target site"""
    try:
        with open('configs/credentials.json', 'r') as f:
            creds_data = json.load(f)
        
        # Extract domain from URL
        domain = urlparse(target_url).netloc
        
        # Find matching credentials
        for cred in creds_data.get('credentials', []):
            if domain in cred.get('site', '') or cred.get('site', '') in domain:
                return cred
        
        # Return default/empty if no match
        return {
            'site': domain,
            'id': '',
            'password': '',
            'cookie': '',
            'session': '',
            'status': 'empty'
        }
    except Exception as e:
        print(f"{YELLOW}[!][login_injector]{RESET} Error loading credentials: {e}", flush=True)
        return {'status': 'error'}


def save_credentials(target_url, credentials):
    """Save successful credentials to configs/credentials.json"""
    try:
        with open('configs/credentials.json', 'r') as f:
            creds_data = json.load(f)
        
        domain = urlparse(target_url).netloc
        credentials['site'] = domain
        credentials['last_updated'] = datetime.now().isoformat()
        credentials['status'] = 'active'
        
        # Update or add credentials
        found = False
        for i, cred in enumerate(creds_data.get('credentials', [])):
            if domain in cred.get('site', ''):
                creds_data['credentials'][i] = credentials
                found = True
                break
        
        if not found:
            creds_data['credentials'].append(credentials)
        
        with open('configs/credentials.json', 'w') as f:
            json.dump(creds_data, f, indent=2)
        
        print(f"{GREEN}[+][login_injector]{RESET} Credentials saved for {domain}", flush=True)
        return True
    except Exception as e:
        print(f"{RED}[-][login_injector]{RESET} Error saving credentials: {e}", flush=True)
        return False


def attempt_two_step_login(form_action: str, username_field: str, password_field: str, credentials: dict) -> tuple:
    """
    Attempt two-step login: first submit username only, then password.
    Returns: (success: bool, result: str)
    
    This handles login forms that appear in two steps:
    1. Username form → user enters username and clicks Next
    2. Password form → user receives password field and clicks Login
    """
    try:
        import re
        import os
        print(f"{CYAN}[*][login_injector]{RESET} Attempting two-step login flow...", flush=True)
        
        # Step 1: Submit username only with proper flags to capture HTML
        # -L: follow redirects
        # -b cookies.txt: send existing cookies
        # -c cookies.txt: save new cookies
        # -H Content-Type: ensure form submission
        username_cmd = f'curl -s -L -b cookies.txt -c cookies.txt -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "{username_field}={credentials.get("id")}" "{form_action}"'
        print(f"{YELLOW}[*][login_injector]{RESET} Step 1: Submitting username (field: {username_field})...", flush=True)
        print(f"{CYAN}[*][login_injector]{RESET} Command: {username_cmd[:150]}...", flush=True)
        
        step1_result = execute.invoke({'cmd': username_cmd, 'timeout_sec': 15})
        
        # CRITICAL DEBUG: Save response to file for inspection
        debug_file = '/tmp/login_step1_response.html'
        try:
            with open(debug_file, 'w') as f:
                f.write(step1_result)
            print(f"{CYAN}[*][login_injector]{RESET} Step 1 response saved to {debug_file}", flush=True)
        except Exception as e:
            print(f"{YELLOW}[!][login_injector]{RESET} Could not save response: {e}", flush=True)
        
        # Print response statistics
        response_size = len(step1_result)
        print(f"{CYAN}[*][login_injector]{RESET} Response size: {response_size} bytes", flush=True)
        
        if response_size < 100:
            print(f"{YELLOW}[!][login_injector]{RESET} Response too small (possibly error). Full response:", flush=True)
            print(step1_result[:500])
        else:
            print(f"{CYAN}[*][login_injector]{RESET} Response preview: {step1_result[:300]}...", flush=True)
        
        # CRITICAL: Extract ALL input field names from the HTML response
        # Try multiple regex patterns to handle different HTML structures
        
        # Pattern 1: Standard <input name="fieldname" ...>
        input_pattern1 = r'<input[^>]*name=["\']?([^"\'\s>]+)["\']?'
        fields_1 = re.findall(input_pattern1, step1_result, re.IGNORECASE)
        
        # Pattern 2: Simple name extraction for different HTML layouts
        input_pattern2 = r'<input\s+[^>]*name\s*=\s*["\']?([^"\'>\s]+)["\']?'
        fields_2 = re.findall(input_pattern2, step1_result, re.IGNORECASE)
        
        # Combine and deduplicate
        all_fields = list(set(fields_1 + fields_2))
        print(f"{CYAN}[*][login_injector]{RESET} Pattern 1 found: {fields_1}", flush=True)
        print(f"{CYAN}[*][login_injector]{RESET} Pattern 2 found: {fields_2}", flush=True)
        print(f"{CYAN}[*][login_injector]{RESET} All input fields in response: {all_fields}", flush=True)
        
        # Look for form tag itself
        form_match = re.search(r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?', step1_result, re.IGNORECASE)
        if form_match:
            print(f"{CYAN}[*][login_injector]{RESET} Found form action in response: {form_match.group(1)}", flush=True)
        
        # Check if we have password field indicators
        has_password_field = (
            'password' in step1_result.lower() or 
            'pwd' in step1_result.lower() or
            'type="password"' in step1_result.lower() or
            "type='password'" in step1_result.lower()
        )
        
        # Check if any field looks like a password field
        has_password_in_fields = any(
            'password' in field.lower() or 'pwd' in field.lower() 
            for field in all_fields
        )
        
        print(f"{CYAN}[*][login_injector]{RESET} Has 'password' keyword: {has_password_field}", flush=True)
        print(f"{CYAN}[*][login_injector]{RESET} Has password in fields: {has_password_in_fields}", flush=True)
        
        if has_password_field or has_password_in_fields or all_fields:
            # Detect the actual password field name from the response
            detected_pwd_field = password_field  # fallback
            
            if all_fields:
                for field in all_fields:
                    field_lower = field.lower()
                    # Check if this field matches any password synonym
                    if any(pwd_syn in field_lower for pwd_syn in ['password', 'pwd', 'pass', 'passwd', 'pswd']):
                        detected_pwd_field = field
                        print(f"{CYAN}[*][login_injector]{RESET} Detected password field from response: {detected_pwd_field}", flush=True)
                        break
            
            print(f"{YELLOW}[*][login_injector]{RESET} Step 2: Submitting password (field: {detected_pwd_field})...", flush=True)
            
            # Step 2: Submit BOTH username AND password together with cookies from step 1
            # This ensures the server maintains session state
            password_cmd = f'curl -s -L -b cookies.txt -c cookies.txt -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "{username_field}={credentials.get("id")}&{detected_pwd_field}={credentials.get("password")}" "{form_action}"'
            print(f"{CYAN}[*][login_injector]{RESET} Submitting with fields: {username_field}={credentials.get("id")}, {detected_pwd_field}=***", flush=True)
            
            step2_result = execute.invoke({'cmd': password_cmd, 'timeout_sec': 15})
            
            # Save step 2 response
            debug_file2 = '/tmp/login_step2_response.html'
            try:
                with open(debug_file2, 'w') as f:
                    f.write(step2_result)
                print(f"{CYAN}[*][login_injector]{RESET} Step 2 response saved to {debug_file2}", flush=True)
            except Exception as e:
                print(f"{YELLOW}[!][login_injector]{RESET} Could not save response: {e}", flush=True)
            
            # Print response snippet for debugging
            snippet = step2_result[:500] if len(step2_result) > 500 else step2_result
            print(f"{CYAN}[*][login_injector]{RESET} Step 2 Response (first 500 chars): {snippet}...", flush=True)
            
            # Check for success
            success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'authenticated', 'home', 'user', 'account']
            failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'denied', 'unauthorized']
            
            result_lower = step2_result.lower()
            
            # Check if we're still on login page (password hint still visible)
            if 'password' in result_lower and 'hunter' in result_lower:
                # Still showing password prompt - likely wrong credentials
                print(f"{RED}[!][login_injector]{RESET} Still on login page - credentials may be incorrect", flush=True)
                return (False, step2_result)
            
            # Check for success indicators
            if any(indicator in result_lower for indicator in success_indicators):
                if not any(indicator in result_lower for indicator in failure_indicators):
                    print(f"{GREEN}[+][login_injector]{RESET} Two-step login successful!", flush=True)
                    return (True, step2_result)
            
            print(f"{YELLOW}[!][login_injector]{RESET} Login response received, checking for errors...", flush=True)
            if any(fail in result_lower for fail in failure_indicators):
                print(f"{RED}[!][login_injector]{RESET} Login failed - invalid credentials", flush=True)
                return (False, step2_result)
        else:
            print(f"{YELLOW}[!][login_injector]{RESET} Password field not detected in response", flush=True)
            print(f"{YELLOW}[*][login_injector]{RESET} Response is probably JavaScript-rendered or error page", flush=True)
            print(f"{YELLOW}[*][login_injector]{RESET} Checking if response shows errors...", flush=True)
            
            # Look for common error patterns
            if 'error' in step1_result.lower() or 'failed' in step1_result.lower():
                print(f"{RED}[!][login_injector]{RESET} Error detected in response - login may have failed", flush=True)
        
        return (False, step1_result)
    
    except Exception as e:
        print(f"{RED}[!][login_injector]{RESET} Two-step login error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return (False, str(e))


def detect_form_fields(field_names: list) -> tuple:
    """
    Intelligently detect username and password fields from form field names.
    Handles variations like: username, userid, USERNAME, ID, account, email, login, pass, pwd, etc.
    
    Returns: (username_field, password_field)
    """
    username_synonyms = [
        'username', 'userid', 'user_id', 'user-id', 'user id',
        'email', 'mail', 'login', 'loginid', 'account', 'accountid',
        'id', 'uid', 'uname', 'user', 'userlogin', 'loginemail', 'accountemail'
    ]
    
    password_synonyms = [
        'password', 'pwd', 'pass', 'passwd', 'pswd', 'secret',
        'pin', 'pass_code', 'passphrase', 'userpassword'
    ]
    
    username_field = 'username'  # Default fallback
    password_field = 'password'  # Default fallback
    
    # Normalize field names for comparison
    field_names_lower = {field.lower(): field for field in field_names}
    
    # Find matching username field
    for synonym in username_synonyms:
        for field_lower, field_original in field_names_lower.items():
            if synonym == field_lower or synonym in field_lower.replace('_', '').replace('-', ''):
                username_field = field_original
                print(f"{CYAN}[*][login_injector]{RESET} Detected username field: {field_original}", flush=True)
                break
        if username_field != 'username':
            break
    
    # Find matching password field
    for synonym in password_synonyms:
        for field_lower, field_original in field_names_lower.items():
            if synonym == field_lower or synonym in field_lower.replace('_', '').replace('-', ''):
                password_field = field_original
                print(f"{CYAN}[*][login_injector]{RESET} Detected password field: {field_original}", flush=True)
                break
        if password_field != 'password':
            break
    
    return (username_field, password_field)


def login_injector_node(state: AgentState, orch=None):
    """
    Login Injector agent that:
    1. Receives validation result indicating login form
    2. Loads credentials from configs/credentials.json (only if --auth flag provided)
    3. Attempts authentication in order: cookie → id+password → bruteforce
    4. Saves successful credentials for reuse
    5. Returns session/cookie to main workflow
    """
    
    print(f"{MAGENTA}[>][login_injector]{RESET} Handling authentication...", flush=True)
    
    # CHECK: Only attempt login if --auth flag was provided
    auth_enabled = state.get('auth', False)
    if not auth_enabled:
        print(f"{YELLOW}[!][login_injector]{RESET} Authentication disabled (use --auth flag to enable)", flush=True)
        return {
            'login_injector': 'Authentication skipped (--auth flag not provided)',
            'auth_success': False,
            'auth_method': 'disabled',
            'routing_decision': 'injector'
        }
    
    # Get validation result
    validation_result = state.get('validation_result', {})
    target_url = state.get('current_test_url', orch.host if orch else '')
    form_details = validation_result.get('additional_context', {})
    
    # Load credentials for this site
    credentials = load_credentials(target_url)
    
    print(f"{CYAN}[*][login_injector]{RESET} Loaded credentials for {urlparse(target_url).netloc}", flush=True)
    print(f"{CYAN}[*][login_injector]{RESET} Status: {credentials.get('status', 'unknown')}", flush=True)
    
    # Authentication strategy: cookie → id+password → bruteforce
    auth_success = False
    auth_method = None
    session_data = {}
    
    # STRATEGY 1: Try existing cookie
    if credentials.get('cookie') and credentials.get('status') == 'active':
        print(f"{CYAN}[*][login_injector]{RESET} Attempting authentication with saved cookie...", flush=True)
        
        # Test cookie validity
        test_cmd = f'curl -s -I -H "Cookie: {credentials.get("cookie")}" "{target_url}"'
        
        try:
            result = execute.invoke({'cmd': test_cmd, 'timeout_sec': 10})
            
            if '200 OK' in result or 'authenticated' in result.lower():
                print(f"{GREEN}[+][login_injector]{RESET} Cookie authentication successful!", flush=True)
                auth_success = True
                auth_method = 'cookie'
                session_data = {
                    'cookie': credentials.get('cookie'),
                    'session': credentials.get('session', '')
                }
            else:
                print(f"{YELLOW}[!][login_injector]{RESET} Cookie expired or invalid", flush=True)
        except Exception as e:
            print(f"{YELLOW}[!][login_injector]{RESET} Cookie test failed: {e}", flush=True)
    
    # STRATEGY 2: Try id + password
    if not auth_success and credentials.get('id') and credentials.get('password'):
        print(f"{CYAN}[*][login_injector]{RESET} Attempting authentication with ID/Password...", flush=True)
        
        form_action = form_details.get('form_action', target_url)
        
        # Intelligently detect username and password fields from form
        field_names = form_details.get('field_names', [])
        username_field, password_field = detect_form_fields(field_names)
        
        # Try SINGLE-STEP login first (both username and password in one POST)
        print(f"{YELLOW}[*][login_injector]{RESET} Attempting single-step login (username + password together)...", flush=True)
        login_cmd = f'curl -s -c cookies.txt -L -X POST -d "{username_field}={credentials.get("id")}&{password_field}={credentials.get("password")}" "{form_action}"'
        
        try:
            result = execute.invoke({'cmd': login_cmd, 'timeout_sec': 15})
            
            # Check for successful login indicators
            success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'authenticated', 'home']
            failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'denied']
            
            result_lower = result.lower()
            
            if any(indicator in result_lower for indicator in success_indicators):
                if not any(indicator in result_lower for indicator in failure_indicators):
                    print(f"{GREEN}[+][login_injector]{RESET} Single-step login successful!", flush=True)
                    auth_success = True
                    auth_method = 'form'
            
            # If single-step failed, try TWO-STEP login
            if not auth_success:
                print(f"{YELLOW}[!][login_injector]{RESET} Single-step login failed, trying two-step flow...", flush=True)
                two_step_success, two_step_result = attempt_two_step_login(form_action, username_field, password_field, credentials)
                
                if two_step_success:
                    auth_success = True
                    auth_method = 'form'
                    result = two_step_result
                else:
                    # FALLBACK: If two-step also fails, try with different common field names
                    print(f"{YELLOW}[!][login_injector]{RESET} Two-step failed, trying common field name fallbacks...", flush=True)
                    fallback_attempts = [
                        ('username', 'password'),
                        ('email', 'password'),
                        ('login', 'password'),
                        ('user', 'pwd'),
                        ('username', 'pwd'),
                    ]
                    
                    for fb_user, fb_pwd in fallback_attempts:
                        if auth_success:
                            break
                        print(f"{YELLOW}[*][login_injector]{RESET} Trying fallback: {fb_user}/{fb_pwd}...", flush=True)
                        fallback_cmd = f'curl -s -c cookies.txt -L -X POST -d "{fb_user}={credentials.get("id")}&{fb_pwd}={credentials.get("password")}" "{form_action}"'
                        try:
                            fb_result = execute.invoke({'cmd': fallback_cmd, 'timeout_sec': 15})
                            fb_lower = fb_result.lower()
                            
                            if any(indicator in fb_lower for indicator in success_indicators):
                                if not any(indicator in fb_lower for indicator in failure_indicators):
                                    print(f"{GREEN}[+][login_injector]{RESET} Fallback login successful with {fb_user}/{fb_pwd}!", flush=True)
                                    auth_success = True
                                    auth_method = 'form'
                                    result = fb_result
                        except Exception as e:
                            print(f"{YELLOW}[*][login_injector]{RESET} Fallback failed: {e}", flush=True)
        
        except Exception as e:
            print(f"{YELLOW}[!][login_injector]{RESET} Login attempt failed: {e}", flush=True)
            # Try two-step as fallback
            two_step_success, _ = attempt_two_step_login(form_action, username_field, password_field, credentials)
            if two_step_success:
                auth_success = True
                auth_method = 'form'
        
        # Extract cookies if authentication was successful
        if auth_success:
            try:
                if os.path.exists('cookies.txt'):
                    with open('cookies.txt', 'r') as f:
                        cookie_content = f.read()
                    
                    # Parse cookies and save
                    session_data = {
                        'cookie': cookie_content,
                        'session': '',
                        'id': credentials.get('id'),
                        'password': credentials.get('password')
                    }
                    
                    # Save credentials for future use
                    save_credentials(target_url, session_data)
            except Exception as e:
                print(f"{YELLOW}[!][login_injector]{RESET} Could not extract cookies: {e}", flush=True)
    
    # STRATEGY 3: No valid credentials - route to bruteforce
    if not auth_success:
        print(f"{YELLOW}[!][login_injector]{RESET} No valid credentials available", flush=True)
        print(f"{CYAN}[*][login_injector]{RESET} Routing to bruteforce agent...", flush=True)
        
        return {
            'login_injector': 'Authentication failed - credentials needed',
            'auth_success': False,
            'routing_decision': 'bruteforce',
            'bruteforce_target': {
                'url': target_url,
                'form_action': form_details.get('form_action', target_url),
                'field_names': form_details.get('field_names', []),
                'authentication_type': validation_result.get('additional_context', {}).get('authentication_type', 'form')
            }
        }
    
    # Authentication successful - continue with testing
    print(f"{GREEN}[+][login_injector]{RESET} Authentication complete via {auth_method}", flush=True)
    print(f"{CYAN}[*][login_injector]{RESET} Proceeding with authenticated testing...", flush=True)
    
    return {
        'login_injector': f'Authentication successful via {auth_method}',
        'auth_success': True,
        'auth_method': auth_method,
        'session_data': session_data,
        'routing_decision': 'regular_injector',
        'authenticated': True
    }
