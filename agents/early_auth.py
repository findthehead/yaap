"""
Early Authentication Agent - Runs BEFORE scout when --auth flag is provided
Attempts authentication early so all subsequent testing uses authenticated session
"""
from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState
from utils.ansi import MAGENTA, GREEN, RED, YELLOW, CYAN, RESET
from agents.login_injector import load_credentials, save_credentials, detect_form_fields, attempt_two_step_login
from tools.executor import execute
import json
import os
from urllib.parse import urlparse


def early_auth_node(state: AgentState, orch=None):
    """
    Early Authentication agent that runs BEFORE scout when --auth flag is provided.
    
    Purpose:
    1. Attempt authentication BEFORE endpoint discovery
    2. Save authenticated session for use in scout and subsequent testing
    3. Allow scout to run with authenticated cookies/headers
    
    Returns authenticated session_data if successful, or empty session if auth fails/disabled
    """
    
    auth_enabled = state.get('auth', False)
    
    # If --auth not provided, skip early auth
    if not auth_enabled:
        print(f"{YELLOW}[*][early_auth]{RESET} Early authentication skipped (--auth flag not provided)", flush=True)
        return {
            'early_auth': 'Skipped - authentication not requested',
            'session_data': {},
            'authenticated': False,
            'auth_method': 'none'
        }
    
    print(f"{MAGENTA}[>][early_auth]{RESET} Attempting early authentication before reconnaissance...", flush=True)
    
    target_url = state.get('current_test_url', orch.host if orch else '')
    if not target_url:
        print(f"{RED}[!][early_auth]{RESET} No target URL provided", flush=True)
        return {
            'early_auth': 'Failed - no target URL',
            'session_data': {},
            'authenticated': False,
            'auth_method': 'none'
        }
    
    # Load credentials
    credentials = load_credentials(target_url)
    
    if credentials.get('status') == 'empty' or not credentials.get('id'):
        print(f"{YELLOW}[!][early_auth]{RESET} No credentials configured for {urlparse(target_url).netloc}", flush=True)
        print(f"{YELLOW}[*] Configure credentials in configs/credentials.json", flush=True)
        return {
            'early_auth': 'No credentials configured',
            'session_data': {},
            'authenticated': False,
            'auth_method': 'none'
        }
    
    print(f"{CYAN}[*][early_auth]{RESET} Loaded credentials for {urlparse(target_url).netloc}", flush=True)
    
    auth_success = False
    auth_method = None
    session_data = {}
    
    # STRATEGY 1: Try existing cookie first
    if credentials.get('cookie') and credentials.get('status') == 'active':
        print(f"{CYAN}[*][early_auth]{RESET} Attempting authentication with saved cookie...", flush=True)
        
        test_cmd = f'curl -s -I -H "Cookie: {credentials.get("cookie")}" "{target_url}"'
        
        try:
            result = execute.invoke({'cmd': test_cmd, 'timeout_sec': 10})
            
            if '200 OK' in result or '302' in result or 'authenticated' in result.lower():
                print(f"{GREEN}[+][early_auth]{RESET} Saved cookie is valid!", flush=True)
                auth_success = True
                auth_method = 'cookie'
                session_data = {
                    'cookie': credentials.get('cookie'),
                    'session': credentials.get('session', '')
                }
            else:
                print(f"{YELLOW}[!][early_auth]{RESET} Saved cookie expired or invalid, attempting fresh login...", flush=True)
        except Exception as e:
            print(f"{YELLOW}[!][early_auth]{RESET} Cookie validation failed: {e}", flush=True)
    
    # STRATEGY 2: Attempt fresh login
    if not auth_success and credentials.get('id') and credentials.get('password'):
        print(f"{CYAN}[*][early_auth]{RESET} Attempting fresh login with username/password...", flush=True)
        
        # Fetch login page to extract form details
        try:
            fetch_cmd = f'curl -s "{target_url}"'
            login_page = execute.invoke({'cmd': fetch_cmd, 'timeout_sec': 10})
            
            # Try to extract form action from HTML
            form_action = target_url
            if '<form' in login_page.lower():
                # Simple extraction of form action
                if 'action=' in login_page:
                    try:
                        action_start = login_page.find('action="') + 8
                        action_end = login_page.find('"', action_start)
                        action = login_page[action_start:action_end]
                        
                        if action.startswith('http'):
                            form_action = action
                        elif action.startswith('/'):
                            base = target_url.split('?')[0].rsplit('/', 1)[0]
                            form_action = base + action
                        else:
                            base = target_url.split('?')[0].rsplit('/', 1)[0]
                            form_action = base + '/' + action
                    except Exception:
                        form_action = target_url
        except Exception:
            form_action = target_url
        
        # Try single-step login
        print(f"{YELLOW}[*][early_auth]{RESET} Attempting single-step login...", flush=True)
        login_cmd = f'curl -s -c /tmp/early_auth_cookies.txt -L -X POST -d "username={credentials.get("id")}&password={credentials.get("password")}" "{form_action}"'
        
        try:
            result = execute.invoke({'cmd': login_cmd, 'timeout_sec': 15})
            
            success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'authenticated', 'home', 'user']
            failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'denied', 'unauthorized']
            
            result_lower = result.lower()
            
            if any(indicator in result_lower for indicator in success_indicators):
                if not any(indicator in result_lower for indicator in failure_indicators):
                    print(f"{GREEN}[+][early_auth]{RESET} Single-step login successful!", flush=True)
                    auth_success = True
                    auth_method = 'form'
        except Exception as e:
            print(f"{YELLOW}[!][early_auth]{RESET} Single-step login failed: {e}", flush=True)
        
        # If single-step failed, try two-step login
        if not auth_success:
            print(f"{YELLOW}[!][early_auth]{RESET} Single-step failed, attempting two-step login...", flush=True)
            two_step_success, _ = attempt_two_step_login(form_action, 'username', 'password', credentials)
            if two_step_success:
                auth_success = True
                auth_method = 'form'
        
        # Extract cookies if successful
        if auth_success:
            try:
                if os.path.exists('/tmp/early_auth_cookies.txt'):
                    with open('/tmp/early_auth_cookies.txt', 'r') as f:
                        cookie_content = f.read()
                    
                    session_data = {
                        'cookie': cookie_content,
                        'session': '',
                        'id': credentials.get('id'),
                        'password': credentials.get('password')
                    }
                    
                    # Save for future use
                    save_credentials(target_url, session_data)
            except Exception as e:
                print(f"{YELLOW}[!][early_auth]{RESET} Could not extract cookies: {e}", flush=True)
    
    if auth_success:
        print(f"{GREEN}[+][early_auth]{RESET} Authentication successful via {auth_method}!", flush=True)
        print(f"{GREEN}[+][early_auth]{RESET} All subsequent testing will use authenticated session", flush=True)
        return {
            'early_auth': f'Authentication successful via {auth_method}',
            'session_data': session_data,
            'authenticated': True,
            'auth_method': auth_method
        }
    else:
        print(f"{RED}[!][early_auth]{RESET} Authentication failed", flush=True)
        print(f"{YELLOW}[*] Proceeding with unauthenticated testing", flush=True)
        return {
            'early_auth': 'Authentication failed',
            'session_data': {},
            'authenticated': False,
            'auth_method': 'none'
        }
