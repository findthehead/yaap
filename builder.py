from langgraph.graph import StateGraph, END
from states.agent_state import AgentState
from agents.scout import scout_node
from agents.researcher import researcher_node
from agents.arsenal import arsenal_node
from agents.final_reporter import reporter_node
from agents.checklist import checklist_node
from agents.injector import injector_node
from agents.observer import observer_node
from agents.modifier import modifier_node
from agents.encoder import encoder_node
from agents.validator import validator_node
from agents.login_injector import login_injector_node
from agents.bruteforce import bruteforce_node
from agents.early_auth import early_auth_node
from agents.condition import proceed, after_research
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.prebuilt import ToolNode
from tools.executor import execute
from tools.websearch import research
from tools.xss_tester import test_xss_payloads
from tools.sqli_tester import test_sqli, quick_sqli_check
from tools.command_injection_tester import test_command_injection, quick_command_injection_check
# OWASP Top 10 additional testers
from tools.ssrf_tester import test_ssrf_payloads, quick_ssrf_check
from tools.path_traversal_tester import test_path_traversal, quick_path_traversal_check
from tools.xxe_tester import test_xxe_injection, quick_xxe_check
from tools.idor_tester import test_idor_vulnerabilities, test_idor_with_uuid
# API Top 10 testers
from tools.api_security_tester import (
    test_graphql_security, test_jwt_security,
    test_api_rate_limiting, test_api_authentication_bypass
)
# Infrastructure testers
from tools.infrastructure_tester import (
    test_tls_ssl_security, enumerate_subdomains, detect_waf,
    test_server_misconfiguration, test_security_headers
)
# Web Security testers (File Upload, Auth, CORS, Headers)
from tools.file_upload_inclusion_tester import (
    test_unrestricted_file_upload, test_file_inclusion,
    test_remote_file_inclusion, test_phar_deserialization
)
from tools.auth_escalation_tester import (
    test_default_credentials, test_broken_authentication,
    test_privilege_escalation, test_access_control_bypass,
    test_password_reset_flaws
)
from tools.cors_headers_tester import (
    test_cors_misconfiguration, test_missing_security_headers,
    test_cache_poisoning, test_http_response_splitting,
    test_host_header_injection
)

checkpointer = InMemorySaver()

# Extended tools list with OWASP Top 10, API Top 10, and web security coverage
tools = [
    # Original tools
    execute, research, test_xss_payloads, test_sqli, quick_sqli_check,
    test_command_injection, quick_command_injection_check,
    # OWASP Top 10 additions
    test_ssrf_payloads, quick_ssrf_check,
    test_path_traversal, quick_path_traversal_check,
    test_xxe_injection, quick_xxe_check,
    test_idor_vulnerabilities, test_idor_with_uuid,
    # API Top 10
    test_graphql_security, test_jwt_security,
    test_api_rate_limiting, test_api_authentication_bypass,
    # Infrastructure
    test_tls_ssl_security, enumerate_subdomains, detect_waf,
    test_server_misconfiguration, test_security_headers,
    # Web Security - File Upload & Inclusion
    test_unrestricted_file_upload, test_file_inclusion,
    test_remote_file_inclusion, test_phar_deserialization,
    # Web Security - Authentication & Privilege Escalation
    test_default_credentials, test_broken_authentication,
    test_privilege_escalation, test_access_control_bypass,
    test_password_reset_flaws,
    # Web Security - CORS & Security Headers
    test_cors_misconfiguration, test_missing_security_headers,
    test_cache_poisoning, test_http_response_splitting,
    test_host_header_injection,
]



def validation_router(state: dict) -> str:
    """
    Routes after validator based on input classification
    Returns: 'login_injector' | 'injector'
    """
    validation_result = state.get('validation_result', {})
    input_type = validation_result.get('input_type', 'UNKNOWN')
    routing_decision = validation_result.get('routing_decision', 'INJECTOR')
    
    # If classified as LOGIN_FORM, use specialized login_injector
    if input_type == 'LOGIN_FORM' or routing_decision == 'LOGIN_INJECTOR':
        return 'login_injector'
    
    # If classified as BRUTEFORCE_TARGET, go straight to bruteforce
    if input_type == 'BRUTEFORCE_TARGET' or routing_decision == 'BRUTEFORCE':
        return 'bruteforce'
    
    # All other types (URL_PARAMETER, COOKIE_PARAMETER, etc.) use regular injector
    return 'injector'


def auth_router(state: dict) -> str:
    """
    Routes after login_injector based on authentication result
    Returns: 'bruteforce' | 'injector'
    """
    auth_success = state.get('auth_success', False)
    auth_method = state.get('auth_method', '')
    
    # If authentication succeeded (via cookie or credentials), proceed to regular testing
    if auth_success:
        return 'injector'
    
    # If auth failed and method was 'bruteforce_needed', route to bruteforce agent
    if auth_method == 'bruteforce_needed':
        return 'bruteforce'
    
    # Default: skip login and proceed to regular testing (might find unauth vulns)
    return 'injector'


def bruteforce_router(state: dict) -> str:
    """
    Routes after bruteforce based on credential discovery result
    Returns: 'login_injector' | 'injector'
    """
    bruteforce_success = state.get('bruteforce_success', False)
    credentials_found = state.get('credentials_found')
    
    # If credentials found, go back to login_injector to use them
    if bruteforce_success and credentials_found:
        return 'login_injector'
    
    # If bruteforce failed, skip login and proceed to regular testing
    return 'injector'


def iterative_testing_loop(state: dict) -> str:
    """
    Routing logic for iterative payload testing loop
    Returns: 'checklist' | 'modifier' | 'encoder' | 'reporter'
    """
    observation = state.get('observation', {})
    current_round = state.get('current_payload_round', 1)
    checklist_state = state.get('checklist_state', {})
    max_rounds = checklist_state.get('max_payload_rounds', 5)
    tested_items = checklist_state.get('tested_items', [])
    encoder_attempts = state.get('encoder_attempts', 0)
    reflection_context = state.get('reflection_context', {})
    test_queue = checklist_state.get('test_queue', [])
    current_test_index = checklist_state.get('current_test_index', 0)
    
    # If vulnerability found, move to next test type (don't stop, keep testing)
    if observation.get('vulnerability_found', False) and observation.get('confidence') in ['Confirmed', 'Likely']:
        # Check if there are more test types to run
        if current_test_index + 1 < len(test_queue):
            return 'checklist'  # Move to next vulnerability type
        else:
            # All vulnerability types tested, now report all findings
            return 'reporter'
    
    # If reached max rounds for current test, move to next checklist item
    if current_round >= max_rounds:
        return 'checklist'
    
    # If tested all vulnerability types, finish and report
    if len(tested_items) >= len(test_queue):
        return 'reporter'
    
    # Check observer's recommendation
    next_action = observation.get('next_action', 'try_different_payload')
    
    # If observer suggests using encoder and we haven't exceeded encoder attempts
    if next_action == 'use_encoder' and encoder_attempts < 3:
        # Payload is reflected but not exploited - use encoder
        return 'encoder'
    
    # If encoder attempts exhausted or encoding complete, move to next checklist item
    encoding_complete = state.get('encoding_complete', False)
    if encoding_complete or encoder_attempts >= 3:
        return 'checklist'
    
    # If observer suggests modification and we haven't tried it yet
    modifier_suggestions = state.get('modifier_suggestions', [])
    
    if next_action == 'modify_encoding' and not modifier_suggestions:
        # Need to modify payload first (legacy modifier path)
        return 'modifier'
    
    # Default: move to next checklist item (this prevents infinite loops)
    return 'checklist'


def build(orch=None):
    builder = StateGraph(AgentState)
    # Wrap nodes with orch parameter using lambda
    builder.add_node("early_auth", lambda state: early_auth_node(state, orch))
    builder.add_node("scout", lambda state: scout_node(state, orch))
    builder.add_node("researcher", lambda state: researcher_node(state, orch))
    builder.add_node("researcher2", lambda state: researcher_node(state, orch))
    builder.add_node("reporter", lambda state: reporter_node(state, orch))
    builder.add_node("arsenal", lambda state: arsenal_node(state, orch))
    builder.add_node("tools", ToolNode(tools))
    
    # NEW: Add iterative testing agents
    builder.add_node("checklist", lambda state: checklist_node(state, orch))
    builder.add_node("validator", lambda state: validator_node(state, orch))
    builder.add_node("login_injector", lambda state: login_injector_node(state, orch))
    builder.add_node("bruteforce", lambda state: bruteforce_node(state, orch))
    builder.add_node("injector", lambda state: injector_node(state, orch))
    builder.add_node("observer", lambda state: observer_node(state, orch))
    builder.add_node("modifier", lambda state: modifier_node(state, orch))
    builder.add_node("encoder", lambda state: encoder_node(state, orch))  # New encoder agent
    
    # Determine entry point based on --auth flag and test mode
    auth_enabled = getattr(orch, 'auth', False) if orch else False
    test_mode = getattr(orch, 'test', 'recon').lower() if orch else 'recon'
    
    # FLOW LOGIC:
    # If --auth provided: early_auth -> scout (or arsenal for hunt mode) -> ...
    # If --auth NOT provided: scout (or arsenal for hunt mode) -> ... (login later if needed)
    
    if auth_enabled:
        # Start with early authentication
        builder.set_entry_point("early_auth")
        builder.add_edge("early_auth", "arsenal" if test_mode == 'hunt' else "scout")
    else:
        # Skip early auth, start directly with scout or arsenal
        if test_mode == 'hunt':
            builder.set_entry_point("arsenal")
        else:
            builder.set_entry_point("scout")
    
    # Scout always routes to researcher (for endpoint analysis)
    builder.add_edge("scout", "researcher")
    
    # After research, branch based on mode: recon -> reporter, hunt -> arsenal
    builder.add_conditional_edges(
        "researcher",
        lambda state: after_research(state, orch),
        {"arsenal": "arsenal", "reporter": "reporter"}
    )
    # If we took the arsenal path (hunt), continue through the full chain
    builder.add_edge("arsenal", "researcher2")
    builder.add_edge("researcher2", "checklist")  # Start iterative loop with checklist
    
    # AUTHENTICATION WORKFLOW: checklist -> validator -> {login_injector|bruteforce|injector}
    builder.add_edge("checklist", "validator")  # Validate input type first
    
    builder.add_conditional_edges(
        "validator",
        validation_router,
        {
            "login_injector": "login_injector",  # LOGIN_FORM detected
            "bruteforce": "bruteforce",          # BRUTEFORCE_TARGET detected
            "injector": "injector"               # Regular input types
        }
    )
    
    # Login injector tries authentication, then routes based on result
    builder.add_conditional_edges(
        "login_injector",
        auth_router,
        {
            "bruteforce": "bruteforce",  # Need credential discovery
            "injector": "injector"       # Auth succeeded or skipped
        }
    )
    
    # Bruteforce tries to find credentials, then routes back or continues
    builder.add_conditional_edges(
        "bruteforce",
        bruteforce_router,
        {
            "login_injector": "login_injector",  # Found creds, try login again
            "injector": "injector"               # Failed, proceed without auth
        }
    )
    
    # ITERATIVE TESTING LOOP: injector -> observer -> {encoder|modifier|reporter|checklist}
    builder.add_edge("injector", "observer")   # Injector executes, observer analyzes
    
    # Observer decides next step based on results
    builder.add_conditional_edges(
        "observer",
        iterative_testing_loop,
        {
            "encoder": "encoder",        # Payload reflected, needs encoding (NEW)
            "modifier": "modifier",      # Need payload modification (legacy)
            "reporter": "reporter",      # Found vulnerability, report it
            "checklist": "checklist"     # Move to next checklist item (default)
        }
    )
    
    # Encoder sends back to injector with encoded payloads
    builder.add_edge("encoder", "injector")
    
    # Modifier sends back to injector with new payloads (legacy)
    builder.add_edge("modifier", "injector")
    
    # Reporter ends the workflow
    builder.add_edge("reporter", END)
    
    graph = builder.compile(checkpointer=checkpointer)
    return graph
