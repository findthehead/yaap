"""
Authentication utilities for YAAP
Handles session data propagation across tools
"""
from typing import Dict, Any, Optional


def build_auth_headers(session_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Build curl authentication headers from session data
    Returns string of curl -H flags
    
    Args:
        session_data: Dict with 'cookie', 'bearer_token', 'session', etc.
    
    Returns:
        String like: '-H "Cookie: sessionid=abc" -H "Authorization: Bearer xyz"'
    """
    if not session_data:
        return ''
    
    headers = []
    
    # Add cookie header
    if session_data.get('cookie'):
        cookie_value = session_data['cookie']
        # If it's from Netscape cookie jar format, extract the actual cookie
        if '\t' in cookie_value and '\n' in cookie_value:
            # Parse Netscape format
            cookie_pairs = []
            for line in cookie_value.strip().split('\n'):
                if not line.startswith('#') and line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        cookie_pairs.append(f"{parts[5]}={parts[6]}")
            if cookie_pairs:
                headers.append(f'-H "Cookie: {"; ".join(cookie_pairs)}"')
        else:
            headers.append(f'-H "Cookie: {cookie_value}"')
    
    # Add bearer token header
    if session_data.get('bearer_token'):
        headers.append(f'-H "Authorization: Bearer {session_data["bearer_token"]}"')
    
    # Add JWT token header
    if session_data.get('jwt_token'):
        headers.append(f'-H "Authorization: Bearer {session_data["jwt_token"]}"')
    
    # Add custom auth header
    if session_data.get('auth_header'):
        headers.append(f'-H "{session_data["auth_header"]}"')
    
    return ' '.join(headers)


def inject_auth_into_curl(cmd: str, session_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Inject authentication headers into curl command
    
    Args:
        cmd: Original curl command
        session_data: Authentication data
    
    Returns:
        Modified curl command with auth headers
    """
    if not session_data:
        return cmd
    
    auth_headers = build_auth_headers(session_data)
    if not auth_headers:
        return cmd
    
    # Insert auth headers after 'curl' command
    if cmd.strip().startswith('curl'):
        # Find the position after 'curl' and any initial flags
        parts = cmd.split(None, 1)  # Split on first whitespace
        if len(parts) == 2:
            return f"{parts[0]} {auth_headers} {parts[1]}"
        else:
            # Just 'curl' with no args
            return f"{parts[0]} {auth_headers}"
    
    return cmd


def preserve_session_in_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Utility to ensure session_data persists through state transitions
    """
    if state.get('auth_success') and state.get('session_data'):
        # Ensure session_data is included in routing decision
        state['authenticated_context'] = {
            'authenticated': True,
            'session_data': state['session_data'],
            'auth_method': state.get('auth_method', 'unknown')
        }
    return state
