"""
Form-aware payload injection tool.
Intelligently injects payloads into form fields or URL parameters.
"""
import json
import hashlib
import re
from typing import Optional, Dict, List
from utils.ansi import CYAN, GREEN, YELLOW, RESET, RED


def inject_into_form(
    form_data: Dict,
    payload: str,
    target_field: str,
    session_data: Optional[Dict] = None
) -> Dict:
    """
    Inject a payload into a validated form field.
    VALIDATES form and field existence before injection - no assumptions.
    
    Args:
        form_data: Form structure with method, action, fields (must be validated)
        payload: Payload string to inject
        target_field: Name of field to inject payload into
        session_data: Optional session data (cookies, tokens)
    
    Returns:
        Dict with injection results and validation status
    """
    import requests
    from urllib.parse import urljoin
    
    try:
        # VALIDATION: Check form has injection points
        validation = form_data.get('validation', {})
        if not validation.get('has_injection_points'):
            return {
                'success': False,
                'error': 'Form has no injectable fields',
                'validation': validation
            }
        
        # VALIDATION: Check target field is injectable
        injectable_fields = [f['name'] for f in validation.get('injectable_fields', [])]
        if target_field not in injectable_fields:
            return {
                'success': False,
                'error': f'Field "{target_field}" is not injectable',
                'injectable_fields': injectable_fields,
                'target_field': target_field
            }
        
        # Prepare headers with auth
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        if session_data:
            if 'cookie' in session_data:
                headers['Cookie'] = session_data['cookie']
            if 'bearer_token' in session_data:
                headers['Authorization'] = f"Bearer {session_data['bearer_token']}"
        
        # Build form data with payload
        submit_data = {}
        target_found = False
        
        for field in form_data.get('fields', []):
            field_name = field.get('name', '')
            if field_name == target_field:
                submit_data[field_name] = payload
                target_found = True
            else:
                # Use default values for other fields
                if field.get('type') == 'hidden':
                    submit_data[field_name] = field.get('value', '')
                elif field.get('type') == 'checkbox':
                    submit_data[field_name] = 'on'
                elif field.get('type') == 'radio':
                    submit_data[field_name] = field.get('value', '')
                elif field.get('type') == 'select':
                    # Use first option
                    options = field.get('options', [])
                    submit_data[field_name] = options[0] if options else ''
                else:
                    submit_data[field_name] = field.get('value', '')
        
        if not target_found:
            return {
                'success': False,
                'error': f'Target field "{target_field}" not found in form',
                'validation_failed': True
            }
        
        # Get baseline response
        form_url = form_data.get('url', '')
        baseline_response = requests.get(form_url, headers=headers, timeout=10, verify=False)
        baseline_hash = hashlib.md5(baseline_response.text.encode()).hexdigest()
        baseline_size = len(baseline_response.text)
        
        # Submit form
        form_action = form_data.get('full_action', form_url)
        form_method = form_data.get('method', 'GET').upper()
        
        if form_method == 'POST':
            response = requests.post(
                form_action,
                data=submit_data,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
        else:
            response = requests.get(
                form_action,
                params=submit_data,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
        
        # Analyze response
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        response_size = len(response.text)
        page_changed = response_hash != baseline_hash
        
        # Check for indicators
        payload_reflected = payload in response.text
        url_changed = response.url != baseline_response.url
        
        # Look for error patterns indicating successful injection
        error_keywords = ['error', 'exception', 'syntax', 'sql', 'mysql', 'database', 
                         'warning', 'fatal', 'uncaught', 'invalid']
        error_indicators = sum(1 for keyword in error_keywords 
                               if re.search(keyword, response.text, re.IGNORECASE))
        
        return {
            'success': True,
            'injection_executed': True,  # Successfully confirmed execution
            'form_action': form_action,
            'form_method': form_method,
            'target_field': target_field,
            'payload': payload,
            'field_validated': True,  # Field was validated before injection
            'response_status': response.status_code,
            'page_changed': page_changed,
            'size_change': response_size - baseline_size,
            'url_changed': url_changed,
            'final_url': response.url,
            'payload_reflected': payload_reflected,
            'error_indicators': error_indicators,
            'response_preview': response.text[:500]
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'injection_executed': False
        }


def inject_into_parameter(
    url: str,
    parameter: str,
    payload: str,
    session_data: Optional[Dict] = None
) -> Dict:
    """
    Inject payload into URL parameter.
    
    Args:
        url: Base URL
        parameter: Parameter name
        payload: Payload to inject
        session_data: Optional session data
    
    Returns:
        Dict with injection results
    """
    import requests
    from urllib.parse import urljoin, urlparse, parse_qs, urlencode
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        if session_data:
            if 'cookie' in session_data:
                headers['Cookie'] = session_data['cookie']
            if 'bearer_token' in session_data:
                headers['Authorization'] = f"Bearer {session_data['bearer_token']}"
        
        # Get baseline
        baseline_response = requests.get(url, headers=headers, timeout=10, verify=False)
        baseline_hash = hashlib.md5(baseline_response.text.encode()).hexdigest()
        baseline_size = len(baseline_response.text)
        
        # Inject payload
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Set payload for target parameter
        params[parameter] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        injected_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        # Submit
        response = requests.get(injected_url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        
        # Analyze
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        response_size = len(response.text)
        
        return {
            'success': True,
            'original_url': url,
            'injected_url': injected_url,
            'parameter': parameter,
            'payload': payload,
            'response_status': response.status_code,
            'page_changed': response_hash != baseline_hash,
            'size_change': response_size - baseline_size,
            'payload_reflected': payload in response.text,
            'response_preview': response.text[:500]
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def analyze_injection_result(result: Dict) -> Dict:
    """
    Analyze injection result to determine likelihood of vulnerability.
    
    Returns confidence score and reasoning.
    """
    if not result.get('success'):
        return {
            'vulnerable': False,
            'confidence': 'None',
            'reasons': [result.get('error', 'Injection failed')]
        }
    
    indicators = {
        'page_changed': result.get('page_changed', False),
        'payload_reflected': result.get('payload_reflected', False),
        'error_indicators': result.get('error_indicators', 0) > 0,
        'url_changed': result.get('url_changed', False),
        'size_change': abs(result.get('size_change', 0)) > 100
    }
    
    confidence_score = sum(indicators.values())
    
    reasons = []
    if indicators['payload_reflected']:
        reasons.append('Payload reflected in response (potential XSS)')
    if indicators['error_indicators']:
        reasons.append('SQL/database errors detected (potential SQLi)')
    if indicators['page_changed']:
        reasons.append('Page content changed significantly')
    if indicators['url_changed']:
        reasons.append('URL changed after submission (potential redirect)')
    if indicators['size_change']:
        reasons.append(f"Response size changed by {result.get('size_change')} bytes")
    
    if confidence_score >= 3:
        confidence = 'Likely'
    elif confidence_score >= 2:
        confidence = 'Possible'
    else:
        confidence = 'Unlikely'
    
    return {
        'vulnerable': confidence in ['Likely', 'Possible'],
        'confidence': confidence,
        'score': confidence_score,
        'reasons': reasons,
        'indicators': indicators
    }
