"""
HTML form discovery and extraction from endpoints.
Finds <form> tags and extracts input fields for payload injection.
"""
import subprocess
import json
import re
from typing import Optional, List, Dict
from utils.ansi import CYAN, GREEN, YELLOW, RESET, RED


def validate_form_injectionpoints(form_data: Dict) -> Dict:
    """
    Validate that a form has actual injectable fields.
    
    Returns validation result with injectable field list.
    """
    injectable_fields = []
    
    for field in form_data.get('fields', []):
        field_name = field.get('name', '')
        field_type = field.get('type', 'text').lower()
        
        # Skip non-injectable field types
        if field_type in ['hidden', 'submit', 'button', 'file']:
            continue
        
        # Skip fields without names
        if not field_name or field_name.strip() == '':
            continue
        
        injectable_fields.append({
            'name': field_name,
            'type': field_type,
            'injectable': True
        })
    
    return {
        'injectable_fields': injectable_fields,
        'has_injection_points': len(injectable_fields) > 0,
        'total_fields': len(form_data.get('fields', [])),
        'injectable_count': len(injectable_fields)
    }


def discover_forms(url: str, session_data: Optional[dict] = None) -> str:
    """
    Fetch a URL and extract all HTML forms.
    ONLY returns forms with actual injectable fields - no assumptions.
    
    Args:
        url: Target URL to scan for forms
        session_data: Optional session data for authentication
    
    Returns:
        JSON with discovered forms and validated injection points
    """
    import requests
    from bs4 import BeautifulSoup
    
    try:
        print(f"{CYAN}[*] Fetching {url} to discover forms...{RESET}")
        
        # Prepare headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        # Add auth headers if provided
        if session_data and 'cookie' in session_data:
            headers['Cookie'] = session_data['cookie']
        elif session_data and 'bearer_token' in session_data:
            headers['Authorization'] = f"Bearer {session_data['bearer_token']}"
        
        # Fetch the page
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            verify=False  # Allow self-signed certs
        )
        
        if response.status_code != 200:
            return json.dumps({
                'success': False,
                'error': f'HTTP {response.status_code} received',
                'url': url,
                'status_code': response.status_code,
                'forms_found': 0,
                'forms': []
            })
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            print(f"{YELLOW}[*] No forms found at {url}{RESET}\n")
            return json.dumps({
                'success': True,
                'url': url,
                'forms_found': 0,
                'forms': [],
                'injectable_forms': 0
            })
        
        discovered_forms = []
        injectable_forms = []
        
        for idx, form in enumerate(forms):
            form_data = {
                'id': idx,
                'name': form.get('name', f'form_{idx}'),
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'url': url,  # Page where form was found (for validation whitelist)
                'fields': []
            }
            
            # Resolve action to full URL
            if form_data['action']:
                if form_data['action'].startswith('http'):
                    form_data['full_action'] = form_data['action']
                elif form_data['action'].startswith('/'):
                    # Absolute path
                    base_url = url.rsplit('/', 1)[0] if '/' in url.split('://', 1)[1] else url
                    form_data['full_action'] = base_url + form_data['action']
                else:
                    # Relative path
                    form_data['full_action'] = url.rsplit('/', 1)[0] + '/' + form_data['action']
            else:
                form_data['full_action'] = url
            
            # Extract input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                field = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                }
                
                # For select, get options
                if inp.name == 'select':
                    options = inp.find_all('option')
                    field['options'] = [opt.get_text() for opt in options]
                
                form_data['fields'].append(field)
            
            discovered_forms.append(form_data)
            
            # VALIDATE: Check if form has injectable fields
            validation = validate_form_injectionpoints(form_data)
            form_data['validation'] = validation
            
            # Only add if there are actual injectable fields
            if validation['has_injection_points']:
                injectable_forms.append(form_data)
        
        if injectable_forms:
            print(f"{GREEN}[+] Discovered {len(discovered_forms)} form(s), {len(injectable_forms)} with injectable fields{RESET}\n")
            
            # Print form summary
            for form in injectable_forms:
                print(f"    ✓ Form: {form['name']} | Method: {form['method']} | Action: {form['full_action']}")
                injection_summary = form['validation']
                print(f"      Injectable fields: {injection_summary['injectable_count']}/{injection_summary['total_fields']}")
                for field in form['validation']['injectable_fields'][:3]:
                    print(f"        - {field['name']} ({field['type']})")
                if len(form['validation']['injectable_fields']) > 3:
                    print(f"        ... and {len(form['validation']['injectable_fields']) - 3} more")
            print()
        else:
            print(f"{YELLOW}[!] {len(discovered_forms)} form(s) found but NONE have injectable fields{RESET}\n")
        
        return json.dumps({
            'success': True,
            'url': url,
            'forms_found': len(discovered_forms),
            'injectable_forms': len(injectable_forms),
            'forms': injectable_forms  # ONLY return forms with injection points
        }, indent=2)
    
    except requests.exceptions.ConnectionError:
        return json.dumps({
            'success': False,
            'error': f'Connection error to {url}',
            'url': url
        })
    except ImportError:
        return json.dumps({
            'success': False,
            'error': 'BeautifulSoup4 not installed. Install with: pip install beautifulsoup4 requests'
        })
    except Exception as e:
        return json.dumps({
            'success': False,
            'error': str(e),
            'url': url
        })


def test_form_injection(
    form_url: str,
    form_data: Dict,
    payload: str,
    target_field: str,
    session_data: Optional[dict] = None
) -> str:
    """
    Inject payload into a validated form field and check if form/page changes.
    VALIDATES that form has injectable fields before any injection.
    
    Args:
        form_url: URL where form is located
        form_data: Form data dict with fields (must be validated)
        payload: Payload to inject
        target_field: Name of field to inject into
        session_data: Optional session data
    
    Returns:
        JSON with injection result and validation status
    """
    import requests
    import hashlib
    
    try:
        # VALIDATION: Check form has injection points
        validation = form_data.get('validation', {})
        if not validation.get('has_injection_points'):
            return json.dumps({
                'success': False,
                'error': 'Form has no injectable fields',
                'validation_failed': True,
                'validation': validation
            })
        
        # VALIDATION: Check target field is injectable
        injectable_field_names = [f['name'] for f in validation.get('injectable_fields', [])]
        if target_field not in injectable_field_names:
            return json.dumps({
                'success': False,
                'error': f'Field "{target_field}" is not injectable',
                'validation_failed': True,
                'injectable_fields': injectable_field_names,
                'target_field': target_field
            })
        
        # Get baseline page
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        if session_data and 'cookie' in session_data:
            headers['Cookie'] = session_data['cookie']
        elif session_data and 'bearer_token' in session_data:
            headers['Authorization'] = f"Bearer {session_data['bearer_token']}"
        
        # Get baseline hash
        response_baseline = requests.get(form_url, headers=headers, timeout=10, verify=False)
        baseline_hash = hashlib.md5(response_baseline.text.encode()).hexdigest()
        baseline_len = len(response_baseline.text)
        
        # Prepare form data with payload
        test_data = {}
        for field in form_data.get('fields', []):
            if field['name'] == target_field:
                test_data[field['name']] = payload
            else:
                test_data[field['name']] = field.get('value', '')
        
        # Submit form
        form_action = form_data.get('full_action', form_url)
        form_method = form_data.get('method', 'GET')
        
        print(f"{CYAN}[*] Injecting payload into validated field '{target_field}'${RESET}")
        print(f"{CYAN}[*] Form Action: {form_action} | Method: {form_method}${RESET}")
        print(f"{CYAN}[*] Payload: {payload[:50]}...${RESET}\n")
        
        if form_method == 'POST':
            response = requests.post(
                form_action,
                data=test_data,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
        else:
            response = requests.get(
                form_action,
                params=test_data,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
        
        # Analyze response
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        response_len = len(response.text)
        page_changed = response_hash != baseline_hash
        size_diff = response_len - baseline_len
        
        # Check for payload reflection
        payload_reflected = payload in response.text
        
        # Check for error messages
        error_patterns = [
            r'error', r'exception', r'syntax', r'mysql', r'database',
            r'warning', r'fatal', r'invalid', r'not found'
        ]
        errors_found = sum(1 for pattern in error_patterns 
                          if re.search(pattern, response.text, re.IGNORECASE))
        
        result = {
            'success': True,
            'field_validated': True,  # Field was validated before injection
            'form_action': form_action,
            'form_method': form_method,
            'target_field': target_field,
            'payload': payload,
            'injection_performed': True,
            'response_status': response.status_code,
            'page_changed': page_changed,
            'size_diff': size_diff,
            'payload_reflected': payload_reflected,
            'error_count': errors_found,
            'changes': {
                'baseline_hash': baseline_hash,
                'baseline_size': baseline_len,
                'response_hash': response_hash,
                'response_size': response_len
            }
        }
        
        # Print results
        if page_changed:
            print(f"{GREEN}[+] Page CHANGED after injection!${RESET}")
            print(f"    Status: {response.status_code} | Size diff: {size_diff:+d} bytes")
        if payload_reflected:
            print(f"{YELLOW}[!] Payload REFLECTED in response (possible XSS)${RESET}")
        if errors_found > 0:
            print(f"{YELLOW}[!] {errors_found} error patterns found (possible SQLi/injection)${RESET}\n")
        
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return json.dumps({
            'success': False,
            'error': str(e),
            'form_action': form_url,
            'injection_performed': False
        })
