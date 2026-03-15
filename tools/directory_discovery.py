"""
Directory and endpoint discovery using feroxbuster.
Identifies real endpoints before attempting injection attacks.
"""
from langchain.tools import tool
import subprocess
import json
import re
import os
import shutil
from typing import Optional
from utils.ansi import CYAN, GREEN, YELLOW, RESET, RED
from tools.tool_setup import (
    _find_feroxbuster_binary,
    _find_katana_binary,
    _find_dirb_binary,
    _install_katana,
    _install_dirb,
    _ensure_seclists_git_clone,
    setup_wordlist,
    _ensure_fallback_wordlist,
    auto_install_feroxbuster,
)


def _parse_katana_output(output_file: str, stdout_text: str = '') -> list:
    """Parse katana output into ferox-compatible endpoint objects."""
    endpoints = []
    seen = set()

    def add_url(candidate: str):
        if not candidate:
            return
        url = candidate.strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            return
        if url in seen:
            return
        seen.add(url)
        endpoints.append({
            'url': url,
            'status': 200,
            'content_length': 0,
            'found': True
        })

    if os.path.exists(output_file):
        with open(output_file, 'r') as handle:
            for line in handle:
                add_url(line)

    if not endpoints and stdout_text:
        for line in stdout_text.splitlines():
            add_url(line)

    return endpoints


def discover_directories_katana(
    url: str,
    timeout: int = 30,
    session_data: Optional[dict] = None
) -> str:
    """Discover endpoints using katana as fallback when feroxbuster is unavailable/fails."""
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'

    katana_path = _find_katana_binary() or _install_katana()
    if not katana_path:
        return json.dumps({
            'success': False,
            'error': 'katana not found and auto-installation failed'
        })

    output_file = '/tmp/katana_output.txt'
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except Exception:
            pass

    cmd = [
        katana_path,
        '-u', url,
        '-o', output_file,
        '-silent'
    ]

    # Add optional header support if katana variant has it
    if session_data and 'cookie' in session_data:
        cmd.extend(['-H', f"Cookie: {session_data['cookie']}"])
    elif session_data and 'bearer_token' in session_data:
        cmd.extend(['-H', f"Authorization: Bearer {session_data['bearer_token']}"])

    try:
        print(f"{CYAN}[*] Starting katana fallback discovery on {url}...{RESET}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 120
        )

        if result.returncode != 0:
            return json.dumps({
                'success': False,
                'error': f'katana failed with code {result.returncode}',
                'stderr': (result.stderr or '')[:500]
            })

        endpoints = _parse_katana_output(output_file, result.stdout or '')
        print(f"{GREEN}[+] katana discovered {len(endpoints)} endpoints{RESET}\n")
        return json.dumps({
            'success': True,
            'target': url,
            'endpoints_discovered': len(endpoints),
            'endpoints': endpoints,
            'discovery_tool': 'katana'
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({
            'success': False,
            'error': f'katana timed out after {timeout + 120} seconds'
        })
    except Exception as error:
        return json.dumps({
            'success': False,
            'error': str(error)
        })


def discover_directories_dirb(
    url: str,
    wordlist: Optional[str] = None,
    timeout: int = 30,
    session_data: Optional[dict] = None
) -> str:
    """Discover endpoints using dirb as last resort when feroxbuster+katana fail."""
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'

    dirb_path = _find_dirb_binary() or _install_dirb()
    if not dirb_path:
        return json.dumps({
            'success': False,
            'error': 'dirb not found and auto-installation failed'
        })

    # Prefer git-cloned SecLists (requested), then user-provided/system wordlists, then local fallback.
    seclists_wordlist = _ensure_seclists_git_clone()
    wordlist_path = seclists_wordlist or (wordlist if wordlist and os.path.exists(wordlist) else setup_wordlist())
    if not wordlist_path:
        wordlist_path = _ensure_fallback_wordlist()

    output_file = '/tmp/dirb_output.txt'
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except Exception:
            pass

    cmd = [dirb_path, url, wordlist_path, '-o', output_file]

    try:
        print(f"{CYAN}[*] Starting dirb last-resort discovery on {url}...{RESET}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 180
        )

        # dirb can still produce useful output even with non-zero code; parse anyway
        endpoints = []
        seen = set()

        text_blob = ''
        if os.path.exists(output_file):
            with open(output_file, 'r') as handle:
                text_blob += handle.read() + '\n'
        text_blob += (result.stdout or '') + '\n' + (result.stderr or '')

        for line in text_blob.splitlines():
            url_match = re.search(r'https?://[^\s\)]+', line)
            if not url_match:
                continue

            found_url = url_match.group(0).strip()
            if found_url in seen:
                continue

            status_match = re.search(r'CODE:(\d{3})', line)
            status_code = int(status_match.group(1)) if status_match else 200

            seen.add(found_url)
            endpoints.append({
                'url': found_url,
                'status': status_code,
                'content_length': 0,
                'found': status_code < 400
            })

        print(f"{GREEN}[+] dirb discovered {len(endpoints)} endpoints{RESET}\n")
        return json.dumps({
            'success': True,
            'target': url,
            'endpoints_discovered': len(endpoints),
            'endpoints': endpoints,
            'discovery_tool': 'dirb'
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({
            'success': False,
            'error': f'dirb timed out after {timeout + 180} seconds'
        })
    except Exception as error:
        return json.dumps({
            'success': False,
            'error': str(error)
        })


def _detect_feroxbuster_flags(ferox_path: str) -> dict:
    """Detect supported CLI flags for feroxbuster variant in use."""
    help_text = ""
    try:
        help_result = subprocess.run(
            [ferox_path, '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        help_text = f"{help_result.stdout}\n{help_result.stderr}"
    except Exception:
        pass

    def has(flag: str) -> bool:
        return flag in help_text

    return {
        'url': '--url' if has('--url') else '-u',
        'threads': '--threads' if has('--threads') else '-t',
        'output': '--output' if has('--output') else '-o',
        'wordlist': '--wordlist' if has('--wordlist') else '-w',
        'header': '--headers' if has('--headers') else '-H',
        'json': '--json' if has('--json') else None,
        'timeout': '--timeout' if has('--timeout') else None,
        'status_codes': '--status-codes' if has('--status-codes') else None,
        'insecure': '--insecure' if has('--insecure') else ('-k' if has('-k') else None),
        'silent': '--no-banner' if has('--no-banner') else ('--no-state' if has('--no-state') else None),
    }


def _build_feroxbuster_command(
    ferox_path: str,
    target_url: str,
    output_file: str,
    threads: int,
    timeout: int,
    wordlist_path: Optional[str],
    session_data: Optional[dict],
    conservative: bool = False
) -> list:
    """Build command compatible with installed feroxbuster variant."""
    flags = _detect_feroxbuster_flags(ferox_path)

    cmd = [
        ferox_path,
        flags['url'], target_url,
        flags['threads'], str(threads),
        flags['output'], output_file,
    ]

    if flags['json']:
        cmd.append(flags['json'])

    if flags['silent']:
        cmd.append(flags['silent'])

    # Always provide explicit wordlist when available; some ferox variants fail
    # if their compiled default list path does not exist on host.
    if wordlist_path:
        cmd.extend([flags['wordlist'], wordlist_path])

    # Preserve auth headers in both modes
    if session_data and 'cookie' in session_data:
        cmd.extend([flags['header'], f"Cookie: {session_data['cookie']}"])
    elif session_data and 'bearer_token' in session_data:
        cmd.extend([flags['header'], f"Authorization: Bearer {session_data['bearer_token']}"])

    if not conservative:
        if flags['timeout']:
            cmd.extend([flags['timeout'], str(timeout)])

        if flags['status_codes']:
            cmd.extend([flags['status_codes'], '200,204,301,302,307,308,401,403'])

        if flags['insecure']:
            cmd.append(flags['insecure'])

    return cmd


def _parse_feroxbuster_output(output_file: str) -> list:
    """Parse feroxbuster output from either JSON object, JSON list, or NDJSON lines."""
    allowed = {200, 201, 204, 301, 302, 307, 308, 401, 403}
    discovered = []

    if not os.path.exists(output_file):
        return discovered

    def add_record(item: dict):
        if not isinstance(item, dict):
            return

        # Handle both aggregate and event-style outputs
        if 'results' in item and isinstance(item.get('results'), list):
            for result_item in item['results']:
                add_record(result_item)
            return

        status = item.get('status')
        if status is None:
            status = item.get('status_code')

        url = item.get('url') or item.get('target') or item.get('path')
        if isinstance(url, dict):
            url = url.get('url')

        if status in allowed and isinstance(url, str) and url:
            content_length = (
                item.get('content_length')
                or item.get('contentLength')
                or item.get('content-length')
                or item.get('size')
                or 0
            )
            discovered.append({
                'url': url,
                'status': status,
                'content_length': content_length,
                'found': status < 400
            })

    with open(output_file, 'r') as handle:
        raw = handle.read().strip()

    if not raw:
        return discovered

    # Try full JSON first
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict):
            add_record(payload)
        elif isinstance(payload, list):
            for element in payload:
                add_record(element)
        return discovered
    except json.JSONDecodeError:
        pass

    # Fallback: NDJSON line-by-line
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            add_record(json.loads(line))
        except json.JSONDecodeError:
            continue

    # De-duplicate by URL+status
    deduped = []
    seen = set()
    for endpoint in discovered:
        key = (endpoint['url'], endpoint['status'])
        if key not in seen:
            seen.add(key)
            deduped.append(endpoint)
    return deduped


def discover_directories_feroxbuster(
    url: str,
    wordlist: Optional[str] = None,
    threads: int = 50,
    timeout: int = 30,
    session_data: Optional[dict] = None
) -> str:
    """
    Discover directories and endpoints using feroxbuster.
    Returns discovered URLs to identify actual injection points.
    
    Args:
        url: Target URL (e.g., http://example.com)
        wordlist: Custom wordlist path (uses default if not provided)
        threads: Number of concurrent threads (default: 50)
        timeout: Request timeout in seconds (default: 30)
        session_data: Optional session data for authenticated discovery
    
    Returns:
        JSON list of discovered endpoints with status codes and sizes
    """
    import shutil
    import os
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    def _try_tool_fallback(reason: str) -> Optional[str]:
        print(f"{YELLOW}[*] Triggering fallback discovery because: {reason}{RESET}")

        katana_result = discover_directories_katana(
            url=url,
            timeout=timeout,
            session_data=session_data if session_data else None
        )
        try:
            katana_data = json.loads(katana_result)
        except json.JSONDecodeError:
            return None

        if katana_data.get('success'):
            print(f"{GREEN}[+] katana fallback succeeded{RESET}\n")
            return katana_result

        print(f"{YELLOW}[*] katana fallback failed, trying dirb last resort...{RESET}")
        dirb_result = discover_directories_dirb(
            url=url,
            timeout=timeout,
            session_data=session_data if session_data else None
        )
        try:
            dirb_data = json.loads(dirb_result)
        except json.JSONDecodeError:
            return None

        if dirb_data.get('success'):
            print(f"{GREEN}[+] dirb last-resort fallback succeeded{RESET}\n")
            return dirb_result

        return None

    # Check if feroxbuster is installed
    ferox_path = _find_feroxbuster_binary()
    if not ferox_path:
        print(f"{RED}[!] feroxbuster not found in PATH{RESET}")
        print(f"{YELLOW}[*] Attempting auto-installation...{RESET}\n")
        
        ferox_path = auto_install_feroxbuster()
        
        # CIRCUIT BREAKER: If feroxbuster installation fails, stop execution immediately
        if not ferox_path:
            tool_fallback = _try_tool_fallback('feroxbuster installation failed')
            if tool_fallback:
                return tool_fallback

            error_msg = "❌ CIRCUIT BREAKER ACTIVATED: feroxbuster installation failed"
            print(f"\n{RED}[!] {error_msg}{RESET}\n")
            print(f"{RED}[!] Cannot proceed without endpoint discovery - assessment HALTED{RESET}")
            print(f"{YELLOW}[*] feroxbuster is REQUIRED for endpoint discovery{RESET}\n")
            print(f"{CYAN}[*] Manual installation options:{RESET}")
            print(f"    macOS:     brew install feroxbuster")
            print(f"    Linux:     cargo install feroxbuster (after installing Rust)")
            print(f"    Linux:     CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest")
            print(f"    Linux:     sudo apt-get install -y dirb")
            print(f"    Wordlist:  git clone https://github.com/danielmiessler/SecLists.git /tmp/SecLists")
            print(f"    Linux alt: download prebuilt from https://github.com/epi052/feroxbuster/releases")
            print(f"    Manual:    https://github.com/epi052/feroxbuster\n")
            raise Exception(error_msg)
    
    # Setup wordlist path
    wordlist_path = wordlist if wordlist and os.path.exists(wordlist) else setup_wordlist()
    if not wordlist_path:
        wordlist_path = _ensure_fallback_wordlist()
        print(f"{YELLOW}[*] Using local fallback wordlist: {wordlist_path}{RESET}")
    
    output_file = '/tmp/ferox_output.json'
    cmd = _build_feroxbuster_command(
        ferox_path=ferox_path,
        target_url=url,
        output_file=output_file,
        threads=threads,
        timeout=timeout,
        wordlist_path=wordlist_path,
        session_data=session_data,
        conservative=False
    )
    
    try:
        print(f"{CYAN}[*] Starting feroxbuster discovery on {url}...{RESET}")
        print(f"{CYAN}[*] Threads: {threads}, Timeout: {timeout}s" + (f", Wordlist: {wordlist_path}" if wordlist_path else " (using default)") + f"{RESET}\n")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 120
        )
        
        if result.returncode == 0:
            # Parse feroxbuster JSON output
            if os.path.exists(output_file):
                try:
                    discovered = _parse_feroxbuster_output(output_file)
                    
                    print(f"{GREEN}[+] Discovered {len(discovered)} endpoints{RESET}\n")
                    
                    # Print discovered URLs
                    for ep in discovered[:5]:
                        print(f"    {ep['url']} ({ep['status']})")
                    if len(discovered) > 5:
                        print(f"    ... and {len(discovered) - 5} more\n")
                    
                    return json.dumps({
                        'success': True,
                        'target': url,
                        'endpoints_discovered': len(discovered),
                        'endpoints': discovered
                    }, indent=2)
                except json.JSONDecodeError as e:
                    print(f"{RED}[!] Failed to parse feroxbuster JSON output{RESET}")
                    return json.dumps({
                        'success': False,
                        'error': 'Failed to parse feroxbuster output',
                        'json_error': str(e)
                    })
            else:
                print(f"{RED}[!] feroxbuster output file not found{RESET}")

                # Some variants may return success but skip output when wordlist path is invalid.
                # Retry once with an explicit local fallback wordlist.
                stderr_text = result.stderr or ''
                if 'Could not open' in stderr_text or 'wordlist' in stderr_text.lower():
                    print(f"{YELLOW}[*] Detected wordlist/open error; retrying with explicit fallback wordlist...{RESET}")
                    wordlist_path = _ensure_fallback_wordlist()
                    retry_cmd = _build_feroxbuster_command(
                        ferox_path=ferox_path,
                        target_url=url,
                        output_file=output_file,
                        threads=threads,
                        timeout=timeout,
                        wordlist_path=wordlist_path,
                        session_data=session_data,
                        conservative=True
                    )
                    retry = subprocess.run(
                        retry_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout + 120
                    )

                    if retry.returncode == 0 and os.path.exists(output_file):
                        discovered = _parse_feroxbuster_output(output_file)
                        print(f"{GREEN}[+] Fallback-wordlist retry succeeded; discovered {len(discovered)} endpoints{RESET}\n")
                        return json.dumps({
                            'success': True,
                            'target': url,
                            'endpoints_discovered': len(discovered),
                            'endpoints': discovered
                        }, indent=2)

                tool_fallback = _try_tool_fallback('feroxbuster completed without output file')
                if tool_fallback:
                    return tool_fallback

                return json.dumps({
                    'success': False,
                    'error': 'feroxbuster completed but no output file found',
                    'stdout': result.stdout[:200],
                    'stderr': result.stderr[:200]
                })
        else:
            print(f"{RED}[!] feroxbuster failed with code {result.returncode}{RESET}")
            if result.stderr:
                print(f"{RED}    Error: {result.stderr[:300]}{RESET}")

            # Retry with conservative command if this is a CLI argument mismatch
            stderr_text = result.stderr or ''
            if 'unexpected argument' in stderr_text or 'Usage:' in stderr_text:
                print(f"{YELLOW}[*] Detected CLI variant mismatch, retrying with conservative flags...{RESET}")
                cmd = _build_feroxbuster_command(
                    ferox_path=ferox_path,
                    target_url=url,
                    output_file=output_file,
                    threads=threads,
                    timeout=timeout,
                    wordlist_path=wordlist_path,
                    session_data=session_data,
                    conservative=True
                )
                retry = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 120
                )

                if retry.returncode == 0 and os.path.exists(output_file):
                    discovered = _parse_feroxbuster_output(output_file)
                    print(f"{GREEN}[+] Conservative retry succeeded; discovered {len(discovered)} endpoints{RESET}\n")
                    return json.dumps({
                        'success': True,
                        'target': url,
                        'endpoints_discovered': len(discovered),
                        'endpoints': discovered
                    }, indent=2)

            tool_fallback = _try_tool_fallback(f'feroxbuster failed with code {result.returncode}')
            if tool_fallback:
                return tool_fallback

            return json.dumps({
                'success': False,
                'error': f'feroxbuster failed with code {result.returncode}',
                'stderr': result.stderr[:500]
            })
    
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] feroxbuster timed out after {timeout + 120}s{RESET}")
        return json.dumps({
            'success': False,
            'error': f'feroxbuster timed out after {timeout + 120} seconds',
            'tip': 'Try increasing timeout or using fewer threads'
        })
    except Exception as e:
        print(f"{RED}[!] Exception: {str(e)}{RESET}")
        return json.dumps({
            'success': False,
            'error': str(e)
        })


def identify_injection_points(
    discovered_endpoints: str,
    base_url: str
) -> str:
    """
    Analyze discovered endpoints to identify which ones have injection parameters.
    Returns URLs with actual injection points where payloads can be tested.
    
    Args:
        discovered_endpoints: JSON string of discovered endpoints from feroxbuster
        base_url: Base URL for filtering relevant endpoints
    
    Returns:
        JSON list of endpoints with injection points identified
    """
    try:
        endpoints_data = json.loads(discovered_endpoints)
    except json.JSONDecodeError:
        return json.dumps({
            'success': False,
            'error': 'Invalid JSON input'
        })
    
    injection_candidates = []
    
    # Common injection-prone endpoints
    injection_patterns = [
        r'.*\.php.*',  # PHP files
        r'.*/search.*',
        r'.*/query.*',
        r'.*/filter.*',
        r'.*/category.*',
        r'.*/product.*',
        r'.*/user.*',
        r'.*/page.*',
        r'.*/id=.*',
        r'.*/.*\?.*',  # URLs with query parameters
    ]
    
    for endpoint in endpoints_data.get('endpoints', []):
        url = endpoint.get('url', '')
        status = endpoint.get('status')
        
        # Skip client/server errors, focus on 200, 301, 302, 401, 403
        if status not in [200, 201, 204, 301, 302, 307, 308, 401, 403]:
            continue
        
        # Check if endpoint matches injection-prone patterns
        if any(re.match(pattern, url, re.IGNORECASE) for pattern in injection_patterns):
            injection_candidates.append({
                'endpoint': url,
                'status': status,
                'injection_likelihood': 'high' if '?' in url else 'medium',
                'suggested_parameters': extract_parameters_from_url(url)
            })
    
    print(f"{GREEN}[+] Identified {len(injection_candidates)} potential injection points{RESET}")
    
    return json.dumps({
        'success': True,
        'base_url': base_url,
        'injection_candidates': injection_candidates,
        'total_candidates': len(injection_candidates)
    }, indent=2)


def extract_parameters_from_url(url: str) -> list:
    """Extract query parameters from URL."""
    if '?' not in url:
        return []
    
    query_string = url.split('?', 1)[1]
    params = []
    
    for param in query_string.split('&'):
        if '=' in param:
            key = param.split('=')[0]
            params.append(key)
        else:
            params.append(param)
    
    return list(set(params))  # Remove duplicates
