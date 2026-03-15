from typing import List, Tuple, Dict, Any
import time
import sys
import random

from langchain_core.messages import ToolMessage
from utils.ansi import CYAN, YELLOW, GREEN, MAGENTA, RESET, BOLD, GRAY, RED


def _type_slowly(text: str, delay: float = 0.01):
    """Type text character by character"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def _tool_map(tools: List[Any]) -> Dict[str, Any]:
    m = {}
    for t in tools or []:
        try:
            name = getattr(t, "name", None) or getattr(t, "__name__", None)
            if name:
                m[name] = t
        except Exception:
            pass
    return m


def _invoke_with_retry(bound: Any, history: List[Any], max_retries: int = 5) -> Any:
    """Invoke model with exponential backoff retry for rate limits and overload errors"""
    for attempt in range(max_retries):
        try:
            return bound.invoke(history)
        except Exception as e:
            error_str = str(e)
            # Check for overload (529) or rate limit (429) errors
            if '529' in error_str or '429' in error_str or 'overload' in error_str.lower() or 'rate limit' in error_str.lower():
                if attempt < max_retries - 1:
                    # Exponential backoff: 2, 4, 8, 16, 32 seconds + jitter
                    wait_time = (2 ** attempt) + random.uniform(0, 2)
                    print(f"\n{YELLOW}[!] API overloaded (attempt {attempt + 1}/{max_retries}). Retrying in {wait_time:.1f}s...{RESET}", flush=True)
                    time.sleep(wait_time)
                else:
                    print(f"\n{RED}✗ API still overloaded after {max_retries} attempts{RESET}", flush=True)
                    raise
            else:
                # Not a rate limit/overload error, raise immediately
                raise
    raise Exception("Max retries exceeded")


def run_tool_loop(model: Any, tools: List[Any], messages: List[Any], max_iters: int = 3) -> Tuple[Any, List[str]]:
    """Call a tools-bound model and execute tool calls until completion or max_iters.

    Returns (final_ai_message, collected_tool_outputs [str]).
    """
    collected: List[str] = []
    tmap = _tool_map(tools)
    bound = model.bind_tools(tools) if hasattr(model, "bind_tools") else model
    
    # Clean history - ensure we only have SystemMessage and HumanMessage at start
    # Remove any stray ToolMessage objects that might be in the initial messages
    history = []
    for msg in messages:
        # Only include SystemMessage, HumanMessage, and AIMessage (not ToolMessage)
        if not isinstance(msg, ToolMessage):
            history.append(msg)

    for iteration in range(max_iters):
        # Show thinking before model call
        if iteration > 0:
            time.sleep(0.4)
            _type_slowly(f"\n{CYAN}[*] Analyzing results and planning next action...{RESET}", delay=0.012)
            time.sleep(0.5)
        
        # Use retry logic for API calls
        ai = _invoke_with_retry(bound, history, max_retries=5)
        
        # Show LLM's textual reasoning if present (before tool calls)
        try:
            content = getattr(ai, 'content', '')
            if content and isinstance(content, str) and len(content.strip()) > 0:
                # Only show if it's actual reasoning, not just tool calls
                if not content.startswith('[') and 'tool_calls' not in content.lower():
                    time.sleep(0.3)
                    print(f"\n{CYAN}[*] LLM Reasoning:{RESET}", flush=True)
                    time.sleep(0.2)
                    # Show first 250 chars of reasoning with typing effect
                    preview = content[:250] + ('...' if len(content) > 250 else '')
                    for line in preview.split('\n')[:3]:  # Max 3 lines
                        if line.strip():
                            _type_slowly(f"{GRAY}   {line.strip()}{RESET}", delay=0.008)
                    time.sleep(0.4)
        except Exception:
            pass
        
        # Different providers attach tool calls differently; try common shapes
        calls = []
        try:
            calls = getattr(ai, "tool_calls", None) or []
        except Exception:
            calls = []
        
        if not calls:
            # No tool calls, we're done
            return ai, collected
        
        # Validate that AI message has proper tool_calls structure
        # This is critical for Anthropic's API
        if not hasattr(ai, 'tool_calls') or not ai.tool_calls:
            # If no proper tool_calls, don't try to execute
            return ai, collected
        
        # Show what tools LLM decided to use
        time.sleep(0.3)
        _type_slowly(f"\n{YELLOW}[>] Executing tools...{RESET}", delay=0.012)
        time.sleep(0.3)
        
        for idx, c in enumerate(calls, 1):
            try:
                name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
                args = c.get("args") if isinstance(c, dict) else getattr(c, "args", {})
                
                # Show tool decision with typing effect
                time.sleep(0.2)
                _type_slowly(f"{GREEN}  {idx}. {BOLD}{name}{RESET}", delay=0.01)
                time.sleep(0.15)
                
                # Show reasoning for tool choice
                if isinstance(args, dict):
                    # Extract meaningful parameters to show
                    key_params = []
                    if 'url' in args:
                        url_display = args['url'][:60] + ('...' if len(str(args['url'])) > 60 else '')
                        key_params.append(f"Target: {url_display}")
                    if 'cmd' in args:
                        cmd_display = str(args['cmd'])[:60] + ('...' if len(str(args['cmd'])) > 60 else '')
                        key_params.append(f"Command: {cmd_display}")
                    if 'query' in args:
                        query_display = str(args['query'])[:60] + ('...' if len(str(args['query'])) > 60 else '')
                        key_params.append(f"Query: {query_display}")
                    if 'max_pages' in args:
                        key_params.append(f"Pages: {args['max_pages']}")
                    
                    for param in key_params[:2]:  # Max 2 params
                        time.sleep(0.1)
                        print(f"{GRAY}     • {param}{RESET}", flush=True)
                
                time.sleep(0.2)
                print(f"{GRAY}     [~] Running...{RESET}", flush=True)
                
            except Exception:
                pass
        
        # Append the AI message containing tool_use before sending tool_result
        # This is REQUIRED by Anthropic's API - tool_result must follow tool_use
        history.append(ai)
        
        # Execute each call (fast, no delays here - tools run at full speed)
        for c in calls:
            try:
                name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
                args = c.get("args") if isinstance(c, dict) else getattr(c, "args", {})
                
                # Extract tool_call_id properly - CRITICAL for Anthropic
                call_id = None
                if isinstance(c, dict):
                    call_id = c.get("id")
                else:
                    call_id = getattr(c, "id", None)
                
                # If still no ID, generate one based on name
                if not call_id:
                    call_id = f"{name}_call"
                
                tool = tmap.get(name)
                if tool is None:
                    out = f"Tool '{name}' not available"
                else:
                    out = tool.invoke(args if isinstance(args, dict) else {})
                collected.append(str(out))
                
                # Append ToolMessage with matching tool_call_id
                history.append(ToolMessage(content=str(out), tool_call_id=str(call_id)))
                
            except Exception as e:
                # Even on error, we need a valid tool_call_id
                call_id = c.get("id") if isinstance(c, dict) else getattr(c, "id", None)
                if not call_id:
                    call_id = f"{name}_error"
                history.append(ToolMessage(content=f"Tool execution error: {e}", tool_call_id=str(call_id)))
        
        # Show completion
        time.sleep(0.2)
        print(f"{GREEN}     ✓ Tools completed{RESET}", flush=True)
        time.sleep(0.3)
        
        # Continue loop; the tool results are in history now
    return ai, collected
