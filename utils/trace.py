"""
Consolidated JSON trace logging for all tool outputs, errors, warnings, and LLM interactions.
Single trace.json file per session with structured key-value pairs.
"""
import os
import json
from datetime import datetime
from threading import Lock

# Global trace data structure
_trace_lock = Lock()
_trace_data = {
    "meta": {},
    "agents": [],
    "tools": [],
    "errors": [],
    "warnings": [],
    "llm_calls": []
}
_trace_file = None
_current_host = None


def init_trace(host: str, test_mode: str = "recon"):
    """Initialize JSON trace file for this session"""
    global _trace_file, _current_host, _trace_data
    _current_host = host
    
    # Clean host for filename
    host_clean = host.replace('://', '_').replace('/', '_').replace(':', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create public directory if it doesn't exist
    os.makedirs('public', exist_ok=True)
    
    trace_path = os.path.join('public', 'trace.json')
    _trace_file = trace_path
    
    # Initialize trace data
    _trace_data = {
        "meta": {
            "target": host,
            "mode": test_mode,
            "started": datetime.now().isoformat(),
            "version": "2.0",
            "session_id": timestamp
        },
        "agents": [],
        "tools": [],
        "errors": [],
        "warnings": [],
        "llm_calls": []
    }
    
    return trace_path


def _save_trace():
    """Save trace data to JSON file"""
    if not _trace_file:
        return
    
    with _trace_lock:
        try:
            with open(_trace_file, 'w', encoding='utf-8') as f:
                json.dump(_trace_data, f, indent=2, default=str, ensure_ascii=False)
        except Exception:
            pass


def write_trace(section: str, content: str, metadata: dict = None):
    """Write general trace entry"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "section": section,
        "content": str(content)[:5000],  # Limit content size
        "metadata": metadata or {}
    }
    
    with _trace_lock:
        if section.startswith("ERROR"):
            _trace_data["errors"].append(entry)
        elif section.startswith("WARNING") or section.startswith("WARN"):
            _trace_data["warnings"].append(entry)
        else:
            # General traces go to tools or agents based on metadata
            if metadata and metadata.get("type") == "agent":
                _trace_data["agents"].append(entry)
            else:
                _trace_data["tools"].append(entry)
    
    _save_trace()


def write_tool_trace(tool_name: str, command: str, output: str, duration: float = 0, status: str = "ok"):
    """Write tool execution trace"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "command": command,
        "output": str(output)[:10000],  # Limit output size
        "duration_seconds": round(duration, 2),
        "status": status
    }
    
    with _trace_lock:
        _trace_data["tools"].append(entry)
    
    _save_trace()


def write_agent_trace(agent_name: str, input_data: str, output_data: str):
    """Write agent execution trace"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "agent": agent_name,
        "input": str(input_data)[:5000],
        "output": str(output_data)[:5000]
    }
    
    with _trace_lock:
        _trace_data["agents"].append(entry)
    
    _save_trace()


def write_interactive_trace(url: str, results: dict):
    """Write interactive crawler trace"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "tool": "interactive_crawler",
        "url": url,
        "pages_crawled": len(results.get('visited_urls', [])),
        "forms_tested": len(results.get('forms_tested', [])),
        "inputs_tested": len(results.get('inputs_tested', [])),
        "errors_found": len(results.get('errors_found', [])),
        "vulnerabilities": results.get('vulnerabilities', []),
        "results": results
    }
    
    with _trace_lock:
        _trace_data["tools"].append(entry)
    
    _save_trace()


def get_trace_file():
    """Get current trace file path"""
    return _trace_file


def write_error(error_type: str, message: str, traceback: str = None):
    """Log an error to trace"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "error_type": error_type,
        "message": message,
        "traceback": traceback
    }
    
    with _trace_lock:
        _trace_data["errors"].append(entry)
    
    _save_trace()


def write_warning(warning_type: str, message: str):
    """Log a warning to trace"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "warning_type": warning_type,
        "message": message
    }
    
    with _trace_lock:
        _trace_data["warnings"].append(entry)
    
    _save_trace()


def write_llm_call(provider: str, model: str, prompt_tokens: int = 0, completion_tokens: int = 0, duration: float = 0):
    """Log LLM API call"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "provider": provider,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "duration_seconds": round(duration, 2)
    }
    
    with _trace_lock:
        _trace_data["llm_calls"].append(entry)
    
    _save_trace()


def finalize_trace():
    """Finalize and save trace file"""
    if not _trace_file:
        return
    
    with _trace_lock:
        _trace_data["meta"]["completed"] = datetime.now().isoformat()
        _trace_data["meta"]["total_tools"] = len(_trace_data["tools"])
        _trace_data["meta"]["total_agents"] = len(_trace_data["agents"])
        _trace_data["meta"]["total_errors"] = len(_trace_data["errors"])
        _trace_data["meta"]["total_warnings"] = len(_trace_data["warnings"])
        _trace_data["meta"]["total_llm_calls"] = len(_trace_data["llm_calls"])
    
    _save_trace()
    print(f"\n[+] Trace saved: {_trace_file}")
