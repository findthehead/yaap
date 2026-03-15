from langchain.tools import tool
import os
import shutil
import signal
import subprocess
import threading
import time
import pty
import select
from typing import Optional, Dict, Any
from utils.ansi import GRAY, DIM, RESET, CYAN, YELLOW, GREEN, RED
from utils.trace import write_tool_trace
from utils.auth import inject_auth_into_curl


def _with_stdbuf(cmd: str) -> str:
    return f"stdbuf -oL -eL {cmd}" if shutil.which("stdbuf") else cmd


def _kill_process_group(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_pty(cmd: str, timeout_sec: int, show_output: bool = False) -> str:
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=os.setsid,  # new process group on Unix
            close_fds=True,
        )
    finally:
        os.close(slave)

    lines = []
    start = time.time()
    killed = False

    def _timeout_kill():
        nonlocal killed
        killed = True
        _kill_process_group(proc)

    timer = threading.Timer(timeout_sec, _timeout_kill)
    timer.start()

    try:
        while True:
            r, _, _ = select.select([master], [], [], 0.2)
            if master in r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                for part in text.splitlines(keepends=True):
                    if part:
                        # Only show output if explicitly requested (for debugging)
                        if show_output:
                            print(f"{DIM}{GRAY}  │ {part.rstrip()}{RESET}", flush=True)
                        lines.append(part.replace("\r", "\n"))
            if proc.poll() is not None:
                # drain remaining
                try:
                    while True:
                        chunk = os.read(master, 4096)
                        if not chunk:
                            break
                        text = chunk.decode("utf-8", errors="replace")
                        if show_output:
                            print(f"{DIM}{GRAY}  │ {text.rstrip()}{RESET}", flush=True)
                        lines.append(text)
                except OSError:
                    pass
                break
    finally:
        timer.cancel()
        os.close(master)
        proc.wait()

    elapsed = time.time() - start
    output = "".join(lines).strip()
    if killed:
        return f"⏱️ Command timed out after {timeout_sec}s (elapsed {elapsed:.1f}s)\n{output}"
    if proc.returncode == 0:
        return output or "[+] Command executed successfully (no output)."
    return f"[!] Command failed (exit {proc.returncode}) in {elapsed:.1f}s\n{output}"


@tool()
def execute(cmd: str, timeout_sec: int = 90, pty_mode: bool = True, show_output: bool = False, session_data: Optional[Dict[str, Any]] = None) -> str:
    """Execute a shell command with real-time streaming and a hard timeout.

    - pty_mode (Unix): best for tools that use carriage-return progress (ffuf, sqlmap, nuclei).
    - Uses stdbuf when available to reduce buffering.
    - Preflight: if the first binary token is missing, return a clear message instead of spawning.
    - show_output: if True, stream output to terminal (default False for clean professional output)
    - session_data: Dict with 'cookie', 'bearer_token' for authenticated requests (auto-injected into curl)
    """
    # Inject authentication headers into curl commands
    if session_data and 'curl' in cmd:
        cmd = inject_auth_into_curl(cmd, session_data)
    
    # Extract tool name for better logging
    tool_name = (cmd.strip().split() or [""])[0].strip("'\"").split('/')[-1]
    
    # Professional terminal output - show what we're running
    print(f"{CYAN}[>]{RESET} {YELLOW}{tool_name}{RESET} ", end='', flush=True)
    
    cmd = _with_stdbuf(cmd)
    # Preflight binary existence (simple heuristic: first token, strip quotes)
    import shutil as _sh
    first_token = (cmd.strip().split() or [""])[0].strip("'\"")
    # Ignore shell builtins and assignment patterns
    if first_token and first_token not in {"echo", "printf", "python", "python3", "sh", "bash", "stdbuf"}:
        # If stdbuf prefix added, second token might be the actual binary
        if first_token == "stdbuf":
            parts = cmd.strip().split()
            if len(parts) > 3:  # stdbuf -oL -eL <realcmd>
                first_token = parts[3].strip("'\"")
        if not _sh.which(first_token):
            result = f"[-] Missing binary: {first_token} not found in PATH"
            print(f"{RED}✗{RESET} missing")
            write_tool_trace(tool_name, cmd, result, 0, "error")
            return result
    
    start_time = time.time()
    
    if pty_mode and os.name != "nt":
        try:
            output = _run_pty(cmd, timeout_sec, show_output)
            elapsed = time.time() - start_time
            
            # Determine status from output
            status = "ok" if "[+]" in output else ("timeout" if "[T]" in output else ("error" if "[!]" in output else "ok"))
            
            # Professional terminal feedback
            if status == "ok":
                print(f"{GREEN}✓{RESET} {DIM}{elapsed:.1f}s{RESET}")
            elif status == "timeout":
                print(f"{YELLOW}⏱{RESET} {DIM}timeout{RESET}")
            else:
                print(f"{RED}✗{RESET} {DIM}{elapsed:.1f}s{RESET}")
            
            # Write full output to trace
            write_tool_trace(tool_name, cmd, output, elapsed, status)
            return output
        except Exception as e:
            # Fallback if PTY is not available (e.g., sandbox ran out of ptys)
            pass

    # Fallback text mode
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
            preexec_fn=os.setsid if os.name != "nt" else None,
            close_fds=True,
        )
    except Exception as e:
        result = f"[-] Execution spawn error: {e}"
        print(f"{RED}✗{RESET} spawn error")
        write_tool_trace(tool_name, cmd, result, 0, "error")
        return result

    lines = []
    killed = False

    def _timeout_kill():
        nonlocal killed
        killed = True
        if os.name != "nt":
            _kill_process_group(proc)
        else:
            try:
                proc.kill()
            except Exception:
                pass

    timer = threading.Timer(timeout_sec, _timeout_kill)
    timer.start()

    try:
        if proc.stdout is not None:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                # Only show if explicitly requested
                if show_output:
                    print(f"{DIM}{GRAY}  │ {line}{RESET}", flush=True)
                lines.append(line)
    finally:
        if proc.stdout:
            proc.stdout.close()
        rc = proc.wait()
        timer.cancel()

    elapsed = time.time() - start
    output = "\n".join(lines).strip()
    
    # Build result message
    if killed:
        result = f"⏱️ Command timed out after {timeout_sec}s (elapsed {elapsed:.1f}s)\n{output}"
        status = "timeout"
        print(f"{YELLOW}⏱{RESET} {DIM}timeout{RESET}")
    elif rc == 0:
        result = output or "[+] Command executed successfully (no output)."
        status = "ok"
        print(f"{GREEN}✓{RESET} {DIM}{elapsed:.1f}s{RESET}")
    else:
        result = f"[!] Command failed (exit {rc}) in {elapsed:.1f}s\n{output}"
        status = "error"
        print(f"{RED}✗{RESET} {DIM}{elapsed:.1f}s{RESET}")
    
    # Write to trace
    write_tool_trace(tool_name, cmd, result, elapsed, status)
    return result
