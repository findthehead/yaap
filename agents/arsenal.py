from __future__ import annotations

import os
import re
import time
from urllib.parse import urlparse
import sys
import shutil
from typing import List, Dict, Any, Set

from states.agent_state import AgentState
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field
from utils.ansi import YELLOW, GREEN, RED, CYAN, MAGENTA, RESET, DIM

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # Fallback to a lightweight parser


def _parse_yaml_commands_fallback(text: str, kind: str) -> List[str]:
    """Very lightweight extractor to get cmd strings for a given kind.

    This is a fallback when PyYAML isn't available. It's not a full YAML parser,
    but works for the simple structure in configs/arsenal.yaml by scanning for:
      - a block starting with `- kind: "<kind>"`
      - then collecting lines with `cmd:` until the next `- kind:` or EOF.
    """
    cmds: List[str] = []
    lines = text.splitlines()
    in_kind = False
    for line in lines:
        if re.match(r"\s*-\s*kind:\s*\"?%s\"?\s*$" % re.escape(kind), line):
            in_kind = True
            continue
        if in_kind and re.match(r"\s*-\s*kind:\s*\"?", line):
            # next block
            break
        if in_kind:
            m = re.search(r"cmd:\s*'([^']*)'", line)
            if m:
                cmds.append(m.group(1))
    return cmds


DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

def _render_placeholders(cmd: str, ctx: Dict[str, Any]) -> str:
    rendered = cmd
    # Inject default wordlist placeholder if present
    if "{{wordlist}}" in rendered:
        ctx.setdefault("wordlist", DEFAULT_WORDLIST)
    for k, v in ctx.items():
        rendered = rendered.replace(f"{{{{{k}}}}}", str(v))
    # Normalize double schemes like http://https://example.com
    rendered = rendered.replace("http://https://", "https://").replace("https://http://", "http://")
    # Collapse repeated slashes (but keep scheme://)
    rendered = re.sub(r"(?<!:)//+", "/", rendered)
    return rendered


def _load_commands(kind: str, config_path: str) -> List[str]:
    with open(config_path, "r", encoding="utf-8") as f:
        text = f.read()
    if yaml is None:
        return _parse_yaml_commands_fallback(text, kind)
    try:
        data = yaml.safe_load(text) or {}
        items = data.get("arsenal", [])
        for item in items:
            if str(item.get("kind", "")).lower() == kind.lower():
                cmds: List[str] = []
                for tool in item.get("tools", []) or []:
                    for entry in tool.get("commands", []) or []:
                        # each entry is like {'name': {'cmd': '...', 'purpose': '...'}}
                        if isinstance(entry, dict):
                            for _name, spec in entry.items():
                                if isinstance(spec, dict) and "cmd" in spec:
                                    cmds.append(spec["cmd"])
                return cmds
    except Exception:
        # fallback to lightweight scanner if yaml parsing fails
        return _parse_yaml_commands_fallback(text, kind)
    return []


def _load_catalog(kind: str, config_path: str):
    """Return a compact catalog for selection: list of entries
    [{key, tool, purpose, cmd}] where key is unique toolname.commandname.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        text = f.read()
    catalog = []
    if yaml is None:
        # Very light fallback: build from parsed command strings; infer tool from the first token
        for cmd in _parse_yaml_commands_fallback(text, kind):
            first = (cmd or "").strip().split()
            tool_name = first[0].strip('"\'') if first else "unknown"
            catalog.append({
                "key": cmd[:24],
                "tool": tool_name,
                "purpose": "",
                "cmd": cmd,
            })
        return catalog
    try:
        data = yaml.safe_load(text) or {}
        items = data.get("arsenal", [])
        for item in items:
            if str(item.get("kind", "")).lower() != kind.lower():
                continue
            for tool in item.get("tools", []) or []:
                tool_name = tool.get("name", "tool")
                for entry in tool.get("commands", []) or []:
                    if isinstance(entry, dict):
                        for cmd_name, spec in entry.items():
                            if isinstance(spec, dict) and "cmd" in spec:
                                purpose = spec.get("purpose", "")
                                catalog.append({
                                    "key": f"{tool_name}.{cmd_name}",
                                    "tool": tool_name,
                                    "purpose": purpose,
                                    "cmd": spec["cmd"],
                                })
        return catalog
    except Exception:
        # Fallback to scanning only commands
        for cmd in _parse_yaml_commands_fallback(text, kind):
            catalog.append({"key": cmd[:24], "tool": "unknown", "purpose": "", "cmd": cmd})
        return catalog


class Selection(BaseModel):
    key: str = Field(..., description="Catalog key like tool.command")
    reason: str = Field("", description="Why this command helps the task")
    overrides: dict = Field(default_factory=dict, description="Optional placeholder overrides (e.g., path, param)")


class Plan(BaseModel):
    selections: list[Selection] = Field(default_factory=list)


def _safe_fallback(catalog: list[dict], kind: str, limit: int = 3) -> list[Selection]:
    """Choose a minimal, safe set of basic commands if the planner yields nothing.

    Picks keys that actually exist in the provided catalog for the given kind.
    """
    kind_l = str(kind).lower()
    if kind_l == "hunt":
        preferred = [
            "curl.simple_get",
            "curl.follow_redirects",
            "ffuf.directory_fuzz",
        ]
    else:
        preferred = [
            "curl.fetch_headers",
            "curl.verbose_request",
            "whatweb.identify",
        ]
    out: list[Selection] = []
    have = {str(c.get("key")) for c in catalog}
    for k in preferred:
        if k in have:
            out.append(Selection(key=k, reason="safe basic probe"))
            if len(out) >= limit:
                break
    # If none of the preferred keys exist, fallback to first few catalog entries
    if not out:
        for c in catalog[:max(1, limit)]:
            k = str(c.get("key"))
            if k:
                out.append(Selection(key=k, reason="minimal fallback"))
                if len(out) >= limit:
                    break
    return out


def _plan_commands(orch, state: AgentState, catalog: list[dict], max_choices: int = 6) -> list[Selection]:
    """Ask the model to select a minimal set of commands based on purposes.

    Added a HumanMessage to avoid provider warnings about system-only inputs.
    """
    # Keep prompt compact to avoid token bloat
    task = state.get("task", "")
    scout = state.get("scout", "")
    researcher = state.get("researcher", "")
    snippet_items = catalog[:100]  # limit to first 100 entries to be safe
    lines = [f"- {c['key']}: {c.get('purpose','').strip()}" for c in snippet_items]
    catalog_text = "\n".join(lines)
    # Give the model a hint about locally available tool binaries
    try:
        import shutil as _shutil
        avail = sorted({str(c.get('tool')) for c in catalog if _shutil.which(str(c.get('tool')) or '')})
        available_hint = ", ".join(avail)
    except Exception:
        available_hint = ""
    instr = (
        "You are an offensive security assistant. From the available command catalog, select the minimal set that strictly aligns with the task and purposes. "
        f"Select at most {max_choices}. Prefer lightweight commands first. Only choose when the purpose clearly matches the need. "
        "Return a JSON object matching the schema with keys and optional overrides for placeholders like path, param, header, json, wordlist."
    )
    messages = [
        SystemMessage(content=(
            instr
            + "\n\nTask:\n" + str(task)
            + "\n\nContext (scout):\n" + str(scout)
            + "\n\nContext (researcher):\n" + (researcher if isinstance(researcher, str) else str(researcher))
            + ("\n\nLocally available tools: " + available_hint if available_hint else "")
            + "\n\nCatalog (key: purpose):\n" + catalog_text
        )),
        HumanMessage(content="Select JSON plan now."),
    ]
    try:
        try:
            from utils.structured import structured_invoke
            plan: Plan = structured_invoke(
                orch.model,
                Plan,
                messages,
                provider=getattr(orch, 'provider', None),
            )
        except Exception:
            plan: Plan = orch.model.with_structured_output(Plan).invoke(messages)
        sels = plan.selections[:max_choices]
        if not sels:
            return []
        return sels
    except Exception:
        # Planner failed entirely; let caller decide fallback based on kind
        return []


def arsenal_node(state: AgentState, orch=None):
    # Build context for placeholder rendering
    host = getattr(orch, "host", "")
    parsed = urlparse(host if "://" in host else f"http://{host}")
    host_noscheme = parsed.netloc or parsed.path or host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ctx = {
        "host": host,
        "host_noscheme": host_noscheme,
        "port": port,
        # sensible defaults for optional placeholders
        "path": getattr(orch, "path", ""),
        "header": "Test",
        "json": "{}",
        "datafile": "data.bin",
        "auth": "",
        "param": getattr(orch, "param", ""),
    }

    # Load commands for the selected kind
    config_path = os.path.join("configs", "arsenal.yaml")
    kind = getattr(orch, "test", "recon")
    catalog = _load_catalog(kind, config_path)
    try:
        print(f"{MAGENTA}[arsenal]{RESET} Starting ({kind}); catalog entries: {len(catalog)}", flush=True)
    except Exception:
        pass
    if not catalog:
        return {"content": state.get("content", []) + ["No commands available in catalog."], "hunter": ""}

    # Prefer only tools that are actually available on this system (expanded search)
    def _tool_available(tool: str) -> bool:
        if not tool:
            return False
        if shutil.which(tool):
            return True
        # Common explicit paths
        candidate_paths = [f"/usr/bin/{tool}", f"/usr/local/bin/{tool}", f"/snap/bin/{tool}"]
        return any(os.path.exists(p) for p in candidate_paths)

    def _is_available(entry: Dict[str, Any]) -> bool:
        tool = str(entry.get("tool", "")).strip()
        return _tool_available(tool)

    available_catalog = [c for c in catalog if _is_available(c)] or catalog

    # Purpose-based planning: one command per tool, chosen by LLM, unless fallback
    max_override = getattr(orch, "max_commands", None)
    # Limit planned selections to number of distinct tools or override
    distinct_tools = list({c.get("tool") for c in available_catalog if c.get("tool")})
    max_choices = int(max_override) if max_override else min(8, len(distinct_tools))
    planned = _plan_commands(orch, state, available_catalog, max_choices=max_choices)
    if not planned:
        planned = _safe_fallback(available_catalog, kind=str(kind), limit=min(3, max_choices))

    # Ensure uniqueness: keep only first selection per tool
    seen_tools: Set[str] = set()
    selections: List[Selection] = []
    for s in planned:
        tk = s.key.split(".")[0] if "." in s.key else s.key
        if tk not in seen_tools:
            selections.append(s)
            seen_tools.add(tk)

    # Ensure-basics in hunt mode: prepend curl.fetch_headers if available and not already selected
    if str(kind).lower() == "hunt" and getattr(orch, "ensure_basics", False):
        # Use an available basic curl key for hunt mode
        candidate_keys = ["curl.simple_get", "curl.follow_redirects"]
        basic_key = None
        for ck in candidate_keys:
            if any(c.get("key") == ck for c in available_catalog):
                basic_key = ck
                break
        if basic_key:
            have_basic = any(getattr(s, 'key', '') == basic_key for s in selections)
            if not have_basic:
                selections = [Selection(key=basic_key, reason="baseline probe")] + selections

    # Map selection keys to command templates (forced targets may be added later)
    key_to_cmd = {c["key"]: c["cmd"] for c in catalog}

    # Import executor tool only (no implicit websearch)
    try:
        from tools.executor import execute  # LangChain Tool
    except Exception as e:
        return {"content": [f"Executor tool not available: {e}"]}

    outputs: List[str] = []
    runs: List[Dict[str, Any]] = []
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join("artifacts")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"arsenal_{kind}_{host_noscheme}_{timestamp}.txt")

    # Optional pre-discovery step: lightweight crawler to find paths and forms (no path arg required)
    try:
        if not getattr(orch, "dry_run", False):
            from tools.executor import execute as _exec
            disc_out = os.path.join(report_dir, f"discovery_{host_noscheme}_{timestamp}.txt")
            py = sys.executable or "python3"
            disc_cmd = f"{py} tools/crawler.py --url {host} --max-pages 25 --out {disc_out}"
            print(f"{MAGENTA}[arsenal]{RESET} Discovering endpoints: {disc_cmd}", flush=True)
            start = time.perf_counter()
            dres = _exec.invoke({"cmd": disc_cmd, "timeout_sec": 120})
            elapsed = time.perf_counter() - start
            outputs.append(f"# discovery\n$ {disc_cmd}\n{dres}")
            runs.append({
                "key": "crawler.discover",
                "purpose": "Find links and forms automatically",
                "cmd": disc_cmd,
                "status": "ok" if not str(dres).startswith(("[!]", "[T]", "[-]")) else "error",
                "duration": f"{elapsed:.1f}s",
                "output": dres,
            })
    except Exception as _e:
        pass

    # Interactive pentest pilot (only in hunt) — probes forms & short payloads, provides targeting hints
    pilot_hints = {"discovered_path": "", "discovered_param": ""}
    try:
        if str(kind).lower() == "hunt" and not getattr(orch, "dry_run", False):
            print(f"{MAGENTA}[arsenal]{RESET} Starting interactive pilot (forms + short payloads)", flush=True)
            try:
                from tools.pentester import run_pilot
                start = time.perf_counter()
                pilot = run_pilot(host, timeout=int(getattr(orch, "default_timeout", 90)), max_payloads=40)
                elapsed = time.perf_counter() - start
                plog = pilot.get("log", "")
                pilot_hints = pilot.get("hints", pilot_hints) or pilot_hints
                outputs.append(f"# pilot\n{plog}")
                runs.append({
                    "key": "pilot.explore",
                    "purpose": "Interactive form probing with short payloads",
                    "cmd": f"pilot(host={host})",
                    "status": "ok",
                    "duration": f"{elapsed:.1f}s",
                    "output": plog,
                })
            except Exception as _pe:
                runs.append({
                    "key": "pilot.explore",
                    "purpose": "Interactive form probing",
                    "cmd": f"pilot(host={host})",
                    "status": "error",
                    "duration": f"0.0s",
                    "output": f"pilot failed: {_pe}",
                })
    except Exception:
        pass

    # Force focused commands after discovery + pilot hints
    forced: List[Selection] = []
    discovered_path = pilot_hints.get("discovered_path", "") if isinstance(pilot_hints, dict) else ""
    discovered_param = pilot_hints.get("discovered_param", "") if isinstance(pilot_hints, dict) else ""
    if str(kind).lower() == 'hunt' and (discovered_path or discovered_param):
        ov_path = discovered_path
        ov_param = discovered_param or 'q'
        if any(c.get('key') == 'sqlmap.level_risk_scan' for c in available_catalog) and shutil.which('sqlmap'):
            forced.append(Selection(key='sqlmap.level_risk_scan', reason='probe injectable parameter', overrides={'path': ov_path, 'param': ov_param}))
        if discovered_param and any(c.get('key') == 'ffuf.parameter_value_fuzz' for c in available_catalog) and shutil.which('ffuf'):
            forced.append(Selection(key='ffuf.parameter_value_fuzz', reason='fuzz parameter values', overrides={'path': ov_path, 'param': ov_param}))
        if not discovered_param and any(c.get('key') == 'ffuf.parameter_name_fuzz' for c in available_catalog) and shutil.which('ffuf'):
            forced.append(Selection(key='ffuf.parameter_name_fuzz', reason='discover parameter names', overrides={'path': ov_path, 'param': '1'}))
    if forced:
        print(f"{MAGENTA}[arsenal]{RESET} Forcing targeted: {[s.key for s in forced]}", flush=True)
        existing = {getattr(s,'key','') for s in selections}
        selections = [s for s in forced if s.key not in existing] + selections

    print(f"{YELLOW}[arsenal]{RESET} Selected {YELLOW}{len(selections)}{RESET} command(s)", flush=True)

    # Baseline fast checks to ensure at least one successful run for grounding
    try:
        if str(kind).lower() == "hunt" and not getattr(orch, "dry_run", False):
            from tools.executor import execute as _exec
            baseline_cmds = [
                ("curl.fetch_headers", f"curl -I {host}", "Fetch HTTP headers"),
                ("whatweb.identify", f"whatweb -a 3 {host}", "Identify technologies"),
            ]
            for key, bcmd, why in baseline_cmds:
                # Prefer binary; else fallback to Python for curl-like HEAD
                bname = key.split(".")[0]
                if shutil.which(bname) is None and key.startswith("curl."):
                    # Fallback HEAD request via urllib
                    try:
                        print(f"{MAGENTA}[arsenal]{RESET} Baseline (py-HEAD): {host}", flush=True)
                        import urllib.request as _ur
                        req = _ur.Request(host, method="HEAD")
                        with _ur.urlopen(req, timeout=int(getattr(orch, "default_timeout", 90))) as resp:
                            hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                            out = f"HTTP {resp.status}\n{hdrs}"
                        elapsed = 0.0
                        outputs.append(f"# baseline\n$ PY-HEAD {host}\n{out}")
                        runs.append({
                            "key": key,
                            "purpose": why,
                            "cmd": f"PY-HEAD {host}",
                            "status": "ok",
                            "duration": f"{elapsed:.1f}s",
                            "output": out,
                        })
                        continue
                    except Exception as _pe:
                        pass
                if shutil.which(bname) is None:
                    continue
                print(f"{MAGENTA}[arsenal]{RESET} Baseline: {bcmd}", flush=True)
                start = time.perf_counter()
                out = _exec.invoke({"cmd": bcmd, "timeout_sec": int(getattr(orch, "default_timeout", 90))})
                elapsed = time.perf_counter() - start
                outputs.append(f"# baseline\n$ {bcmd}\n{out}")
                status = "ok" if not str(out).startswith(("[!]", "[T]", "[-]")) else "error"
                runs.append({
                    "key": key,
                    "purpose": why,
                    "cmd": bcmd,
                    "status": status,
                    "duration": f"{elapsed:.1f}s",
                    "output": out,
                })
    except Exception:
        pass

    # Run each command via the executor tool
    def _extract_findings(text: str) -> List[str]:
        hints: List[str] = []
        t = text or ""
        patterns = [
            r"\bVULNERABLE\b",
            r"(?i)sql\s*injection|sqli",
            r"(?i)cross[- ]site\s*scripting|xss",
            r"\bCVE-\d{4}-\d+\b",
            r"\b(critical|high)\b",
            r"\b(401|403|500|502|503|504)\b",
            r"(?i)leak|expos(e|ure)|secret|token",
            r"(?i)open\s*redirect",
            r"(?i)directory\s*traversal|path\s*traversal",
        ]
        for p in patterns:
            if re.search(p, t):
                hints.append(p)
        return sorted(set(hints))

    findings: List[str] = []

    for sel in selections:
        base = key_to_cmd.get(sel.key)
        if not base:
            continue
        # Apply overrides if provided
        local_ctx = dict(ctx)
        if isinstance(sel.overrides, dict):
            for k, v in sel.overrides.items():
                local_ctx[k] = v
        # Seed discovery-derived placeholders when missing
        try:
            discovered_path
        except NameError:
            discovered_path = ""
            discovered_param = ""
        if discovered_path and not local_ctx.get('path'):
            local_ctx['path'] = discovered_path
        if discovered_param and not local_ctx.get('param'):
            local_ctx['param'] = discovered_param
        cmd = _render_placeholders(base, local_ctx)
        # If ffuf is selected and a payload file is provided, swap the wordlist to payload file
        try:
            if sel.key.startswith("ffuf."):
                payload_file = getattr(orch, "payload_file", "")
                if payload_file:
                    # Replace any existing -w argument with the payload file
                    import re as _re
                    if " -w " in cmd:
                        cmd = _re.sub(r"-w\s+\S+", f"-w {payload_file}", cmd)
                    else:
                        cmd += f" -w {payload_file}"
        except Exception:
            pass
        try:
            head = f"{CYAN}{sel.key}{RESET}"
            why = f"{DIM}{sel.reason}{RESET}" if sel.reason else ""
            print(f"[>] {head} — {why}", flush=True)
            # Preflight: check binary availability. Prefer explicit tool name;
            # otherwise infer from the command template.
            tool_name = (sel.key.split(".")[0] if "." in sel.key else "").strip()
            if not tool_name:
                base_for_tool = key_to_cmd.get(sel.key, "")
                if base_for_tool:
                    token = base_for_tool.strip().split()[0]
                    tool_name = (token or "").strip('"\'')
            if tool_name and not _tool_available(tool_name):
                # Attempt optional auto-install if flag set and we have sudo rights
                attempted_install = False
                if getattr(orch, "auto_install", False) and os.geteuid() == 0:
                    pkg = tool_name  # Assume package name matches tool
                    install_cmds = []
                    # Add Kali repo only once (if sqlmap requested and repo not present)
                    try:
                        if tool_name == "sqlmap":
                            sources = open('/etc/apt/sources.list','r',encoding='utf-8').read()
                            if 'kali' not in sources.lower():
                                install_cmds.append('echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list')
                                install_cmds.append('wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add -')
                        install_cmds.append('apt-get update -y')
                        install_cmds.append(f'apt-get install -y {pkg}')
                    except Exception:
                        install_cmds = [f'apt-get install -y {pkg}']
                    full_script = ' && '.join(install_cmds)
                    print(f"{MAGENTA}[arsenal]{RESET} Auto-install attempt for {tool_name}: {full_script}", flush=True)
                    try:
                        from tools.executor import execute as _exec
                        _ = _exec.invoke({"cmd": full_script, "timeout_sec": 400})
                        attempted_install = True
                    except Exception:
                        attempted_install = False
                if tool_name and _tool_available(tool_name):
                    print(f"{GREEN}[arsenal]{RESET} Found tool after install: {tool_name}", flush=True)
                if tool_name and not _tool_available(tool_name):
                    res = f"[-] Missing binary: '{tool_name}' not found (attempted_install={attempted_install})"
                elapsed = 0.0
                note = f"# {sel.key} — {sel.reason}" if getattr(sel, "reason", "") else f"# {sel.key}"
                outputs.append(f"{note}\n$ {cmd}\n{res}")
                runs.append({
                    "key": sel.key,
                    "purpose": sel.reason,
                    "cmd": cmd,
                    "status": "error",
                    "duration": f"{elapsed:.1f}s",
                    "output": res,
                })
                findings.extend(_extract_findings(str(res)))
                print(f"{RED}✗{RESET} {CYAN}{sel.key}{RESET} missing binary", flush=True)
                continue
            if getattr(orch, "dry_run", False):
                res = "⏭️ Dry run: command not executed"
                elapsed = 0.0
            else:
                print(f"{MAGENTA}[arsenal]{RESET} Executing: {cmd}", flush=True)
                start = time.perf_counter()
                res = execute.invoke({"cmd": cmd, "timeout_sec": int(getattr(orch, "default_timeout", 90))})
                elapsed = time.perf_counter() - start
        except Exception as e:
            res = f"Execution failure: {e}"
            elapsed = 0.0
        note = f"# {sel.key} — {sel.reason}" if getattr(sel, "reason", "") else f"# {sel.key}"
        outputs.append(f"{note}\n$ {cmd}\n{res}")
        sres = str(res)
        status = "ok" if not sres.startswith(("[!]", "[T]", "[-]")) else "error"
        mark = f"{GREEN}✓{RESET}" if status == "ok" else f"{RED}✗{RESET}"
        print(f"{mark} {CYAN}{sel.key}{RESET} finished in {YELLOW}{elapsed:.1f}s{RESET}", flush=True)
        runs.append({
            "key": sel.key,
            "purpose": sel.reason,
            "cmd": cmd,
            "status": status,
            "duration": f"{elapsed:.1f}s",
            "output": res,
        })
        findings.extend(_extract_findings(str(res)))

    # Persist a raw log
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n\n".join(outputs))
    except Exception as e:
        outputs.append(f"Failed to write report: {e}")

    # Feed into state: set hunter so reporter can summarize consistently
    # Also keep aggregated outputs in content list
    agg = "\n\n".join(outputs)
    available_tools = sorted({c.get("tool") for c in available_catalog if c.get("tool")})
    return {
        "hunter": agg,
        "content": state.get("content", []) + [agg],
        "tools_runs": state.get("tools_runs", []) + runs,
        "findings": state.get("findings", []) + sorted(set(findings)),
        "available_tools": available_tools,
    }
