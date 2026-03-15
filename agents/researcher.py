from langchain_core.messages import SystemMessage, HumanMessage
from states.agent_state import AgentState, Queries
from utils.parser import markdown_parse
from tools.websearch import research
from utils.toolbind import run_tool_loop
from utils.ansi import YELLOW, GREEN, RED, RESET, CYAN, MAGENTA, BOLD
from utils.reasoning import ReasoningDisplay, show_llm_response
import time
import re


def _extract_terms(text: str):
    terms = set()
    if not text:
        return terms
    # CVE IDs
    for m in re.findall(r"CVE-\d{4}-\d+", text, flags=re.I):
        terms.add(m.upper())
    # Common tech tokens with optional versions
    techs = [
        "Apache", "Nginx", "OpenSSL", "PHP", "WordPress", "Drupal", "Joomla",
        "Tomcat", "Struts", "Spring", "Log4j", "Gunicorn", "Node.js", "Express",
    ]
    for t in techs:
        for m in re.findall(rf"{t}[ /]?\d+(?:\.\d+)*", text, flags=re.I):
            terms.add(m)
        if re.search(rf"\b{t}\b", text, flags=re.I):
            terms.add(t)
    return terms


def _is_command_like(q: str) -> bool:
    ql = q.lower()
    # Filter out shell/binary style queries and flags
    banned_bins = [
        "curl", "whatweb", "nmap", "masscan", "ffuf", "sqlmap",
        "mitmproxy", "mitmweb", "mitmdump", "wpscan", "nuclei", "lynx",
    ]
    if any(b in ql for b in banned_bins):
        return True
    if " -" in ql or ql.strip().startswith("-"):
        return True
    # Allow URLs, but block patterns that look like commands with URLs prefixing a binary
    return False


def researcher_node(state: AgentState, orch = None):
    prompt_lines = markdown_parse('prompts/research_prompt.md')
    prompt_content = '\n'.join(prompt_lines) if isinstance(prompt_lines, list) else str(prompt_lines)
    
    # Combine available context: scout summary, any previous researcher notes, and evidence if present
    base_chunks = []
    for k in ("scout", "researcher", "hunter"):
        v = state.get(k, "")
        if isinstance(v, list):
            base_chunks.extend([str(x) for x in v])
        elif v:
            base_chunks.append(str(v))
    base_text = "\n\n".join(base_chunks)

    # Initialize reasoning display
    display = ReasoningDisplay("researcher", CYAN)
    
    try:
        print(f"\n{CYAN}{'='*80}{RESET}", flush=True)
        print(f"{CYAN}[>] RESEARCHER AGENT{RESET} {BOLD}Analyzing intelligence and planning research{RESET}", flush=True)
        print(f"{CYAN}{'='*80}{RESET}\n", flush=True)
        time.sleep(0.5)
        
        display.thinking("I need to understand the target's technology stack, known vulnerabilities, and attack surface. Let me analyze the reconnaissance data and formulate targeted research queries.")
        
        t0 = time.perf_counter()
        # Ensure non-empty human message and provider-tolerant structured output
        tmsg = state.get('task') or f"Research security posture for {getattr(orch, 'host', '')}"
        if not isinstance(tmsg, str) or not tmsg.strip():
            tmsg = f"Research security posture for {getattr(orch, 'host', '')}"
        
        display.observation("Analyzing reconnaissance data to extract technology indicators and potential CVEs...")
        
        try:
            from utils.structured import structured_invoke
            queries_struct = structured_invoke(
                orch.model,
                Queries,
                [
                    SystemMessage(content=prompt_content.format(content=base_text)),
                    HumanMessage(content=tmsg),
                ],
                provider=getattr(orch, 'provider', None),
            )
        except Exception:
            # Last resort: fall back to default call which may still work for local models
            queries_struct = orch.model.with_structured_output(Queries).invoke([
                SystemMessage(content=prompt_content.format(content=base_text)),
                HumanMessage(content=tmsg)
            ])
        llm_queries = list(getattr(queries_struct, 'queries', []) or [])
        
        if llm_queries:
            display.decision(f"Generated {len(llm_queries)} strategic research queries based on reconnaissance findings")
            time.sleep(0.4)
            print(f"\n{MAGENTA}📚 Research Queries:{RESET}", flush=True)
            time.sleep(0.2)
            for i, q in enumerate(llm_queries[:5], 1):
                time.sleep(0.1)
                print(f"{CYAN}  {i}.{RESET} {q}", flush=True)
            if len(llm_queries) > 5:
                time.sleep(0.1)
                print(f"{CYAN}  ...{RESET} and {len(llm_queries)-5} more queries", flush=True)
        
        time.sleep(0.3)
        print(f"\n{GREEN}✓{RESET} Generated queries in {YELLOW}{time.perf_counter()-t0:.1f}s{RESET}", flush=True)
    except Exception as e:
        print(f"\n{RED}✗{RESET} [researcher] Failed to build queries: {e}\n", flush=True)
        llm_queries = []

    # Heuristic queries from detected terms
    extracted = _extract_terms(base_text)
    host = getattr(orch, 'host', '') or ''
    extra_queries = []
    for term in sorted(extracted):
        if term.upper().startswith("CVE-"):
            extra_queries.extend([
                f"{term} CVSS score",
                f"Mitigation for {term}",
                f"Exploit PoC {term}",
            ])
        else:
            extra_queries.extend([
                f"Known vulnerabilities {term} CVE",
                f"Hardening guide {term}",
            ])
    if host and isinstance(host, str):
        extra_queries.extend([
            f"site:{host} admin",
            f"site:{host} login",
        ])

    # Merge, dedupe, and cap queries
    seen = set()
    final_queries = []
    for q in llm_queries + extra_queries:
        q = str(q).strip()
        if q and q not in seen and not _is_command_like(q):
            seen.add(q)
            final_queries.append(q)
        if len(final_queries) >= 10:
            break

    # Use tool-bound loop to let the model call 'research' directly
    seed = []
    prev_research = state.get('researcher', [])
    if isinstance(prev_research, list):
        seed.extend([str(x) for x in prev_research])
    if base_text:
        seed.append(base_text)
    
    display.reasoning("Gathering vulnerability intelligence and security context...")
    
    # Instruct the model briefly to call 'research' tool with focused queries
    sys_extra = "\n\nWhen needed, call the 'research' tool with targeted queries to enrich the findings."
    msgs = [
        SystemMessage(content=prompt_content + sys_extra),
        HumanMessage(content=tmsg),
    ]
    
    time.sleep(0.4)
    ai, outs = run_tool_loop(orch.model, [research], msgs, max_iters=3)
    
    # Show LLM's reasoning
    time.sleep(0.4)
    show_llm_response("researcher", ai, CYAN)
    
    seed.extend(outs)
    
    display.conclusion(f"Compiled intelligence from {len(outs)} research queries. Ready for exploitation phase.")
    
    time.sleep(0.3)
    print()  # Extra spacing
    
    return {"researcher": seed}
