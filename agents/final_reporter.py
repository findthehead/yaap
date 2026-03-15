from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, AIMessage, ChatMessage
from states.agent_state import AgentState
from utils.parser import markdown_parse
from utils.reporter import export_report
from utils.text import sanitize_model_text
from utils.ansi import YELLOW, GREEN, RED, RESET



def reporter_node(state: AgentState, orch = None):
    prompt_lines = markdown_parse('prompts/final_report_propmt.md')
    prompt_content = '\n'.join(prompt_lines) if isinstance(prompt_lines, list) else str(prompt_lines)
    
    # Build an evidence digest strictly from successful tool runs (ground truth)
    tools_runs = state.get('tools_runs', []) or []
    ok_runs = [r for r in tools_runs if str(r.get('status')) == 'ok']
    if ok_runs:
        parts = []
        for r in ok_runs:
            key = str(r.get('key',''))
            cmd = str(r.get('cmd',''))
            out = str(r.get('output',''))
            parts.append(f"key: {key}\ncmd: {cmd}\noutput:\n{out}\n----")
        hunter_content = "\n".join(parts)
    else:
        # Fall back to researcher/scout content when no successful runs
        rc = state.get('researcher', [])
        if isinstance(rc, list):
            hunter_content = "\n".join(str(x) for x in rc)
        else:
            hunter_content = str(rc or state.get('scout', ''))
    
    # Get findings from state
    findings = state.get('findings', []) or []
    findings_section = ""
    if findings:
        findings_section = "\n\n[!] IDENTIFIED VULNERABILITIES:\n"
        for idx, finding in enumerate(findings, 1):
            findings_section += f"{idx}. {finding}\n"
        findings_section += "\nIMPORTANT: Include ALL above vulnerabilities in the final report with proper severity ratings.\n"
    
    # Strict anti-fabrication guardrails
    guard = (
        "Rules (strict):\n"
        "- Only summarize facts present verbatim in the Evidence Digest and Identified Vulnerabilities.\n"
        "- Do NOT invent endpoints like /admin, /api, /uploads unless they appear in the digest.\n"
        "- If a section lacks evidence, write 'Evidence insufficient' or 'No endpoints discovered'.\n"
        "- Cite commands (key/cmd) when stating findings, and keep claims minimal if outputs are generic.\n"
        "- MUST include all vulnerabilities from the 'IDENTIFIED VULNERABILITIES' section with severity ratings.\n"
        "- Rate XSS vulnerabilities as High or Medium depending on context.\n"
        "- Rate SQL Injection as Critical or High.\n"
        "- Provide specific mitigation steps for each vulnerability found.\n"
    )
    content_block = f"Evidence Digest (successful runs only)\n\n{hunter_content}\n{findings_section}\n{guard}"

    messages = [
        SystemMessage(content=prompt_content.format(content=content_block)), 
        HumanMessage(content="Produce an evidence-grounded report. Include ALL identified vulnerabilities with severity ratings and mitigations.")
    ]
    tools_runs = tools_runs or []
    
    # Soft gating: if in hunt mode with zero successful tool runs, note it but still produce a report
    mode = str(getattr(orch, 'test', 'recon')).lower()
    ok_runs = [r for r in tools_runs if str(r.get('status')) == 'ok']
    preface = ""
    if mode == 'hunt' and len(ok_runs) == 0:
        preface = (
            "Note: No successful tool runs recorded; summarizing reconnaissance and research only. "
            "Verify tool availability, timeouts, and network connectivity.\n\n"
        )

    try:
        print(f"{YELLOW}[>][reporter]{RESET} Drafting final report from evidence...", flush=True)
        response = orch.model.invoke(messages)
        print(f"{GREEN}✓{RESET} [reporter] Draft ready", flush=True)
    except Exception as e:
        print(f"{RED}✗{RESET} [reporter] Failed to draft report: {e}", flush=True)
        raise

    # Build structured report payload
    final_summary = preface + sanitize_model_text(response.content)
    
    # Check if report generation is disabled
    if hasattr(orch, 'no_report') and orch.no_report:
        print(f"{YELLOW}[*][reporter]{RESET} Report generation disabled (--no-report).", flush=True)
        if findings:
            print(f"\n{RED}{'='*80}{RESET}")
            print(f"{RED}[!] IDENTIFIED VULNERABILITIES ({len(findings)} found){RESET}")
            print(f"{RED}{'='*80}{RESET}\n")
            for idx, finding in enumerate(findings, 1):
                print(f"{RED}{idx}. {finding}{RESET}\n")
            print(f"{RED}{'='*80}{RESET}\n")
        else:
            print(f"\n{GREEN}[✓] No vulnerabilities identified during assessment.{RESET}\n")
        return {"reporter": final_summary, "report_path": "No report generated (--no-report flag)"}
    
    # Generate report files
    try:
        report_path = export_report({
            'final_summary': final_summary,
            'tools_runs': tools_runs,
            'findings': findings,
        }, orch=orch)
    except Exception as e:
        report_path = f"Report export failed: {e}"

    return {"reporter": final_summary, "report_path": report_path}
