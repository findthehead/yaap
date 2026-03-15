import html
from markdown import markdown
from datetime import datetime
from utils.parser import url_parse
from utils.pdf_reporter import generate_professional_pdf
import json
import csv
import os

try:
    from fpdf import FPDF  # type: ignore
    _PDF_AVAILABLE = True
except Exception:
    _PDF_AVAILABLE = False


def convert_to_string(obj):
    """Convert various object types to readable string form."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (list, tuple)):
        parts = []
        for item in obj:
            if hasattr(item, "content"):
                parts.append(str(item.content))
            elif hasattr(item, "__str__"):
                parts.append(str(item))
            else:
                parts.append(repr(item))
        return "\n".join(parts)
    if hasattr(obj, "content"):
        return str(obj.content)
    if hasattr(obj, "pretty_print"):
        return str(obj.pretty_print())
    return str(obj)


def render_markdown(md_text):
    """Render markdown text into safe HTML."""
    if not md_text or not md_text.strip():
        return "<p><em>No content available.</em></p>"
    return markdown(md_text, extensions=["fenced_code", "tables", "sane_lists", "toc"])


def export_report(report, orch=None):
    """Generate professional PDF report (default) with optional CSV output.
    
    NO HTML output by default - only professional A4 PDF with evidence.
    CSV only generated with --csv_report flag.

    Report dict keys:
      - final_summary: str
      - findings: list[str]
      - vulnerabilities: list[dict] - structured vulnerability data
      - tools_runs: list[dict]
    """
    if orch is None:
        try:
            from yaap.yaap import orch as orch
        except Exception:
            orch = None

    host_label = str(getattr(orch, "host", "unknown"))
    test_label = str(getattr(orch, "test", "unknown"))
    mode = str(getattr(orch, "test", "recon")).lower()
    heading = "Security Assessment Report" if mode == "hunt" else "Reconnaissance Report"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = url_parse(orch.host) if orch else "unknown"
    os.makedirs("artifacts", exist_ok=True)
    base = os.path.join("artifacts", f"report_{mode}_{host}_{timestamp}")

    # Extract data
    summary = convert_to_string(report.get("final_summary", "")).strip()
    findings = report.get("findings", []) or []
    vulnerabilities = report.get("vulnerabilities", []) or []
    runs = report.get("tools_runs", []) or []

    # Generate professional PDF (ALWAYS)
    pdf_path = f"{base}.pdf"
    if _PDF_AVAILABLE:
        try:
            pdf = generate_professional_pdf(
                {
                    'final_summary': summary,
                    'findings': findings,
                    'vulnerabilities': vulnerabilities,
                    'tools_runs': runs
                },
                target=host_label,
                test_type=heading,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            pdf.output(pdf_path)
            print(f"\n[+] Professional PDF Report Generated")
            print(f"    {pdf_path}")
        except Exception as e:
            print(f"    [!] PDF generation failed: {e}")
            pdf_path = None
    else:
        print(f"    [!] PDF library missing. Install fpdf2: pip install fpdf2")
        pdf_path = None

    # Generate CSV ONLY if --csv_report flag is set
    csv_path = None
    if getattr(orch, "output_csv", False):
        csv_path = f"{base}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["Type", "Severity", "Title", "URL", "Parameter", "Payload", "Evidence", "Mitigation"])
            
            # Write vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get("type", ""),
                    vuln.get("severity", ""),
                    vuln.get("title", ""),
                    vuln.get("url", ""),
                    vuln.get("parameter", ""),
                    vuln.get("payload", "")[:200],
                    vuln.get("evidence", "")[:200],
                    vuln.get("mitigation", "")[:200]
                ])
            
            # Write tool runs
            writer.writerow([])  # Empty row
            writer.writerow(["Tool Execution Log"])
            writer.writerow(["key", "purpose", "cmd", "status", "duration"])
            for r in runs:
                writer.writerow([
                    r.get("key", ""),
                    r.get("purpose", ""),
                    r.get("cmd", ""),
                    r.get("status", ""),
                    r.get("duration", ""),
                ])
        print(f"    [+] CSV Report: {csv_path}")

    # NO HTML output by default
    # NO JSON output by default

    primary = pdf_path or f"{base}_unavailable.txt"
    return primary
