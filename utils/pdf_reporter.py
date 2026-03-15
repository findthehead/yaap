"""
Professional A4 PDF Report Generator
Clean, developer-focused security reports with actionable insights
"""
import os
import re
from datetime import datetime
from fpdf import FPDF


def sanitize_for_pdf(text):
    """Remove Unicode characters that Helvetica font can't render.
    
    Replaces problematic Unicode with ASCII equivalents:
    - All emoji and special symbols → ASCII alternatives
    - Keeps basic text readable
    """
    if not text:
        return ''
    
    text = str(text)
    
    # Unicode → ASCII replacements
    replacements = {
        '⚠': '[!]',      # Warning
        '✓': '[OK]',     # Checkmark
        '✗': '[X]',      # X mark  
        '●': '-',        # Bullet
        '○': 'o',        # Empty bullet
        '▪': '*',        # Square bullet
        '→': '->',       # Arrow
        '←': '<-',       # Left arrow
        '↔': '<->',      # Both arrows
        '☐': '[ ]',      # Checkbox
        '☑': '[X]',      # Checked
        '™': '[TM]',     # Trademark
        '©': '(c)',      # Copyright
        '°': 'deg',      # Degree
        '±': '+/-',      # Plus/minus
        '×': 'x',        # Multiply
        '÷': '/',        # Divide
        '½': '1/2',      # Fraction
        '£': 'GBP',      # Currency
        '€': 'EUR',      # Currency
        '¥': 'JPY',      # Currency
        '…': '.',        # Ellipsis
        ''': "'",        # Quote
        ''': "'",        # Quote
        '"': '"',        # Quote
        '"': '"',        # Quote
        '–': '-',        # En dash
        '—': '--',       # Em dash
    }
    
    for unicode_char, ascii_equiv in replacements.items():
        text = text.replace(unicode_char, ascii_equiv)
    
    # Remove any remaining non-ASCII characters
    text = ''.join(c for c in text if ord(c) < 128 or c == '\n')
    
    return text


class SecurityReportPDF(FPDF):
    """Professional security assessment PDF with A4 format"""
    
    def __init__(self):
        super().__init__(format='A4')  # 210mm x 297mm
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(20, 20, 20)
        
        # Color palette
        self.COLOR_PRIMARY = (0, 51, 102)      # Dark blue
        self.COLOR_SUCCESS = (40, 167, 69)     # Green
        self.COLOR_WARNING = (255, 193, 7)     # Yellow/Amber
        self.COLOR_DANGER = (220, 53, 69)      # Red
        self.COLOR_INFO = (23, 162, 184)       # Cyan
        self.COLOR_GRAY = (108, 117, 125)      # Gray
        self.COLOR_LIGHT_BG = (248, 249, 250)  # Light gray background
        
    def header(self):
        """PDF header with branding"""
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(40, 40, 40)
        self.cell(0, 10, 'yaap Security Assessment', ln=1, align='L')
        self.set_draw_color(200, 200, 200)
        self.line(20, 32, 190, 32)
        self.ln(5)
        
    def footer(self):
        """PDF footer with page numbers"""
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')
        
    def title_page(self, target, test_type, timestamp):
        """Generate professional title page"""
        self.add_page()
        self.set_font('Helvetica', 'B', 28)
        self.set_text_color(0, 51, 102)
        self.ln(60)
        self.cell(0, 20, 'Security Assessment Report', ln=1, align='C')
        
        self.set_font('Helvetica', '', 14)
        self.set_text_color(80, 80, 80)
        self.ln(10)
        self.cell(0, 10, f'Target: {target}', ln=1, align='C')
        self.cell(0, 10, f'Assessment Type: {test_type.upper()}', ln=1, align='C')
        self.cell(0, 10, f'Generated: {timestamp}', ln=1, align='C')
        
        self.ln(80)
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(150, 150, 150)
        self.multi_cell(0, 5, 'This document contains confidential security information. '
                        'Distribution should be limited to authorized personnel only.', align='C')
        
    def section_header(self, title, level=1, color=None):
        """Add section header with optional color"""
        title = sanitize_for_pdf(title)  # Remove Unicode characters
        self.ln(5)
        if color is None:
            color = self.COLOR_PRIMARY if level == 1 else (51, 51, 51)
        
        if level == 1:
            self.set_font('Helvetica', 'B', 18)
            self.set_text_color(*color)
            self.cell(0, 12, title, ln=1)
            self.set_draw_color(*color)
            self.set_line_width(0.5)
            self.line(20, self.get_y(), 190, self.get_y())
            self.ln(2)
        elif level == 2:
            self.set_font('Helvetica', 'B', 14)
            self.set_text_color(*color)
            # Add colored background box
            current_y = self.get_y()
            self.set_fill_color(*self.COLOR_LIGHT_BG)
            self.rect(20, current_y, 170, 8, 'F')
            self.cell(0, 8, title, ln=1)
        else:
            self.set_font('Helvetica', 'B', 12)
            self.set_text_color(*color)
            self.cell(0, 7, '  ' + title, ln=1)
        self.set_text_color(0, 0, 0)
        self.ln(2)
        
    def body_text(self, text, indent=0, bold=False):
        """Add body text with proper formatting"""
        text = sanitize_for_pdf(text)  # Remove Unicode characters
        self.set_font('Helvetica', 'B' if bold else '', 11)
        self.set_text_color(40, 40, 40)
        if indent > 0:
            self.set_x(20 + indent)
        self.multi_cell(0, 6, text)
        
    def bullet_point(self, text, level=0, color=None):
        """Add a bullet point with optional color"""
        text = sanitize_for_pdf(text)  # Remove Unicode characters
        indent = 25 + (level * 10)
        bullet = '-' if level == 0 else 'o' if level == 1 else '*'
        
        self.set_font('Helvetica', '', 11)
        if color:
            self.set_text_color(*color)
        else:
            self.set_text_color(40, 40, 40)
        
        # Add bullet
        self.set_x(indent)
        self.cell(5, 6, bullet)
        
        # Add text with wrapping
        self.set_x(indent + 5)
        current_y = self.get_y()
        self.multi_cell(0, 6, text)
        self.set_text_color(0, 0, 0)
        
    def info_box(self, title, content, box_color=None):
        """Add an information box with title and content"""
        title = sanitize_for_pdf(title)
        content = sanitize_for_pdf(content)
        if box_color is None:
            box_color = self.COLOR_INFO
        
        current_y = self.get_y()
        box_height = 30  # Will adjust based on content
        
        # Draw colored left border
        self.set_fill_color(*box_color)
        self.rect(20, current_y, 3, box_height, 'F')
        
        # Draw light background
        self.set_fill_color(*self.COLOR_LIGHT_BG)
        self.rect(23, current_y, 167, box_height, 'F')
        
        # Add title
        self.set_xy(28, current_y + 3)
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(*box_color)
        self.cell(0, 6, title)
        
        # Add content
        self.set_xy(28, current_y + 10)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(155, 5, content)
        
        self.ln(5)
        self.set_text_color(0, 0, 0)
        
    def vulnerability_box(self, vuln_data):
        """Add formatted vulnerability box with clean, developer-focused information"""
        # Extract vulnerability details and sanitize
        title = sanitize_for_pdf(vuln_data.get('title', 'Unknown Vulnerability'))
        severity = sanitize_for_pdf(vuln_data.get('severity', 'Unknown'))
        url = sanitize_for_pdf(vuln_data.get('url', ''))
        parameter = sanitize_for_pdf(vuln_data.get('parameter', ''))
        payload = sanitize_for_pdf(vuln_data.get('payload', ''))
        evidence = sanitize_for_pdf(vuln_data.get('evidence', ''))
        mitigation = sanitize_for_pdf(vuln_data.get('mitigation', ''))
        
        # Severity color mapping
        severity_colors = {
            'CRITICAL': self.COLOR_DANGER,
            'HIGH': (255, 152, 0),
            'MEDIUM': self.COLOR_WARNING,
            'LOW': self.COLOR_SUCCESS,
            'INFO': self.COLOR_INFO
        }
        color = severity_colors.get(severity.upper(), self.COLOR_GRAY)
        
        current_y = self.get_y()
        
        # Draw left colored border
        self.set_fill_color(*color)
        self.rect(20, current_y, 4, 50, 'F')
        
        # Draw background box
        self.set_fill_color(*self.COLOR_LIGHT_BG)
        self.rect(24, current_y, 166, 50, 'F')
        
        # Severity badge
        self.set_xy(30, current_y + 5)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 10)
        self.cell(25, 6, severity.upper(), 0, 0, 'C', True)
        
        # Title
        self.set_xy(60, current_y + 5)
        self.set_text_color(0, 0, 0)
        self.set_font('Helvetica', 'B', 12)
        self.multi_cell(125, 6, title)
        
        # Reset position for details
        self.set_xy(30, current_y + 14)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        
        # Affected location
        if url:
            self.set_font('Helvetica', 'B', 9)
            self.cell(30, 5, 'Location:', 0, 0)
            self.set_font('Helvetica', '', 9)
            self.multi_cell(0, 5, url[:80] + ('...' if len(url) > 80 else ''))
            self.set_xy(30, self.get_y())
            
        if parameter:
            self.set_font('Helvetica', 'B', 9)
            self.cell(30, 5, 'Parameter:', 0, 0)
            self.set_font('Helvetica', '', 9)
            self.cell(0, 5, parameter, ln=1)
            self.set_xy(30, self.get_y())
            
        # Evidence (clean, no payload display unless critical)
        if evidence:
            self.set_font('Helvetica', 'B', 9)
            self.cell(30, 5, 'Evidence:', 0, 0)
            self.set_font('Helvetica', '', 9)
            # Clean evidence text
            clean_evidence = evidence[:150].replace('\n', ' ')
            self.multi_cell(0, 5, clean_evidence + ('...' if len(evidence) > 150 else ''))
            
        self.ln(8)
        
    def code_block(self, code, language=''):
        """Add code block for technical details (minimal use)"""
        self.set_fill_color(30, 30, 30)
        self.set_text_color(220, 220, 220)
        self.set_font('Courier', '', 8)
        
        # Add small padding
        self.ln(2)
        self.set_x(25)
        # Clean and limit code
        clean_code = str(code).replace('\r', '').strip()
        if len(clean_code) > 300:
            clean_code = clean_code[:300] + '\n...(output truncated)'
        self.multi_cell(160, 4, clean_code, 0, 'L', True)
        self.set_text_color(0, 0, 0)
        self.ln(2)


def generate_professional_pdf(report_data, target, test_type, timestamp):
    """Generate clean, developer-focused PDF report with actionable insights"""
    pdf = SecurityReportPDF()
    pdf.alias_nb_pages()
    
    # Title page
    pdf.title_page(sanitize_for_pdf(target), sanitize_for_pdf(test_type), sanitize_for_pdf(timestamp))
    
    # Extract data
    summary = sanitize_for_pdf(report_data.get('final_summary', 'No summary available'))
    findings = report_data.get('findings', [])
    vulnerabilities = report_data.get('vulnerabilities', [])
    tools_runs = report_data.get('tools_runs', [])
    
    # Parse summary for structured information
    recon_info = extract_recon_info(summary, tools_runs)
    research_info = extract_research_info(summary, tools_runs)
    vulnerability_info = extract_vulnerability_info(summary, findings)
    
    # Executive Summary
    pdf.add_page()
    pdf.section_header('Executive Summary', 1, pdf.COLOR_PRIMARY)
    
    # Add summary statistics box
    vuln_count = len(findings) + len(vulnerabilities)
    if vuln_count > 0:
        pdf.info_box('Security Assessment Result', 
                    f'Found {vuln_count} potential security issue(s) requiring attention.',
                    pdf.COLOR_DANGER)
    else:
        pdf.info_box('Security Assessment Result', 
                    'No critical vulnerabilities identified during this assessment.',
                    pdf.COLOR_SUCCESS)
    
    pdf.body_text(summary[:1000] if isinstance(summary, str) else str(summary)[:1000])
    pdf.ln(5)
    
    # Reconnaissance Findings
    if recon_info:
        pdf.add_page()
        pdf.section_header('Reconnaissance Phase', 1, pdf.COLOR_INFO)
        pdf.body_text('Discovery and enumeration results:', bold=True)
        pdf.ln(3)
        
        if 'technologies' in recon_info:
            pdf.section_header('Identified Technologies', 2, pdf.COLOR_INFO)
            for tech in recon_info['technologies'][:10]:
                pdf.bullet_point(tech, 0, pdf.COLOR_GRAY)
            pdf.ln(3)
        
        if 'endpoints' in recon_info:
            pdf.section_header('Discovered Endpoints', 2, pdf.COLOR_INFO)
            for endpoint in recon_info['endpoints'][:15]:
                pdf.bullet_point(endpoint, 0, pdf.COLOR_GRAY)
            pdf.ln(3)
        
        if 'parameters' in recon_info:
            pdf.section_header('Input Parameters Found', 2, pdf.COLOR_INFO)
            for param in recon_info['parameters'][:10]:
                pdf.bullet_point(param, 0, pdf.COLOR_GRAY)
            pdf.ln(3)
    
    # Research Phase
    if research_info:
        pdf.add_page()
        pdf.section_header('Research Phase', 1, (102, 51, 153))
        pdf.body_text('Intelligence gathering and vulnerability research:', bold=True)
        pdf.ln(3)
        
        if 'attack_surface' in research_info:
            pdf.section_header('Attack Surface Analysis', 2, (102, 51, 153))
            for item in research_info['attack_surface'][:10]:
                pdf.bullet_point(item, 0, pdf.COLOR_GRAY)
            pdf.ln(3)
        
        if 'risk_areas' in research_info:
            pdf.section_header('Potential Risk Areas', 2, pdf.COLOR_WARNING)
            for risk in research_info['risk_areas'][:8]:
                pdf.bullet_point(risk, 0, pdf.COLOR_GRAY)
            pdf.ln(3)
    
    # Vulnerability Findings (if any)
    if findings or vulnerabilities:
        pdf.add_page()
        pdf.section_header('Security Findings', 1, pdf.COLOR_DANGER)
        pdf.body_text('The following security issues were identified and require remediation:', bold=True)
        pdf.ln(5)
        
        # Structured vulnerabilities
        if vulnerabilities:
            for vuln in vulnerabilities[:10]:  # Limit to 10
                pdf.vulnerability_box(vuln)
                pdf.ln(3)
        
        # Text findings
        if findings:
            for idx, finding in enumerate(findings[:10], 1):
                pdf.section_header(f'Finding #{idx}', 3, pdf.COLOR_DANGER)
                # Parse finding for clean display
                clean_finding = clean_finding_text(finding)
                pdf.body_text(clean_finding)
                pdf.ln(4)
    
    # Recommendations
    pdf.add_page()
    pdf.section_header('Remediation Recommendations', 1, pdf.COLOR_SUCCESS)
    pdf.body_text('Priority actions to improve security posture:', bold=True)
    pdf.ln(3)
    
    recommendations = extract_recommendations(summary, findings, vulnerabilities)
    for idx, rec in enumerate(recommendations[:8], 1):
        pdf.bullet_point(f'{rec}', 0, pdf.COLOR_GRAY)
        pdf.ln(2)
    
    return pdf


def extract_recon_info(summary, tools_runs):
    """Extract reconnaissance information from summary"""
    info = {}
    summary_text = str(summary).lower()
    
    # Extract technologies
    tech_keywords = ['apache', 'nginx', 'php', 'python', 'java', 'node.js', 'mysql', 'postgresql', 
                     'redis', 'mongodb', 'wordpress', 'drupal', 'joomla', 'framework', 'library']
    technologies = []
    for keyword in tech_keywords:
        if keyword in summary_text:
            technologies.append(keyword.title())
    if technologies:
        info['technologies'] = list(set(technologies))
    
    # Extract endpoints
    import re
    endpoints = re.findall(r'(/[\w/\-]+(?:\.\w+)?)', str(summary))
    if endpoints:
        info['endpoints'] = list(set([e for e in endpoints if len(e) > 2]))[:15]
    
    # Extract parameters
    params = re.findall(r'\b(\w+)=', str(summary))
    if params:
        info['parameters'] = list(set(params))[:10]
    
    return info


def extract_research_info(summary, tools_runs):
    """Extract research phase information"""
    info = {}
    summary_text = str(summary)
    
    # Extract attack surface mentions
    attack_surface = []
    if 'form' in summary_text.lower():
        attack_surface.append('Interactive forms identified for injection testing')
    if 'api' in summary_text.lower():
        attack_surface.append('API endpoints discovered')
    if 'auth' in summary_text.lower() or 'login' in summary_text.lower():
        attack_surface.append('Authentication mechanisms found')
    if 'upload' in summary_text.lower():
        attack_surface.append('File upload functionality present')
    
    if attack_surface:
        info['attack_surface'] = attack_surface
    
    # Extract risk areas
    risk_areas = []
    if 'user input' in summary_text.lower():
        risk_areas.append('User input handling requires validation')
    if 'sql' in summary_text.lower():
        risk_areas.append('Database interaction points need review')
    if 'xss' in summary_text.lower():
        risk_areas.append('Cross-site scripting protection needed')
    if 'csrf' in summary_text.lower():
        risk_areas.append('CSRF token implementation required')
    
    if risk_areas:
        info['risk_areas'] = risk_areas
    
    return info


def extract_vulnerability_info(summary, findings):
    """Extract vulnerability details"""
    # This is handled by the findings parameter
    return findings


def clean_finding_text(finding):
    """Clean finding text for professional display"""
    if not finding:
        return ''
    
    # Remove excessive newlines
    finding = re.sub(r'\n{3,}', '\n\n', str(finding))
    
    # Remove tool command outputs
    finding = re.sub(r'Command:.*?\n', '', finding)
    finding = re.sub(r'cmd:.*?\n', '', finding)
    
    # Remove excessive technical jargon
    finding = finding.replace('key:', '').replace('output:', '')
    
    # Limit length
    if len(finding) > 500:
        finding = finding[:500] + '...'
    
    return finding.strip()


def extract_recommendations(summary, findings, vulnerabilities):
    """Extract actionable recommendations"""
    recommendations = []
    summary_text = str(summary).lower()
    
    # Generic security recommendations
    if findings or vulnerabilities:
        recommendations.append('Implement input validation and sanitization on all user inputs')
        recommendations.append('Use parameterized queries to prevent SQL injection')
        recommendations.append('Apply Content Security Policy (CSP) headers')
        recommendations.append('Enable security headers (X-Frame-Options, X-Content-Type-Options)')
    
    # Specific recommendations based on findings
    if 'xss' in summary_text:
        recommendations.append('Encode output data before rendering in HTML context')
    if 'sql' in summary_text or 'injection' in summary_text:
        recommendations.append('Review database query construction and use prepared statements')
    if 'auth' in summary_text:
        recommendations.append('Strengthen authentication mechanisms and session management')
    if 'csrf' in summary_text:
        recommendations.append('Implement anti-CSRF tokens on state-changing operations')
    
    # Always include
    recommendations.append('Conduct regular security assessments and code reviews')
    recommendations.append('Keep all frameworks and dependencies updated')
    recommendations.append('Implement Web Application Firewall (WAF) for additional protection')
    
    return list(set(recommendations))[:10]
