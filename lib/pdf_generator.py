import io
import pandas as pd
from typing import Dict, Any, Optional
from fpdf import FPDF
from datetime import datetime

class OSINTPdfReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.set_text_color(240, 166, 58) # Amber
        self.cell(0, 10, 'OSINT-Scan Intelligence Report', 0, 1, 'L')
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(110, 124, 130) # Text-dim
        self.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Live Network)", 0, 1, 'L')
        self.line(10, 25, 200, 25)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(110, 124, 130)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def safe_str(val: Any) -> str:
    if pd.isna(val) or val is None:
        return "N/A"
    s = str(val).replace("—", "-").replace("✓", "[OK]").replace("⚠", "[!]")
    s = s.replace("\xa0", " ").replace("\t", " ")
    
    # Break any unbroken string longer than 40 chars to prevent FPDF layout crashes
    words = s.split(" ")
    safe_words = []
    for w in words:
        if len(w) > 40:
            chunks = [w[i:i+40] for i in range(0, len(w), 40)]
            safe_words.append(" ".join(chunks))
        else:
            safe_words.append(w)
            
    s = " ".join(safe_words)
    return s.encode('latin-1', 'ignore').decode('latin-1')

def build_pdf_report(
    domain_val: str,
    user_val: str,
    ip_val: str,
    domain_df: pd.DataFrame,
    user_df: pd.DataFrame,
    ip_df: pd.DataFrame,
    risk_result: Dict[str, Any],
    ai_summary: str
) -> bytes:
    """
    Builds a PDF report containing the OSINT sweep data and the Gemini AI summary.
    Returns the raw bytes of the PDF.
    """
    pdf = OSINTPdfReport()
    pdf.add_page()
    
    # 1. TARGET SUMMARY
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(201, 211, 214)
    pdf.cell(0, 8, 'TARGET OVERVIEW', 0, 1, 'L', fill=True)
    pdf.set_fill_color(18, 23, 28)
    
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(0, 0, 0) # Black for actual content to be readable on white PDF bg
    if domain_val: pdf.cell(0, 6, safe_str(f"Domain: {domain_val}"), 0, 1)
    if user_val: pdf.cell(0, 6, safe_str(f"Email/Identity: {user_val}"), 0, 1)
    if ip_val: pdf.cell(0, 6, safe_str(f"IP Address: {ip_val}"), 0, 1)
    pdf.ln(5)

    # 2. RISK SCORE
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'THREAT SEVERITY SCORE', 0, 1, 'L')
    pdf.set_font('Helvetica', 'B', 14)
    
    # Color logic
    level = risk_result['level']
    if level == "CRITICAL":
        pdf.set_text_color(232, 84, 75)
    elif level == "HIGH":
        pdf.set_text_color(255, 120, 73)
    elif level == "MEDIUM":
        pdf.set_text_color(240, 166, 58)
    else:
        pdf.set_text_color(79, 217, 201)
        
    pdf.cell(0, 8, safe_str(f"{risk_result['score']}/100 - {level}"), 0, 1)
    pdf.set_text_color(0, 0, 0)
    
    if risk_result['breakdown']:
        pdf.set_font('Helvetica', '', 10)
        for item in risk_result['breakdown']:
            txt = safe_str(f"- [{item['severity']}] {item['category']}: {item['detail']}")
            if txt.strip():
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(pdf.epw, 6, txt)
    pdf.ln(5)

    # 3. AI SUMMARY (If present)
    if ai_summary and not ai_summary.startswith("⚠️"):
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_text_color(79, 217, 201)
        pdf.cell(0, 10, 'GEMINI AI EXECUTIVE BRIEF', 0, 1, 'L')
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Helvetica', '', 10)
        
        # Super basic markdown parsing for PDF (just handling bold and newlines for now)
        lines = ai_summary.split('\n')
        for line in lines:
            cleaned = line.replace('**', '').replace('###', '').replace('##', '').replace('#', '').strip()
            if not cleaned:
                pdf.ln(3)
                continue
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 6, safe_str(cleaned))
        pdf.ln(5)

    # 4. DATA TABLES
    if not domain_df.empty:
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, 'DOMAIN INFRASTRUCTURE', 0, 1)
        pdf.set_font('Helvetica', '', 9)
        for _, row in domain_df.iterrows():
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 6, safe_str(f"Subdomain: {row['subdomain']} | IP: {row['ip_address']} | ISP: {row.get('isp', 'N/A')}"), 0, 1)
        pdf.ln(5)
        
    if not user_df.empty:
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, 'IDENTITY & BREACH FOOTPRINT', 0, 1)
        pdf.set_font('Helvetica', '', 9)
        for _, row in user_df.iterrows():
            disp = str(row.get('display_name', 'N/A'))
            if len(disp) > 75: disp = disp[:72] + "..."
            txt = safe_str(f"Platform: {row['platform']} | Category: {row['category']} | Name: {disp}")
            if txt.strip():
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(pdf.epw, 6, txt)
        pdf.ln(5)

    # Return bytes
    return bytes(pdf.output(dest='S'))
