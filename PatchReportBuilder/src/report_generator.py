import os
import logging
from typing import List, Dict, Any
from fpdf import FPDF
from src.risk_ranker import categorize_severity

logger = logging.getLogger(__name__)

def clean_unicode_for_pdf(text: str) -> str:
    """
    Cleans unicode characters (like smart quotes, bullet points, em dashes)
    that are not natively supported by the standard PDF Latin-1/Helvetica encoding.
    """
    if not text:
        return ""
    replacements = {
        "\u201c": '"', "\u201d": '"',  # Smart double quotes
        "\u2018": "'", "\u2019": "'",  # Smart single quotes
        "\u2014": "--", "\u2013": "-", # Em and en dashes
        "\u2022": "*",                 # Bullets
        "\u200b": "",                  # Zero-width space
        "\u00ae": "(R)", "\u2122": "TM", # Registered and Trademark
        "\u2265": ">=", "\u2264": "<="  # Math symbols
    }
    for orig, rep in replacements.items():
        text = text.replace(orig, rep)
    # Convert anything remaining that cannot encode in latin-1 to '?'
    return text.encode("latin-1", errors="replace").decode("latin-1")


class PatchReportPDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        # Top header on every page (except maybe cover page if we had one)
        self.set_font("helvetica", "B", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, "CONFIDENTIAL - AI-POWERED VULNERABILITY REPORT", align="L")
        self.cell(0, 10, "PATCH/VULNERABILITY REPORT BUILDER", align="R")
        self.ln(8)
        # Decorative header line
        self.set_draw_color(200, 200, 200)
        self.line(10, 18, 200, 18)
        self.ln(5)

    def footer(self):
        # Bottom footer on every page
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.set_draw_color(220, 220, 220)
        self.line(10, 280, 200, 280)
        self.cell(0, 10, "Internal Security Report - Generated with PatchReportBuilder", align="L")
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="R")

    def cve_badge(self, severity: str, x: float, y: float):
        """Draws a colored badge indicating vulnerability severity level."""
        severity_colors = {
            "Critical": (217, 83, 79),  # Red
            "High": (253, 126, 20),     # Orange
            "Medium": (240, 173, 78),   # Yellow
            "Low": (92, 184, 92)        # Green
        }
        r, g, b = severity_colors.get(severity, (120, 120, 120))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("helvetica", "B", 9)
        self.rect(x, y - 4, 18, 6, "F")
        self.set_xy(x, y - 4)
        self.cell(18, 6, severity, align="C")


def generate_markdown_report(
    stats: Dict[str, int], 
    top_risks: List[Dict[str, Any]], 
    ai_analyses: Dict[str, Dict[str, str]], 
    executive_summary: str
) -> str:
    """
    Assembles report data into standard Markdown format.
    """
    md = []
    md.append("# AI-Powered Patch & Vulnerability Report")
    md.append("\n## 1. Executive Summary\n")
    md.append(executive_summary)
    
    md.append("\n## 2. Vulnerability Statistics\n")
    md.append(f"- **Total Vulnerabilities Analyzed**: {stats.get('Total', 0)}")
    md.append(f"- **Critical Severity (CVSS >= 9.0)**: {stats.get('Critical', 0)}")
    md.append(f"- **High Severity (7.0 <= CVSS < 9.0)**: {stats.get('High', 0)}")
    md.append(f"- **Medium Severity (4.0 <= CVSS < 7.0)**: {stats.get('Medium', 0)}")
    md.append(f"- **Low Severity (CVSS < 4.0)**: {stats.get('Low', 0)}")
    
    md.append("\n## 3. Top Risk Registry\n")
    md.append("| Rank | CVE ID | CVSS Score | Severity | Published Date |")
    md.append("|---|---|---|---|---|")
    for item in top_risks:
        md.append(
            f"| {item.get('Rank')} | {item.get('CVE_ID')} | {item.get('CVSS_Score')} | "
            f"{item.get('Severity')} | {item.get('Published_Date')} |"
        )
        
    md.append("\n## 4. Detailed Vulnerability Enrichment & AI Analysis\n")
    for item in top_risks:
        cve_id = item.get("CVE_ID")
        analysis = ai_analyses.get(cve_id, {})
        
        md.append(f"### {item.get('Rank')}. {cve_id} (Score: {item.get('CVSS_Score')} - {item.get('Severity')})")
        md.append(f"**NVD Description:** {item.get('Description')}\n")
        
        md.append(f"#### Business Impact\n{analysis.get('business_impact', 'N/A')}\n")
        md.append(f"#### Executive-Friendly Explanation\n{analysis.get('executive_explanation', 'N/A')}\n")
        md.append(f"#### Recommended Remediation\n{analysis.get('remediation', 'N/A')}\n")
        md.append(f"#### Priority Justification\n{analysis.get('priority_justification', 'N/A')}\n")
        
        if item.get("References"):
            md.append("**References:**")
            for ref in item.get("References", [])[:3]:  # Top 3 references
                md.append(f"- [{ref}]({ref})")
            md.append("")
        md.append("---")
        
    return "\n".join(md)


def generate_pdf_report(
    stats: Dict[str, int],
    top_risks: List[Dict[str, Any]],
    ai_analyses: Dict[str, Dict[str, str]],
    executive_summary: str,
    output_path: str
) -> None:
    """
    Generates a professional PDF report and saves it to output_path.
    """
    pdf = PatchReportPDF()
    pdf.alias_nb_pages()
    
    # Page 1: Title and Executive Summary
    pdf.add_page()
    
    # Title Block
    pdf.set_font("helvetica", "B", 22)
    pdf.set_text_color(30, 41, 59) # Slate 800
    pdf.cell(0, 15, "AI-Powered Patch &", ln=True)
    pdf.cell(0, 12, "Vulnerability Report", ln=True)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(100, 116, 139) # Slate 500
    pdf.cell(0, 8, "Generated by Patch/Vulnerability Report Builder", ln=True)
    pdf.ln(5)
    
    # Executive Summary Heading
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.ln(2)
    
    # Write Executive Summary paragraphs
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    
    clean_summary = clean_unicode_for_pdf(executive_summary)
    # Strip markdown headers if any (e.g. ##, #) to keep PDF flow clean
    clean_summary_lines = []
    for line in clean_summary.split("\n"):
        if line.startswith("#"):
            clean_summary_lines.append(line.replace("#", "").strip().upper())
        else:
            clean_summary_lines.append(line)
            
    pdf.multi_cell(0, 5.5, "\n".join(clean_summary_lines))
    pdf.ln(5)
    
    # Page 2: Stats and Top Risks Table
    pdf.add_page()
    
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, "2. Severity Statistics & Key Metrics", ln=True)
    pdf.ln(2)
    
    # Stats metrics grid (drawn as key-value lines)
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(50, 50, 50)
    
    col_width = 85
    pdf.cell(col_width, 8, f"Total Vulnerabilities: {stats.get('Total', 0)}", border=1, align="C")
    # Set text colors or custom cells for counts
    pdf.cell(col_width, 8, f"Critical (CVSS >= 9.0): {stats.get('Critical', 0)}", border=1, align="C")
    pdf.ln(8)
    pdf.cell(col_width, 8, f"High (CVSS >= 7.0): {stats.get('High', 0)}", border=1, align="C")
    pdf.cell(col_width, 8, f"Medium (CVSS >= 4.0): {stats.get('Medium', 0)}", border=1, align="C")
    pdf.ln(8)
    pdf.cell(col_width, 8, f"Low (CVSS < 4.0): {stats.get('Low', 0)}", border=1, align="C")
    pdf.ln(12)
    
    # Table Header
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "3. Top Risk Registry", ln=True)
    pdf.ln(2)
    
    # Table Columns: Rank (15), CVE ID (40), CVSS Score (30), Severity (35), Published (40)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_fill_color(241, 245, 249) # Slate 100
    pdf.set_text_color(51, 65, 85)
    pdf.cell(15, 8, "Rank", border=1, align="C", fill=True)
    pdf.cell(40, 8, "CVE ID", border=1, align="C", fill=True)
    pdf.cell(30, 8, "CVSS Score", border=1, align="C", fill=True)
    pdf.cell(35, 8, "Severity", border=1, align="C", fill=True)
    pdf.cell(45, 8, "Published Date", border=1, align="C", fill=True)
    pdf.ln(8)
    
    # Table Rows
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    
    for item in top_risks:
        # Prevent page break in the middle of a row
        if pdf.get_y() > 250:
            pdf.add_page()
            # Redraw headers
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(15, 8, "Rank", border=1, align="C", fill=True)
            pdf.cell(40, 8, "CVE ID", border=1, align="C", fill=True)
            pdf.cell(30, 8, "CVSS Score", border=1, align="C", fill=True)
            pdf.cell(35, 8, "Severity", border=1, align="C", fill=True)
            pdf.cell(45, 8, "Published Date", border=1, align="C", fill=True)
            pdf.ln(8)
            pdf.set_font("helvetica", "", 10)
            
        pdf.cell(15, 7, str(item.get("Rank")), border=1, align="C")
        pdf.cell(40, 7, clean_unicode_for_pdf(item.get("CVE_ID")), border=1, align="C")
        pdf.cell(30, 7, f"{item.get('CVSS_Score'):.1f}", border=1, align="C")
        
        # Color coding for severity cell
        sev = item.get("Severity")
        pdf.cell(35, 7, sev, border=1, align="C")
        pdf.cell(45, 7, clean_unicode_for_pdf(item.get("Published_Date", "")), border=1, align="C")
        pdf.ln(7)
        
    # Page 3+: Detailed Vulnerability Analysis
    for item in top_risks:
        cve_id = item.get("CVE_ID")
        analysis = ai_analyses.get(cve_id, {})
        
        pdf.add_page()
        
        # Section Header
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 10, f"{item.get('Rank')}. {cve_id}", ln=True)
        
        # Sub-header details
        pdf.set_font("helvetica", "B", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(50, 6, f"CVSS Score: {item.get('CVSS_Score')}", ln=False)
        pdf.cell(50, 6, f"Severity: {item.get('Severity')}", ln=False)
        pdf.cell(50, 6, f"Published: {item.get('Published_Date')}", ln=True)
        pdf.ln(4)
        
        # Description Block
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 6, "NVD Description", ln=True)
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 5, clean_unicode_for_pdf(item.get("Description")))
        pdf.ln(5)
        
        # AI Insight Cards
        cards = [
            ("Business Impact", "business_impact", (239, 246, 255), (59, 130, 246)),  # Light Blue, Blue border
            ("Executive Explanation", "executive_explanation", (248, 250, 252), (100, 116, 139)),  # Light Slate, Slate border
            ("Recommended Remediation", "remediation", (240, 253, 244), (34, 197, 94)),  # Light Green, Green border
            ("Priority Justification", "priority_justification", (254, 242, 242), (239, 68, 68))   # Light Red, Red border
        ]
        
        for title, key, bg_color, border_color in cards:
            text = analysis.get(key, "No analysis generated.")
            clean_text = clean_unicode_for_pdf(text)
            
            # Estimate height needed for this card
            # Standard line is 5 units, let's assume 1 unit space between lines, width is ~180mm. 
            # 180mm fits about 90 Helvetica characters.
            char_count = len(clean_text)
            estimated_lines = (char_count // 85) + 3
            estimated_height = estimated_lines * 5.5 + 8
            
            # Check for page break
            if pdf.get_y() + estimated_height > 260:
                pdf.add_page()
                pdf.set_font("helvetica", "B", 12)
                pdf.set_text_color(30, 41, 59)
                pdf.cell(0, 8, f"{cve_id} Analysis (Continued)", ln=True)
                pdf.ln(2)
                
            y_start = pdf.get_y()
            
            # Header of card
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(border_color[0], border_color[1], border_color[2])
            pdf.cell(0, 6, f"  {title}", ln=True)
            
            # Body text of card
            pdf.set_font("helvetica", "", 9.5)
            pdf.set_text_color(60, 60, 60)
            
            # We want to draw a boundary border around the card
            # Let's temporarily compute multi_cell height by drawing off-screen or using a box
            y_before_text = pdf.get_y()
            pdf.multi_cell(0, 5, f"  {clean_text}")
            y_after_text = pdf.get_y()
            
            # Draw left vertical accent line
            pdf.set_draw_color(border_color[0], border_color[1], border_color[2])
            pdf.set_line_width(0.8)
            pdf.line(12, y_start, 12, y_after_text)
            pdf.ln(4)
            
        # References Section if they exist
        refs = item.get("References", [])
        if refs:
            # Check for page break
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 6, "References", ln=True)
            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(29, 78, 216) # Link blue
            for ref in refs[:3]:
                clean_ref = clean_unicode_for_pdf(ref)
                pdf.cell(0, 4.5, f"- {clean_ref}", ln=True)
                
    # Save the output PDF file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    logger.info(f"PDF report successfully saved to {output_path}")
