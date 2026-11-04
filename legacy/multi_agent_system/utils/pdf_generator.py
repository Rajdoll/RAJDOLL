"""
Simple PDF Report Generator using markdown2pdf
Note: For now, we'll just save Markdown. Users can convert to PDF using external tools.
TODO: Implement proper PDF generation using Docker container with wkhtmltopdf
"""

import os
from pathlib import Path


def generate_pdf_report(markdown_content: str, job_id: int, 
                       output_dir: str = "reports") -> str:
    """
    Generate PDF report from Markdown content
    
    For now, this saves the Markdown. Users can convert using:
    - pandoc: pandoc report.md -o report.pdf
    - wkhtmltopdf: wkhtmltopdf report.html report.pdf
    - Online tools: https://www.markdowntopdf.com/
    
    Args:
        markdown_content: Markdown report content
        job_id: Job ID for filename
        output_dir: Output directory path
        
    Returns:
        Path to generated Markdown file (PDF generation TODO)
    """
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # For now, just save Markdown
    output_path = os.path.join(output_dir, f"security_report_job_{job_id}.md")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    
    # TODO: Implement actual PDF generation using Docker container
    # with wkhtmltopdf or similar tool
    
    return output_path


class PDFReportGenerator:
    """Generate PDF reports from Markdown using WeasyPrint"""
    
    # CSS styling for professional PDF reports
    PDF_CSS = """
    @page {
        size: A4;
        margin: 2.5cm 2cm 2cm 2cm;
        
        @top-left {
            content: "OWASP WSTG Security Assessment";
            font-size: 9pt;
            color: #666;
        }
        
        @top-right {
            content: "CONFIDENTIAL";
            font-size: 9pt;
            color: #D32F2F;
            font-weight: bold;
        }
        
        @bottom-center {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 9pt;
            color: #666;
        }
    }
    
    body {
        font-family: 'DejaVu Sans', Arial, sans-serif;
        font-size: 10pt;
        line-height: 1.6;
        color: #333;
        text-align: justify;
    }
    
    h1 {
        color: #1976D2;
        font-size: 24pt;
        font-weight: bold;
        margin-top: 0;
        margin-bottom: 20pt;
        page-break-after: avoid;
        border-bottom: 3pt solid #1976D2;
        padding-bottom: 10pt;
    }
    
    h2 {
        color: #0D47A1;
        font-size: 18pt;
        font-weight: bold;
        margin-top: 30pt;
        margin-bottom: 15pt;
        page-break-after: avoid;
        border-bottom: 2pt solid #0D47A1;
        padding-bottom: 5pt;
    }
    
    h3 {
        color: #1565C0;
        font-size: 14pt;
        font-weight: bold;
        margin-top: 20pt;
        margin-bottom: 10pt;
        page-break-after: avoid;
    }
    
    h4 {
        color: #1976D2;
        font-size: 12pt;
        font-weight: bold;
        margin-top: 15pt;
        margin-bottom: 8pt;
        page-break-after: avoid;
    }
    
    h5 {
        color: #1E88E5;
        font-size: 11pt;
        font-weight: bold;
        margin-top: 12pt;
        margin-bottom: 6pt;
        page-break-after: avoid;
    }
    
    p {
        margin-top: 0;
        margin-bottom: 10pt;
        text-align: justify;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15pt;
        margin-bottom: 15pt;
        page-break-inside: avoid;
    }
    
    th {
        background-color: #1976D2;
        color: white;
        font-weight: bold;
        padding: 10pt;
        text-align: left;
        border: 1pt solid #0D47A1;
    }
    
    td {
        padding: 8pt;
        border: 1pt solid #E0E0E0;
    }
    
    tr:nth-child(even) {
        background-color: #F5F5F5;
    }
    
    code {
        background-color: #F5F5F5;
        padding: 2pt 4pt;
        border-radius: 3pt;
        font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
        font-size: 9pt;
    }
    
    pre {
        background-color: #F5F5F5;
        border-left: 4pt solid #1976D2;
        padding: 10pt;
        overflow-x: auto;
        page-break-inside: avoid;
        font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
        font-size: 9pt;
    }
    
    blockquote {
        border-left: 4pt solid #FF9800;
        padding-left: 15pt;
        margin-left: 0;
        margin-right: 0;
        font-style: italic;
        color: #666;
    }
    
    ul, ol {
        margin-top: 10pt;
        margin-bottom: 10pt;
        padding-left: 20pt;
    }
    
    li {
        margin-bottom: 5pt;
    }
    
    hr {
        border: none;
        border-top: 1pt solid #E0E0E0;
        margin-top: 20pt;
        margin-bottom: 20pt;
    }
    
    .severity-critical {
        color: #D32F2F;
        font-weight: bold;
        background-color: #FFEBEE;
        padding: 2pt 6pt;
        border-radius: 3pt;
    }
    
    .severity-high {
        color: #F57C00;
        font-weight: bold;
        background-color: #FFF3E0;
        padding: 2pt 6pt;
        border-radius: 3pt;
    }
    
    .severity-medium {
        color: #FBC02D;
        font-weight: bold;
        background-color: #FFFDE7;
        padding: 2pt 6pt;
        border-radius: 3pt;
    }
    
    .severity-low {
        color: #388E3C;
        font-weight: bold;
        background-color: #E8F5E9;
        padding: 2pt 6pt;
        border-radius: 3pt;
    }
    
    .severity-informational {
        color: #1976D2;
        font-weight: bold;
        background-color: #E3F2FD;
        padding: 2pt 6pt;
        border-radius: 3pt;
    }
    
    .cover-page {
        text-align: center;
        page-break-after: always;
    }
    
    .cover-page h1 {
        font-size: 32pt;
        margin-top: 100pt;
        border: none;
    }
    
    .cover-page img {
        max-width: 200pt;
        margin: 30pt auto;
    }
    
    .confidential-notice {
        background-color: #FFEBEE;
        border: 2pt solid #D32F2F;
        padding: 15pt;
        margin: 20pt 0;
        text-align: center;
        font-weight: bold;
        color: #D32F2F;
    }
    
    .toc {
        page-break-after: always;
    }
    
    .finding-box {
        border: 1pt solid #E0E0E0;
        padding: 15pt;
        margin: 20pt 0;
        page-break-inside: avoid;
        background-color: #FAFAFA;
    }
    
    .reference-id {
        background-color: #1976D2;
        color: white;
        padding: 2pt 8pt;
        border-radius: 3pt;
        font-family: monospace;
    }
    
    a {
        color: #1976D2;
        text-decoration: none;
    }
    
    a:hover {
        text-decoration: underline;
    }
    
    .page-break {
        page-break-after: always;
    }
    
    /* Appendix styling */
    .appendix {
        page-break-before: always;
    }
    
    /* Warning boxes */
    .warning {
        background-color: #FFF3E0;
        border-left: 4pt solid #FF9800;
        padding: 15pt;
        margin: 15pt 0;
    }
    
    .warning::before {
        content: "⚠️ WARNING: ";
        font-weight: bold;
        color: #F57C00;
    }
    
    /* Info boxes */
    .info {
        background-color: #E3F2FD;
        border-left: 4pt solid #1976D2;
        padding: 15pt;
        margin: 15pt 0;
    }
    
    .info::before {
        content: "ℹ️ INFO: ";
        font-weight: bold;
        color: #1976D2;
    }
    """
    
    def __init__(self):
        """Initialize PDF generator"""
        self.font_config = FontConfiguration()
    
    def markdown_to_pdf(self, markdown_content: str, output_path: str) -> str:
        """
        Convert Markdown to PDF
        
        Args:
            markdown_content: Markdown report content
            output_path: Output PDF file path
            
        Returns:
            Path to generated PDF file
        """
        
        # Convert Markdown to HTML
        html_content = self._markdown_to_html(markdown_content)
        
        # Generate PDF with WeasyPrint
        html = HTML(string=html_content)
        css = CSS(string=self.PDF_CSS, font_config=self.font_config)
        
        # Create output directory if not exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Generate PDF
        html.write_pdf(output_path, stylesheets=[css], font_config=self.font_config)
        
        return output_path
    
    def _markdown_to_html(self, markdown_content: str) -> str:
        """Convert Markdown to HTML with extensions"""
        
        # Markdown extensions for better formatting
        extensions = [
            'markdown.extensions.tables',
            'markdown.extensions.fenced_code',
            'markdown.extensions.codehilite',
            'markdown.extensions.toc',
            'markdown.extensions.nl2br',
            'markdown.extensions.sane_lists',
            'markdown.extensions.smarty',
            'markdown.extensions.attr_list'
        ]
        
        # Convert Markdown to HTML
        html_body = markdown.markdown(
            markdown_content,
            extensions=extensions,
            output_format='html5'
        )
        
        # Wrap in complete HTML document
        html_doc = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP WSTG Security Assessment Report</title>
</head>
<body>
    {html_body}
</body>
</html>
"""
        
        # Post-process: Add severity classes
        html_doc = self._add_severity_styling(html_doc)
        
        return html_doc
    
    def _add_severity_styling(self, html: str) -> str:
        """Add CSS classes for severity levels"""
        severity_mapping = {
            '**CRITICAL**': '<span class="severity-critical">CRITICAL</span>',
            '**HIGH**': '<span class="severity-high">HIGH</span>',
            '**MEDIUM**': '<span class="severity-medium">MEDIUM</span>',
            '**LOW**': '<span class="severity-low">LOW</span>',
            '**INFORMATIONAL**': '<span class="severity-informational">INFORMATIONAL</span>'
        }
        
        for pattern, replacement in severity_mapping.items():
            html = html.replace(pattern, replacement)
        
        return html


def generate_pdf_report(markdown_content: str, job_id: int, 
                       output_dir: str = "reports") -> str:
    """
    Generate PDF report from Markdown content
    
    Args:
        markdown_content: Markdown report content
        job_id: Job ID for filename
        output_dir: Output directory path
        
    Returns:
        Path to generated PDF file
    """
    generator = PDFReportGenerator()
    
    # Create output filename
    output_path = os.path.join(output_dir, f"security_report_job_{job_id}.pdf")
    
    # Generate PDF
    pdf_path = generator.markdown_to_pdf(markdown_content, output_path)
    
    return pdf_path


# Example usage
if __name__ == "__main__":
    # Test PDF generation
    test_markdown = """
# Web Vulnerability Assessment Report

**Target:** http://example.com  
**Date:** January 1, 2025

## Executive Summary

This is a test report with **CRITICAL** severity finding.

### Findings

| ID | Title | Severity |
|----|-------|----------|
| 1 | SQL Injection | **HIGH** |
| 2 | XSS | **MEDIUM** |

## Details

### Finding #1: SQL Injection

**Severity:** **HIGH**

This is a test finding with code:

```python
payload = "' OR 1=1--"
```

**Remediation:** Use prepared statements.
"""
    
    output = generate_pdf_report(test_markdown, 999, "test_reports")
    print(f"PDF generated: {output}")
