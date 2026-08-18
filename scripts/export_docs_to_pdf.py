import os
import subprocess
import markdown
from pathlib import Path
import shutil

base = Path(r"C:\Users\shivs\Desktop\Projects & Development\ndr-platform")
pdf_dir = base / "docs" / "pdf"
pdf_dir.mkdir(parents=True, exist_ok=True)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

DARK_CYBER_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    @page {
        margin: 0;
        size: A4 portrait;
        background-color: #070a12;
    }

    * {
        box-sizing: border-box;
    }

    html, body {
        background-color: #070a12 !important;
        color: #cbd5e1;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        line-height: 1.6;
        font-size: 10pt;
        margin: 0;
        padding: 36px 44px;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
    }

    .doc-header-badge {
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
        font-size: 8.5pt;
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.12);
        border: 1px solid rgba(56, 189, 248, 0.3);
        padding: 3px 10px;
        border-radius: 20px;
        letter-spacing: 1px;
        text-transform: uppercase;
        font-weight: 700;
        margin-bottom: 12px;
    }

    h1 {
        font-size: 20pt;
        font-weight: 800;
        color: #ffffff;
        border-bottom: 2px solid #0284c7;
        padding-bottom: 8px;
        margin-top: 20px;
        margin-bottom: 14px;
        letter-spacing: -0.5px;
        page-break-after: avoid;
    }

    h2 {
        font-size: 13.5pt;
        font-weight: 700;
        color: #38bdf8;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 6px;
        margin-top: 22px;
        margin-bottom: 10px;
        page-break-after: avoid;
    }

    h3 {
        font-size: 11pt;
        font-weight: 700;
        color: #93c5fd;
        margin-top: 16px;
        margin-bottom: 8px;
        page-break-after: avoid;
    }

    p, li {
        color: #94a3b8;
        font-size: 9.5pt;
    }

    strong {
        color: #f1f5f9;
        font-weight: 700;
    }

    a {
        color: #38bdf8;
        text-decoration: none;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 14px 0;
        font-size: 9pt;
        background: #0f172a;
        border-radius: 8px;
        overflow: hidden;
        border: 1px solid #1e293b;
        page-break-inside: avoid;
    }

    th, td {
        border: 1px solid #1e293b;
        padding: 8px 12px;
        text-align: left;
    }

    th {
        background-color: #131d33;
        color: #38bdf8;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        font-size: 8.5pt;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    tr:nth-child(even) {
        background-color: #0b1120;
    }

    tr:hover {
        background-color: #1e293b;
    }

    code {
        font-family: 'JetBrains Mono', Consolas, monospace;
        background-color: #131d33;
        color: #38bdf8;
        padding: 2px 5px;
        border-radius: 4px;
        font-size: 8.5pt;
        border: 1px solid #1e293b;
    }

    pre {
        background-color: #030712 !important;
        border: 1px solid #1e293b;
        color: #e2e8f0;
        padding: 12px 16px;
        border-radius: 8px;
        overflow-x: auto;
        font-family: 'JetBrains Mono', Consolas, monospace;
        font-size: 8.5pt;
        margin: 12px 0;
        page-break-inside: avoid;
    }

    pre code {
        background-color: transparent !important;
        border: none;
        color: #e2e8f0;
        padding: 0;
    }

    blockquote {
        border-left: 4px solid #38bdf8;
        background-color: #0d1a30;
        margin: 14px 0;
        padding: 10px 16px;
        border-radius: 0 8px 8px 0;
        color: #93c5fd;
        border-top: 1px solid #1e293b;
        border-right: 1px solid #1e293b;
        border-bottom: 1px solid #1e293b;
    }

    blockquote strong {
        color: #38bdf8;
    }

    img {
        max-width: 100%;
        height: auto;
        border-radius: 8px;
        margin: 14px 0;
        border: 1px solid #1e293b;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.7);
    }

    .page-break {
        page-break-before: always;
        padding-top: 24px;
    }

    hr {
        border: 0;
        height: 1px;
        background: #1e293b;
        margin: 20px 0;
    }
</style>
"""


def convert_md_to_pdf(md_path: Path, output_pdf: Path, title: str):
    raw_md = md_path.read_text(encoding="utf-8")
    hero_path = (base / "docs" / "hero-banner.jpg").as_uri()
    arch_path = (base / "docs" / "architecture-diagram.png").as_uri()
    
    raw_md = raw_md.replace('src="docs/hero-banner.jpg"', f'src="{hero_path}"')
    raw_md = raw_md.replace('src="hero-banner.jpg"', f'src="{hero_path}"')
    raw_md = raw_md.replace('src="docs/architecture-diagram.png"', f'src="{arch_path}"')
    raw_md = raw_md.replace('src="architecture-diagram.png"', f'src="{arch_path}"')

    html_body = markdown.markdown(raw_md, extensions=["tables", "fenced_code", "nl2br", "sane_lists"])
    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    {DARK_CYBER_CSS}
</head>
<body>
    <div class="doc-header-badge">NDR PLATFORM // TECHNICAL WHITEPAPER</div>
    {html_body}
</body>
</html>
"""

    temp_html = pdf_dir / f"temp_{output_pdf.stem}.html"
    temp_html.write_text(full_html, encoding="utf-8")

    cmd = [
        edge_path,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={str(output_pdf)}",
        str(temp_html)
    ]
    subprocess.run(cmd, check=True)
    temp_html.unlink()
    print(f"Generated Dark Cyber PDF: {output_pdf.name}")


def generate_all():
    docs = [
        (base / "README.md", pdf_dir / "01_NDR_Platform_Overview.pdf", "NDR Platform Overview"),
        (base / "docs" / "architecture.md", pdf_dir / "02_System_Architecture_Design.pdf", "NDR Architecture"),
        (base / "docs" / "results.md", pdf_dir / "03_Empirical_Results_and_Benchmarks.pdf", "Empirical Results"),
        (base / "docs" / "threat-mapping.md", pdf_dir / "04_MITRE_ATTACK_Threat_Mapping.pdf", "MITRE Threat Mapping"),
        (base / "docs" / "live-validation.md", pdf_dir / "05_Live_Lab_Validation_Guide.pdf", "Lab Validation Runbook"),
        (base / "lab" / "network-diagram.md", pdf_dir / "06_Virtual_Lab_Network_Topology.pdf", "Lab Topology"),
    ]

    for md_file, out_pdf, doc_title in docs:
        if md_file.exists():
            convert_md_to_pdf(md_file, out_pdf, doc_title)

    # Master Portfolio Whitepaper PDF
    hero_uri = (base / 'docs' / 'hero-banner.jpg').as_uri()
    arch_uri = (base / 'docs' / 'architecture-diagram.png').as_uri()
    
    master_md = f"# Network Detection & Response (NDR) Platform\\n## Complete Technical Whitepaper & Engineering Specification\\n\\n<p align='center'><img src='{hero_uri}' width='100%' /></p>\\n\\n"
    for md_file, _, _ in docs:
        if md_file.exists():
            txt = md_file.read_text(encoding="utf-8")
            txt = txt.replace('src="docs/hero-banner.jpg"', f'src="{hero_uri}"').replace('src="hero-banner.jpg"', f'src="{hero_uri}"')
            txt = txt.replace('src="docs/architecture-diagram.png"', f'src="{arch_uri}"').replace('src="architecture-diagram.png"', f'src="{arch_uri}"')
            master_md += "\\n\\n<div class='page-break'></div>\\n\\n" + txt

    master_html = markdown.markdown(master_md, extensions=["tables", "fenced_code", "nl2br", "sane_lists"])
    full_master_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>NDR Platform Master Whitepaper</title>
    {DARK_CYBER_CSS}
</head>
<body>
    <div class="doc-header-badge">CYBERSECURITY ENGINEERING SPECIFICATION</div>
    {master_html}
</body>
</html>
"""
    
    temp_master = pdf_dir / "temp_master.html"
    temp_master.write_text(full_master_html, encoding="utf-8")
    master_pdf = pdf_dir / "NDR_Platform_Complete_Portfolio_Whitepaper.pdf"
    
    cmd = [
        edge_path,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={str(master_pdf)}",
        str(temp_master)
    ]
    subprocess.run(cmd, check=True)
    temp_master.unlink()
    print(f"Generated Master PDF: {master_pdf.name}")

    # Copy to prem-portfolio assets
    portfolio_whitepaper = Path(r"C:\Users\shivs\Desktop\Projects & Development\prem-portfolio\assets\NDR_Platform_Whitepaper.pdf")
    shutil.copy2(master_pdf, portfolio_whitepaper)
    print(f"Synced master PDF to portfolio website assets: {portfolio_whitepaper}")


if __name__ == "__main__":
    generate_all()
