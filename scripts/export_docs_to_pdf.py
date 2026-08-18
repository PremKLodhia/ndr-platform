import os
import subprocess
import markdown
from pathlib import Path

base = Path(r"C:\Users\shivs\Desktop\Projects & Development\ndr-platform")
pdf_dir = base / "docs" / "pdf"
pdf_dir.mkdir(parents=True, exist_ok=True)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

CSS_STYLE = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    @page {
        margin: 20mm 15mm 20mm 15mm;
        size: A4 portrait;
    }

    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #1a202c;
        line-height: 1.6;
        font-size: 10.5pt;
        background-color: #ffffff;
        margin: 0;
        padding: 0;
    }

    h1 {
        font-size: 18pt;
        color: #0f172a;
        border-bottom: 2px solid #3b82f6;
        padding-bottom: 8px;
        margin-top: 24px;
        page-break-after: avoid;
    }

    h2 {
        font-size: 13pt;
        color: #1e293b;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 6px;
        margin-top: 20px;
        page-break-after: avoid;
    }

    h3 {
        font-size: 11pt;
        color: #334155;
        margin-top: 16px;
        page-break-after: avoid;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 16px 0;
        font-size: 9.5pt;
        page-break-inside: avoid;
    }

    th, td {
        border: 1px solid #cbd5e1;
        padding: 7px 10px;
        text-align: left;
    }

    th {
        background-color: #f1f5f9;
        color: #0f172a;
        font-weight: 600;
    }

    tr:nth-child(even) {
        background-color: #f8fafc;
    }

    code {
        font-family: 'JetBrains Mono', Consolas, monospace;
        background-color: #f1f5f9;
        color: #0f172a;
        padding: 2px 4px;
        border-radius: 4px;
        font-size: 9pt;
    }

    pre {
        background-color: #0f172a;
        color: #f8fafc;
        padding: 10px;
        border-radius: 6px;
        overflow-x: auto;
        font-family: 'JetBrains Mono', Consolas, monospace;
        font-size: 8.5pt;
        page-break-inside: avoid;
    }

    pre code {
        background-color: transparent;
        color: #f8fafc;
        padding: 0;
    }

    blockquote {
        border-left: 4px solid #3b82f6;
        background-color: #eff6ff;
        margin: 14px 0;
        padding: 8px 14px;
        border-radius: 0 4px 4px 0;
        color: #1e40af;
    }

    img {
        max-width: 100%;
        height: auto;
        border-radius: 6px;
        margin: 10px 0;
    }

    .page-break {
        page-break-before: always;
    }
</style>
"""


def convert_md_to_pdf(md_path: Path, output_pdf: Path, title: str):
    raw_md = md_path.read_text(encoding="utf-8")
    hero_path = (base / "docs" / "hero-banner.jpg").as_uri()
    raw_md = raw_md.replace('src="docs/hero-banner.jpg"', f'src="{hero_path}"')
    raw_md = raw_md.replace('src="hero-banner.jpg"', f'src="{hero_path}"')

    html_body = markdown.markdown(raw_md, extensions=["tables", "fenced_code", "nl2br", "sane_lists"])
    full_html = f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title>{CSS_STYLE}</head><body>{html_body}</body></html>"

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
    print(f"Generated: {output_pdf.name}")


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

    # Master Whitepaper
    hero_uri = (base / 'docs' / 'hero-banner.jpg').as_uri()
    master_md = f"# Network Detection & Response (NDR) Platform\n## Complete Portfolio & Technical Whitepaper\n\n<p align='center'><img src='{hero_uri}' width='100%' /></p>\n\n"
    for md_file, _, _ in docs:
        if md_file.exists():
            master_md += "\n\n<div class='page-break'></div>\n\n" + md_file.read_text(encoding="utf-8").replace('src="docs/hero-banner.jpg"', f'src="{hero_uri}"').replace('src="hero-banner.jpg"', f'src="{hero_uri}"')

    master_html = markdown.markdown(master_md, extensions=["tables", "fenced_code", "nl2br", "sane_lists"])
    full_master_html = f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>NDR Platform Master Whitepaper</title>{CSS_STYLE}</head><body>{master_html}</body></html>"
    
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


if __name__ == "__main__":
    generate_all()
