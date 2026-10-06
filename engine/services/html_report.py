from datetime import datetime
from typing import Any

def findings_to_html(findings: list[Any]) -> str:
    """Generate an executive compliance HTML report from scan findings."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", "unknown")
        sev_str = str(sev).lower()
        if sev_str in severity_counts:
            severity_counts[sev_str] += 1
            
    total = len(findings)
    grade = "A+"
    if severity_counts["critical"] > 0:
        grade = "F"
    elif severity_counts["high"] > 0:
        grade = "D"
    elif severity_counts["medium"] > 0:
        grade = "C"
    elif severity_counts["low"] > 0:
        grade = "B"

    # Minimal, beautiful HTML template using Tailwind CSS via CDN
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Arbalest Executive Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background-color: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; }}
        .glass {{ background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }}
    </style>
</head>
<body class="p-8">
    <div class="max-w-6xl mx-auto space-y-8">
        <!-- Header -->
        <div class="flex justify-between items-end border-b border-slate-700 pb-4">
            <div>
                <h1 class="text-4xl font-bold bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent">Arbalest</h1>
                <p class="text-slate-400 mt-2">Executive Compliance Report &mdash; {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}</p>
            </div>
            <div class="text-right">
                <p class="text-sm text-slate-400 uppercase tracking-widest">Security Grade</p>
                <p class="text-6xl font-black {"text-green-500" if grade in ("A+", "B") else "text-red-500"}">{grade}</p>
            </div>
        </div>

        <!-- Dashboard Cards -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="glass p-6 rounded-2xl flex flex-col justify-center items-center">
                <p class="text-slate-400 text-sm uppercase tracking-wider mb-2">Total Findings</p>
                <p class="text-5xl font-bold text-white">{total}</p>
            </div>
            <div class="glass p-6 rounded-2xl col-span-2">
                <p class="text-slate-400 text-sm uppercase tracking-wider mb-4">Severity Breakdown</p>
                <div class="flex items-center space-x-6">
                    <div class="text-center"><p class="text-3xl font-bold text-red-500">{severity_counts["critical"]}</p><p class="text-xs text-slate-400 mt-1">CRITICAL</p></div>
                    <div class="text-center"><p class="text-3xl font-bold text-orange-500">{severity_counts["high"]}</p><p class="text-xs text-slate-400 mt-1">HIGH</p></div>
                    <div class="text-center"><p class="text-3xl font-bold text-yellow-500">{severity_counts["medium"]}</p><p class="text-xs text-slate-400 mt-1">MEDIUM</p></div>
                    <div class="text-center"><p class="text-3xl font-bold text-blue-400">{severity_counts["low"]}</p><p class="text-xs text-slate-400 mt-1">LOW</p></div>
                    <div class="text-center"><p class="text-3xl font-bold text-slate-400">{severity_counts["info"]}</p><p class="text-xs text-slate-400 mt-1">INFO</p></div>
                </div>
            </div>
        </div>

        <!-- Compliance Mapping -->
        <div class="glass p-6 rounded-2xl">
            <h2 class="text-xl font-bold mb-4 flex items-center">SOC2 & ISO27001 Mapping</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-700 text-sm text-slate-400">
                            <th class="py-3 font-medium">Finding ID</th>
                            <th class="py-3 font-medium">Severity</th>
                            <th class="py-3 font-medium">CWE</th>
                            <th class="py-3 font-medium">SOC2 Control</th>
                            <th class="py-3 font-medium">ISO 27001</th>
                        </tr>
                    </thead>
                    <tbody class="text-sm">
"""
    
    # Add table rows for findings
    for f in findings:
        f_id = getattr(f, "finding_id", getattr(f, "vulnerability_name", "Unknown"))
        sev = str(getattr(f, "severity", "unknown")).upper()
        cwe = getattr(f, "cwe", "N/A")
        
        # Simple heuristic mapping for demo
        soc2 = "CC7.1 (Vulnerability Management)"
        iso = "A.12.6.1 (Technical Vulnerabilities)"
        if "sql" in f_id.lower() or "injection" in f_id.lower():
            soc2 = "CC6.1 (Logical Access)"
            iso = "A.14.2.1 (Secure Development)"
        elif "secret" in f_id.lower() or "credential" in f_id.lower():
            soc2 = "CC6.1 (Authentication)"
            iso = "A.9.2.1 (User Registration)"
            
        sev_color = "text-slate-400"
        if sev == "CRITICAL":
            sev_color = "text-red-500 font-bold"
        elif sev == "HIGH":
            sev_color = "text-orange-500 font-bold"
        elif sev == "MEDIUM":
            sev_color = "text-yellow-500"
        elif sev == "LOW":
            sev_color = "text-blue-400"
        
        html += f"""
                        <tr class="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                            <td class="py-3 pr-4">{f_id}</td>
                            <td class="py-3 pr-4 {sev_color}">{sev}</td>
                            <td class="py-3 pr-4 text-slate-400">{cwe}</td>
                            <td class="py-3 pr-4">{soc2}</td>
                            <td class="py-3">{iso}</td>
                        </tr>"""

    html += """
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="text-center text-slate-500 text-sm mt-8 pt-4 border-t border-slate-800">
            Generated securely by Arbalest Autonomous DevSecOps Engine.
        </div>
    </div>
</body>
</html>
"""
    return html
