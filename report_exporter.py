"""
report_exporter.py
Genera reportes profesionales en HTML, JSON y TXT.
"""
import json
from datetime import datetime
from pathlib import Path


SEV_COLOR = {
    "critical": "#ff3b5c",
    "high":     "#ff6b35",
    "medium":   "#fbbf24",
    "low":      "#10d48e",
    "review":   "#60a5fa",
    "info":     "#00d4ff",
}

SEV_BG = {
    "critical": "#3a0d18",
    "high":     "#3a1a0d",
    "medium":   "#3a2d0d",
    "low":      "#0d3a28",
    "review":   "#0d1f3a",
    "info":     "#0d2a3a",
}


def export_html(findings, score, system_info=None, output_path=None):
    """Genera un reporte HTML profesional."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = (system_info or {}).get("hostname", "Desconocido")
    os_name = (system_info or {}).get("os", "Windows")
    os_ver  = (system_info or {}).get("version", "")

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "review")}

    score_color = ("#10d48e" if score <= 30
                   else "#fbbf24" if score <= 60
                   else "#ff3b5c")

    # ── finding rows ──
    rows_html = ""
    for i, f in enumerate(findings):
        sev   = f["severity"]
        color = SEV_COLOR.get(sev, "#aaa")
        bg    = SEV_BG.get(sev, "#1a1a1a")
        mitre = ", ".join(f.get("mitre", [])) or "—"
        rows_html += f"""
        <tr style="background:{bg}; border-bottom:1px solid #1a3a5c;">
          <td style="padding:10px 14px;">
            <span style="background:{color};color:#000;padding:2px 8px;
                  border-radius:4px;font-size:11px;font-weight:700;">
              {sev.upper()}
            </span>
          </td>
          <td style="padding:10px 14px;color:#e8f4ff;font-weight:600;">{f['title']}</td>
          <td style="padding:10px 14px;color:#6a90b8;font-size:12px;word-break:break-all;">{f['details']}</td>
          <td style="padding:10px 14px;color:#10d48e;font-size:12px;">{f['recommendation']}</td>
          <td style="padding:10px 14px;color:#00d4ff;font-size:11px;">{mitre}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {host}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');
  *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#060d18; color:#e8f4ff; font-family:'Exo 2',sans-serif;
          min-height:100vh; }}

  /* ── TOP BAR ── */
  .topbar {{ background:#0c1a2e; border-bottom:2px solid #00d4ff;
             padding:16px 40px; display:flex; align-items:center;
             justify-content:space-between; }}
  .topbar h1 {{ font-family:'Share Tech Mono',monospace; color:#00d4ff;
                font-size:20px; letter-spacing:3px; }}
  .topbar .meta {{ color:#6a90b8; font-size:13px; font-family:'Share Tech Mono',monospace; }}

  /* ── HERO SCORE ── */
  .hero {{ background:linear-gradient(135deg,#0c1a2e 0%,#060d18 100%);
           padding:50px 40px; display:flex; align-items:center; gap:60px;
           border-bottom:1px solid #1a3a5c; }}
  .score-ring {{ position:relative; width:160px; height:160px; flex-shrink:0; }}
  .score-ring svg {{ width:160px; height:160px; }}
  .score-ring .num {{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%);
                      font-size:38px; font-weight:800; color:{score_color};
                      font-family:'Share Tech Mono',monospace; }}
  .score-ring .lbl {{ position:absolute; bottom:8px; left:50%; transform:translateX(-50%);
                      font-size:10px; color:#6a90b8; letter-spacing:2px; }}
  .hero-info h2 {{ font-size:30px; font-weight:800; color:#e8f4ff; margin-bottom:6px; }}
  .hero-info p  {{ color:#6a90b8; font-size:14px; margin-bottom:20px;
                   font-family:'Share Tech Mono',monospace; }}

  /* ── CARDS ── */
  .cards {{ display:flex; gap:16px; margin-top:24px; flex-wrap:wrap; }}
  .card {{ background:#0f2340; border:1px solid #1a3a5c; border-radius:8px;
           padding:16px 22px; min-width:120px; }}
  .card .val {{ font-size:32px; font-weight:800; font-family:'Share Tech Mono',monospace; }}
  .card .lbl {{ font-size:11px; color:#6a90b8; letter-spacing:1px; margin-top:4px; }}

  /* ── SECTION ── */
  .section {{ padding:40px; }}
  .section-title {{ font-size:13px; color:#6a90b8; letter-spacing:3px;
                    text-transform:uppercase; margin-bottom:20px;
                    padding-bottom:8px; border-bottom:1px solid #1a3a5c; }}

  /* ── TABLE ── */
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  thead tr {{ background:#0c1a2e; }}
  thead th {{ padding:12px 14px; text-align:left; color:#6a90b8;
              font-size:11px; letter-spacing:2px; font-weight:600; }}
  tbody tr:hover {{ filter:brightness(1.1); }}

  /* ── FOOTER ── */
  .footer {{ text-align:center; padding:30px; color:#2a4a6a;
             font-family:'Share Tech Mono',monospace; font-size:11px;
             border-top:1px solid #1a3a5c; }}

  /* ── SYSTEM INFO ── */
  .sysinfo {{ display:flex; gap:30px; flex-wrap:wrap; padding:0 40px 30px; }}
  .sysinfo-item {{ background:#0c1a2e; border:1px solid #1a3a5c; border-radius:6px;
                   padding:12px 20px; }}
  .sysinfo-item .k {{ font-size:10px; color:#6a90b8; letter-spacing:2px; }}
  .sysinfo-item .v {{ font-size:14px; color:#e8f4ff; margin-top:4px;
                      font-family:'Share Tech Mono',monospace; }}
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <h1>⬡ WINDOWS VULN SCANNER — SECURITY REPORT</h1>
  <div class="meta">Generado: {now}</div>
</div>

<!-- HERO -->
<div class="hero">
  <div class="score-ring">
    <svg viewBox="0 0 160 160">
      <circle cx="80" cy="80" r="65" fill="none" stroke="#1a3a5c" stroke-width="10"/>
      <circle cx="80" cy="80" r="65" fill="none" stroke="{score_color}" stroke-width="10"
              stroke-dasharray="{int(score * 4.08)} 408"
              stroke-linecap="round" transform="rotate(-90 80 80)"/>
    </svg>
    <div class="num">{score}</div>
    <div class="lbl">RIESGO</div>
  </div>
  <div class="hero-info">
    <h2>Reporte de Seguridad</h2>
    <p>{host} &nbsp;|&nbsp; {os_name} {os_ver}</p>
    <div class="cards">
      <div class="card">
        <div class="val" style="color:#ff3b5c">{counts['critical']}</div>
        <div class="lbl">CRÍTICOS</div>
      </div>
      <div class="card">
        <div class="val" style="color:#ff6b35">{counts['high']}</div>
        <div class="lbl">ALTOS</div>
      </div>
      <div class="card">
        <div class="val" style="color:#fbbf24">{counts['medium']}</div>
        <div class="lbl">MEDIOS</div>
      </div>
      <div class="card">
        <div class="val" style="color:#10d48e">{counts['low']}</div>
        <div class="lbl">BAJOS</div>
      </div>
      <div class="card">
        <div class="val" style="color:#60a5fa">{counts['review']}</div>
        <div class="lbl">REVIEW</div>
      </div>
      <div class="card">
        <div class="val" style="color:#e8f4ff">{len(findings)}</div>
        <div class="lbl">TOTAL</div>
      </div>
    </div>
  </div>
</div>

<!-- SYSTEM INFO -->
{''.join([f"""
<div class="sysinfo">
  <div class="sysinfo-item"><div class="k">HOSTNAME</div><div class="v">{system_info.get('hostname','—')}</div></div>
  <div class="sysinfo-item"><div class="k">SISTEMA OPERATIVO</div><div class="v">{system_info.get('os','—')} {system_info.get('version','')}</div></div>
  <div class="sysinfo-item"><div class="k">ARQUITECTURA</div><div class="v">{system_info.get('arch','—')}</div></div>
  <div class="sysinfo-item"><div class="k">ÚLTIMO ARRANQUE</div><div class="v">{system_info.get('last_boot','—')}</div></div>
  <div class="sysinfo-item"><div class="k">FECHA DE ESCANEO</div><div class="v">{system_info.get('scan_time', now)}</div></div>
</div>"""] if system_info else [])}

<!-- FINDINGS TABLE -->
<div class="section">
  <div class="section-title">Hallazgos de seguridad ({len(findings)})</div>
  <table>
    <thead>
      <tr>
        <th>SEVERIDAD</th>
        <th>HALLAZGO</th>
        <th>DETALLE</th>
        <th>RECOMENDACIÓN</th>
        <th>MITRE ATT&CK</th>
      </tr>
    </thead>
    <tbody>
      {rows_html if rows_html else '<tr><td colspan="5" style="text-align:center;padding:30px;color:#6a90b8;">✅ Sin hallazgos detectados</td></tr>'}
    </tbody>
  </table>
</div>

<!-- FOOTER -->
<div class="footer">
  Windows Vuln Scanner v2.0 PRO &nbsp;•&nbsp; SOC Edition &nbsp;•&nbsp;
  Uso exclusivo en entornos autorizados &nbsp;•&nbsp; {now}
</div>

</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    return html


def export_json(findings, score, system_info=None, output_path=None):
    report = {
        "tool":           "Windows Vuln Scanner v2.0 PRO",
        "generated":      datetime.now().isoformat(),
        "system":         system_info or {},
        "score":          score,
        "total_findings": len(findings),
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high":     sum(1 for f in findings if f["severity"] == "high"),
            "medium":   sum(1 for f in findings if f["severity"] == "medium"),
            "low":      sum(1 for f in findings if f["severity"] == "low"),
            "review":   sum(1 for f in findings if f["severity"] == "review"),
        },
        "findings": findings
    }
    out = json.dumps(report, indent=2, ensure_ascii=False)
    if output_path:
        Path(output_path).write_text(out, encoding="utf-8")
    return out


def export_txt(findings, score, system_info=None, output_path=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        "  WINDOWS VULN SCANNER v2.0 PRO — REPORTE DE SEGURIDAD",
        "=" * 70,
        f"  Fecha    : {now}",
        f"  Host     : {(system_info or {}).get('hostname', '—')}",
        f"  SO       : {(system_info or {}).get('os', '—')}",
        f"  Score    : {score}/100",
        f"  Total    : {len(findings)} hallazgo(s)",
        "=" * 70,
        "",
    ]
    for f in findings:
        lines += [
            f"[{f['severity'].upper()}] {f['title']}",
            f"  Detalle        : {f['details']}",
            f"  Recomendación  : {f['recommendation']}",
            f"  MITRE          : {', '.join(f.get('mitre', [])) or '—'}",
            "-" * 70,
        ]
    out = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(out, encoding="utf-8")
    return out