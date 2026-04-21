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


def compare_scans(current_findings, prev_findings, current_score=None, prev_score=None):
    """Compara dos listas de findings usando ID único. Calcula impacto y narrativa."""
    if not prev_findings:
        return None
    import re

    _sev    = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4, "info": 5}
    _impact = {"critical": 10, "high": 6, "medium": 3, "low": 1, "review": 0, "info": 0}

    def _key(f):
        return f.get("id") or re.sub(r'\b\d+\b', '#', f.get("title", "").lower().strip())

    curr = {_key(f): f for f in current_findings}
    prev = {_key(f): f for f in prev_findings}

    new_f      = [f for k, f in curr.items() if k not in prev]
    resolved_f = [f for k, f in prev.items() if k not in curr]
    worsened, improved = [], []
    for k in curr:
        if k in prev:
            cs = _sev.get(curr[k].get("severity", "info"), 5)
            ps = _sev.get(prev[k].get("severity", "info"), 5)
            if cs < ps:
                worsened.append({"current": curr[k], "previous": prev[k]})
            elif cs > ps:
                improved.append({"current": curr[k], "previous": prev[k]})

    # Impacto neto: positivo = mejoró, negativo = empeoró
    impact_delta = (
        sum(_impact.get(f["severity"], 0) for f in resolved_f)
        + sum(_impact.get(e["previous"]["severity"], 0) - _impact.get(e["current"]["severity"], 0) for e in improved)
        - sum(_impact.get(f["severity"], 0) for f in new_f)
        - sum(_impact.get(e["current"]["severity"], 0) - _impact.get(e["previous"]["severity"], 0) for e in worsened)
    )

    score_delta = (current_score - prev_score) if (current_score is not None and prev_score is not None) else None
    trend = "improved" if impact_delta > 0 else ("worsened" if impact_delta < 0 else "stable")

    # Narrativa automática
    total = len(new_f) + len(resolved_f) + len(worsened) + len(improved)
    if total == 0:
        narrative = "Sin cambios detectados. El perfil de riesgo permanece estable."
    elif trend == "improved":
        parts = []
        if resolved_f: parts.append(f"se resolvieron {len(resolved_f)} hallazgo(s)")
        if improved:   parts.append(f"{len(improved)} mejoraron de severidad")
        if new_f:      parts.append(f"aunque aparecieron {len(new_f)} nuevo(s)")
        narrative = "La seguridad mejoró: " + ", ".join(parts) + "."
        if score_delta is not None and score_delta < 0:
            narrative += f" El score bajó {abs(score_delta)} puntos."
    elif trend == "worsened":
        parts = []
        if new_f:
            crits = sum(1 for f in new_f if f["severity"] == "critical")
            parts.append(f"{crits} nuevo(s) CRÍTICO(s)" if crits else f"{len(new_f)} nuevo(s) hallazgo(s)")
        if worsened: parts.append(f"{len(worsened)} hallazgo(s) empeoraron de severidad")
        narrative = "La seguridad empeoró: " + ", ".join(parts) + ". Revisar cambios urgentemente."
        if score_delta is not None and score_delta > 0:
            narrative += f" El score subió {score_delta} puntos."
    else:
        narrative = f"Se detectaron {total} cambio(s) con impacto neto neutro."

    return {
        "new":          new_f,
        "resolved":     resolved_f,
        "worsened":     worsened,
        "improved":     improved,
        "impact_delta": impact_delta,
        "score_delta":  score_delta,
        "trend":        trend,
        "narrative":    narrative,
        "prev_score":   prev_score,
        "curr_score":   current_score,
    }


def _build_changes_section(comparison):
    if not comparison:
        return ""

    new_f      = comparison.get("new",          [])
    resolved_f = comparison.get("resolved",      [])
    worsened   = comparison.get("worsened",      [])
    improved   = comparison.get("improved",      [])
    trend      = comparison.get("trend",         "stable")
    narrative  = comparison.get("narrative",     "")
    score_delta = comparison.get("score_delta")
    prev_score  = comparison.get("prev_score")
    curr_score  = comparison.get("curr_score")
    impact      = comparison.get("impact_delta", 0)

    trend_color = {"improved": "#10d48e", "worsened": "#ff3b5c", "stable": "#6a90b8"}[trend]
    trend_icon  = {"improved": "▼ MEJORÓ", "worsened": "▲ EMPEORÓ", "stable": "— ESTABLE"}[trend]

    # Score comparison bar
    score_html = ""
    if prev_score is not None and curr_score is not None:
        delta_txt  = f"+{score_delta}" if score_delta > 0 else str(score_delta)
        delta_col  = "#ff3b5c" if score_delta > 0 else ("#10d48e" if score_delta < 0 else "#6a90b8")
        score_html = f"""
      <div style="display:flex;align-items:center;gap:20px;margin-top:12px;flex-wrap:wrap;">
        <div style="text-align:center;">
          <div style="font-size:10px;color:#6a90b8;letter-spacing:1px;">ANTERIOR</div>
          <div style="font-size:26px;font-weight:800;color:#6a90b8;font-family:'Share Tech Mono',monospace;">{prev_score}</div>
        </div>
        <div style="font-size:20px;color:{delta_col};font-weight:800;">{delta_txt}</div>
        <div style="text-align:center;">
          <div style="font-size:10px;color:#6a90b8;letter-spacing:1px;">ACTUAL</div>
          <div style="font-size:26px;font-weight:800;color:{delta_col};font-family:'Share Tech Mono',monospace;">{curr_score}</div>
        </div>
        <div style="font-size:12px;color:{trend_color};font-weight:700;margin-left:8px;">{trend_icon}</div>
      </div>"""

    def _item(f, color):
        return (f'<div style="margin:3px 0;font-size:12px;">'
                f'<span style="color:{color};font-weight:700;font-size:10px;">[{f["severity"].upper()}]</span>'
                f' <span style="color:#c8d8e8;">{f["title"]}</span></div>')

    def _change_item(entry, arrow, col):
        c, p = entry["current"], entry["previous"]
        return (f'<div style="margin:3px 0;font-size:12px;">'
                f'<span style="color:{SEV_COLOR.get(p["severity"],"#aaa")};font-size:10px;">{p["severity"].upper()}</span>'
                f' <span style="color:{col};">{arrow}</span>'
                f' <span style="color:{SEV_COLOR.get(c["severity"],"#aaa")};font-size:10px;">{c["severity"].upper()}</span>'
                f' <span style="color:#c8d8e8;"> {c["title"]}</span></div>')

    _none = '<div style="color:#3a5a7a;font-size:12px;padding:4px 0;">Ninguno</div>'

    new_html      = "".join(_item(f, "#ff6b35") for f in new_f[:10])      or _none
    resolved_html = "".join(_item(f, "#10d48e") for f in resolved_f[:10]) or _none
    worsened_html = "".join(_change_item(e, "▲", "#ff3b5c") for e in worsened[:5]) or _none
    improved_html = "".join(_change_item(e, "▼", "#10d48e") for e in improved[:5]) or _none

    return f"""
<!-- SECURITY EVOLUTION -->
<div style="padding:28px 40px 0;">
  <div style="font-size:11px;color:#6a90b8;letter-spacing:3px;text-transform:uppercase;
              margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1a3a5c;">
    Security Evolution
  </div>

  <!-- Narrativa + Score -->
  <div style="background:#0c1a2e;border-left:3px solid {trend_color};border-radius:8px;
              padding:18px 22px;margin-bottom:16px;">
    <div style="font-size:11px;color:{trend_color};letter-spacing:2px;margin-bottom:6px;">
      {trend_icon} &nbsp;|&nbsp; Impacto neto: {'+' if impact>0 else ''}{impact}
    </div>
    <p style="color:#c8d8e8;font-size:13px;line-height:1.6;margin:0;">{narrative}</p>
    {score_html}
  </div>

  <!-- Grid de cambios -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div style="background:#0c1a2e;border-radius:8px;padding:14px 18px;">
      <div style="font-size:10px;color:#ff6b35;letter-spacing:2px;margin-bottom:8px;">▲ NUEVOS ({len(new_f)})</div>
      {new_html}
    </div>
    <div style="background:#0c1a2e;border-radius:8px;padding:14px 18px;">
      <div style="font-size:10px;color:#10d48e;letter-spacing:2px;margin-bottom:8px;">✓ RESUELTOS ({len(resolved_f)})</div>
      {resolved_html}
    </div>
    <div style="background:#0c1a2e;border-radius:8px;padding:14px 18px;">
      <div style="font-size:10px;color:#ff3b5c;letter-spacing:2px;margin-bottom:8px;">▲ EMPEORADOS ({len(worsened)})</div>
      {worsened_html}
    </div>
    <div style="background:#0c1a2e;border-radius:8px;padding:14px 18px;">
      <div style="font-size:10px;color:#60a5fa;letter-spacing:2px;margin-bottom:8px;">▼ MEJORADOS ({len(improved)})</div>
      {improved_html}
    </div>
  </div>
</div>"""


def _build_executive_summary(findings, score):
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "review")}

    if counts["critical"] > 0:
        status_label = "ESTADO CRÍTICO"
        status_color = "#ff3b5c"
        status_bg    = "#2a0a10"
        status_icon  = "⛔"
    elif counts["high"] > 0:
        status_label = "EN RIESGO"
        status_color = "#ff6b35"
        status_bg    = "#2a1508"
        status_icon  = "⚠"
    elif counts["medium"] > 0:
        status_label = "PRECAUCIÓN"
        status_color = "#fbbf24"
        status_bg    = "#2a2008"
        status_icon  = "⚡"
    else:
        status_label = "BAJO RIESGO"
        status_color = "#10d48e"
        status_bg    = "#08251a"
        status_icon  = "✅"

    # Impacto general
    impact_parts = []
    titles_low = " ".join(f["title"].lower() for f in findings)
    if "deshabilitado" in titles_low and "logging" in titles_low:
        impact_parts.append("Los eventos de seguridad no están siendo auditados.")
    if "defender" in titles_low and ("deshabilitado" in titles_low or "desactivad" in titles_low):
        impact_parts.append("El sistema carece de protección antimalware activa.")
    if "wdigest" in titles_low:
        impact_parts.append("Las credenciales pueden ser volcadas desde la memoria.")
    if "fuerza bruta" in titles_low or "brute" in titles_low:
        impact_parts.append("Se detecta actividad de fuerza bruta en curso.")
    if "rdp" in titles_low and "nla" in titles_low:
        impact_parts.append("El servicio RDP está expuesto sin autenticación de red.")
    if not impact_parts:
        impact_parts.append("Se detectaron configuraciones que elevan el riesgo del sistema.")

    impact_text = " ".join(impact_parts)

    # Top 5
    top5 = findings[:5]
    top5_html = "".join(
        f'<li style="margin:4px 0;color:{SEV_COLOR.get(f["severity"],"#aaa")};">'
        f'<b>[{f["severity"].upper()}]</b> <span style="color:#e8f4ff">{f["title"]}</span></li>'
        for f in top5
    )

    # Alert banners (critical only)
    alerts_html = ""
    for f in findings:
        if f["severity"] not in ("critical", "high"):
            break
        col = SEV_COLOR.get(f["severity"], "#aaa")
        bg  = SEV_BG.get(f["severity"], "#1a1a1a")
        alerts_html += (
            f'<div style="background:{bg};border-left:4px solid {col};'
            f'padding:10px 18px;margin:6px 0;border-radius:4px;display:flex;align-items:center;gap:14px;">'
            f'<span style="background:{col};color:#000;padding:2px 10px;border-radius:4px;'
            f'font-size:11px;font-weight:800;white-space:nowrap;">{f["severity"].upper()}</span>'
            f'<span style="color:#e8f4ff;font-size:13px;">{f["title"]}</span>'
            f'</div>'
        )

    exec_html = f"""
<!-- EXECUTIVE SUMMARY -->
<div style="padding:32px 40px 0;">
  <div style="font-size:11px;color:#6a90b8;letter-spacing:3px;text-transform:uppercase;
              margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1a3a5c;">
    Executive Summary
  </div>
  <div style="display:flex;gap:24px;align-items:stretch;flex-wrap:wrap;">

    <!-- Status card -->
    <div style="background:{status_bg};border:2px solid {status_color};border-radius:10px;
                padding:28px 32px;min-width:200px;display:flex;flex-direction:column;
                align-items:center;justify-content:center;gap:8px;flex-shrink:0;">
      <div style="font-size:42px;">{status_icon}</div>
      <div style="font-size:16px;font-weight:800;color:{status_color};letter-spacing:2px;
                  font-family:'Share Tech Mono',monospace;">{status_label}</div>
      <div style="font-size:22px;font-weight:800;color:{status_color};
                  font-family:'Share Tech Mono',monospace;">{score}<span style="font-size:13px;"> / 100</span></div>
      <div style="font-size:11px;color:#6a90b8;">Score de riesgo</div>
    </div>

    <!-- Impact + Top 5 -->
    <div style="flex:1;min-width:280px;">
      <div style="background:#0c1a2e;border-radius:8px;padding:18px 22px;margin-bottom:14px;">
        <div style="font-size:11px;color:#6a90b8;letter-spacing:2px;margin-bottom:8px;">IMPACTO GENERAL</div>
        <p style="color:#c8d8e8;font-size:13px;line-height:1.6;">{impact_text}</p>
      </div>
      <div style="background:#0c1a2e;border-radius:8px;padding:18px 22px;">
        <div style="font-size:11px;color:#6a90b8;letter-spacing:2px;margin-bottom:10px;">TOP 5 HALLAZGOS PRIORITARIOS</div>
        <ul style="list-style:none;padding:0;margin:0;font-size:13px;">{top5_html}</ul>
      </div>
    </div>
  </div>
</div>

<!-- ALERTS -->
{"" if not alerts_html else f'''
<div style="padding:24px 40px 0;">
  <div style="font-size:11px;color:#6a90b8;letter-spacing:3px;text-transform:uppercase;
              margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1a3a5c;">
    Alertas activas
  </div>
  {alerts_html}
</div>'''}
"""
    return exec_html


def export_html(findings, score, system_info=None, output_path=None, comparison=None):
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
    for f in findings:
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

{_build_executive_summary(findings, score)}

{_build_changes_section(comparison)}

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