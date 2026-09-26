'use strict';

/**
 * Multi-format report exporter for BobGuard.
 * Supports HTML dashboard and Markdown summary formats.
 */

const path = require('path');

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const SEVERITY_COLOR = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#6b7280'
};

const SEVERITY_BG = {
  CRITICAL: '#fee2e2',
  HIGH: '#ffedd5',
  MEDIUM: '#fef3c7',
  LOW: '#f3f4f6'
};

const VERDICT_COLOR = { BLOCK: '#dc2626', WARN: '#d97706', PASS: '#16a34a' };
const VERDICT_BG    = { BLOCK: '#fee2e2', WARN: '#fef3c7', PASS: '#dcfce7' };

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function relPath(filePath) {
  if (!filePath) return '';
  return path.relative(process.cwd(), filePath).replace(/\\/g, '/');
}

function scoreGaugeColor(score) {
  if (score >= 90) return '#16a34a';
  if (score >= 70) return '#d97706';
  return '#dc2626';
}

// ---------------------------------------------------------------------------
// HTML report
// ---------------------------------------------------------------------------

/**
 * Builds an SVG arc score gauge.
 * @param {number} score 0-100
 * @returns {string} inline SVG
 */
function buildScoreGaugeSvg(score) {
  const r = 54;
  const cx = 70;
  const cy = 70;
  const circumference = Math.PI * r; // half-circle
  const pct = Math.max(0, Math.min(1, score / 100));
  const dashOffset = circumference * (1 - pct);
  const color = scoreGaugeColor(score);

  return `<svg width="140" height="90" viewBox="0 0 140 90" xmlns="http://www.w3.org/2000/svg">
  <path d="M16,70 A54,54 0 0,1 124,70" fill="none" stroke="#e5e7eb" stroke-width="12" stroke-linecap="round"/>
  <path d="M16,70 A54,54 0 0,1 124,70" fill="none" stroke="${escHtml(color)}" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset.toFixed(2)}"/>
  <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="700" fill="${escHtml(color)}" font-family="system-ui,sans-serif">${score}</text>
  <text x="70" y="82" text-anchor="middle" font-size="11" fill="#57606a" font-family="system-ui,sans-serif">/100</text>
</svg>`;
}

/**
 * Renders the findings table rows.
 * @param {object[]} findings
 * @returns {string}
 */
function buildFindingsRows(findings) {
  if (findings.length === 0) {
    return `<tr><td colspan="5" style="text-align:center;padding:20px;color:#57606a;">No findings — clean bill of health.</td></tr>`;
  }

  return findings
    .slice()
    .sort((a, b) => {
      const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (ord[a.severity] ?? 9) - (ord[b.severity] ?? 9);
    })
    .map((f) => {
      const sev = f.severity || 'MEDIUM';
      const badge = `<span style="background:${escHtml(SEVERITY_BG[sev])};color:${escHtml(SEVERITY_COLOR[sev])};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">${escHtml(sev)}</span>`;
      const loc = f.type === 'DEPENDENCY'
        ? `${escHtml(f.package || '')}@${escHtml(f.declaredVersion || '')}`
        : `${escHtml(relPath(f.filePath) || '')}:${escHtml(String(f.line || ''))}`;
      const desc = escHtml(f.description || '');
      const fix  = escHtml(f.remediation || f.advisory || '');
      const rule = escHtml(f.ruleId || f.cve || '');

      return `<tr>
  <td>${badge}</td>
  <td style="font-family:monospace;font-size:12px;">${rule}</td>
  <td style="font-family:monospace;font-size:12px;">${loc}</td>
  <td>${desc}</td>
  <td style="font-size:12px;color:#57606a;">${fix}</td>
</tr>`;
    })
    .join('\n');
}

/**
 * Generates a self-contained HTML audit dashboard.
 * @param {object} report  - { target, summary, findings, generatedAt, version }
 * @returns {string} full HTML document
 */
function generateHtmlReport(report) {
  const { summary, findings = [], target = '', generatedAt, version = '0.2.0' } = report;
  const score   = summary.releaseReadinessScore;
  const verdict = summary.verdict;
  const gaugeSvg = buildScoreGaugeSvg(score);
  const findingsRows = buildFindingsRows(findings);

  const owaspRows = [
    ['A01 – Broken Access Control', findings.filter(f => (f.owaspCategory || '').includes('A01')).length],
    ['A02 – Cryptographic Failures', findings.filter(f => (f.owaspCategory || '').includes('A02')).length],
    ['A03 – Injection', findings.filter(f => (f.owaspCategory || '').includes('A03')).length],
    ['A04 – Insecure Design', findings.filter(f => (f.owaspCategory || '').includes('A04')).length],
    ['A08 – Software Integrity', findings.filter(f => (f.owaspCategory || '').includes('A08')).length],
    ['A09 – Logging & Monitoring', findings.filter(f => (f.owaspCategory || '').includes('A09')).length],
  ].map(([cat, cnt]) =>
    `<tr><td>${escHtml(cat)}</td><td style="text-align:right;font-weight:${cnt > 0 ? '700' : '400'};color:${cnt > 0 ? '#dc2626' : '#16a34a'};">${cnt}</td></tr>`
  ).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BobGuard Audit Report</title>
<style>
  *,*::before,*::after{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.6;background:#f7f8fa;color:#1f2328;}
  .wrap{max-width:960px;margin:0 auto;padding:32px 20px;}
  h1{font-size:22px;margin:0 0 4px;}
  .meta{color:#57606a;font-size:12px;margin-bottom:24px;}
  .cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px;}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;flex:1;min-width:160px;}
  .card-title{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#57606a;margin-bottom:8px;}
  .verdict-banner{display:inline-block;padding:4px 18px;border-radius:6px;font-weight:700;font-size:18px;}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;}
  th{background:#f7f8fa;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#57606a;padding:8px 12px;text-align:left;border-bottom:1px solid #e5e7eb;}
  td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;}
  tr:last-child td{border-bottom:none;}
  h2{font-size:15px;margin:28px 0 10px;}
  footer{margin-top:40px;padding-top:12px;border-top:1px solid #e5e7eb;text-align:center;color:#57606a;font-size:11px;}
</style>
</head>
<body>
<div class="wrap">
  <h1>BobGuard Security Audit Report</h1>
  <p class="meta">Target: <code>${escHtml(target)}</code> &nbsp;|&nbsp; Generated: ${escHtml(generatedAt || new Date().toISOString())} &nbsp;|&nbsp; BobGuard v${escHtml(version)}</p>

  <div class="cards">
    <div class="card" style="text-align:center;">
      <div class="card-title">Release Readiness</div>
      ${gaugeSvg}
    </div>
    <div class="card" style="text-align:center;">
      <div class="card-title">Verdict</div>
      <div style="margin-top:16px;">
        <span class="verdict-banner" style="background:${escHtml(VERDICT_BG[verdict])};color:${escHtml(VERDICT_COLOR[verdict])};">${escHtml(verdict)}</span>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Findings by Severity</div>
      <table style="border:none;border-radius:0;">
        <tbody>
          <tr><td>Critical</td><td style="text-align:right;font-weight:700;color:#dc2626;">${summary.bySeverity.CRITICAL}</td></tr>
          <tr><td>High</td><td style="text-align:right;font-weight:700;color:#ea580c;">${summary.bySeverity.HIGH}</td></tr>
          <tr><td>Medium</td><td style="text-align:right;color:#d97706;">${summary.bySeverity.MEDIUM}</td></tr>
          <tr><td>Low</td><td style="text-align:right;color:#6b7280;">${summary.bySeverity.LOW}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-title">OWASP Breakdown</div>
      <table style="border:none;border-radius:0;font-size:12px;">
        <tbody>${owaspRows}</tbody>
      </table>
    </div>
  </div>

  <h2>Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Description</th><th>Remediation</th></tr></thead>
    <tbody>${findingsRows}</tbody>
  </table>

  <footer>Made with IBM Bob</footer>
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

/**
 * Generates a Markdown security summary suitable for PR comments.
 * @param {object} report  - { target, summary, findings, generatedAt, version }
 * @returns {string} Markdown text
 */
function generateMarkdownReport(report) {
  const { summary, findings = [], target = '', generatedAt, version = '0.2.0' } = report;
  const score   = summary.releaseReadinessScore;
  const verdict = summary.verdict;

  const verdictBadge = verdict === 'BLOCK' ? '🔴 BLOCK' : verdict === 'WARN' ? '🟡 WARN' : '🟢 PASS';

  const lines = [
    `# BobGuard Security Audit`,
    ``,
    `| Field | Value |`,
    `|---|---|`,
    `| **Target** | \`${target}\` |`,
    `| **Score** | **${score}/100** |`,
    `| **Verdict** | ${verdictBadge} |`,
    `| **Generated** | ${generatedAt || new Date().toISOString()} |`,
    `| **BobGuard** | v${version} |`,
    ``,
    `## Severity Summary`,
    ``,
    `| Severity | Count |`,
    `|---|---|`,
    `| 🔴 Critical | ${summary.bySeverity.CRITICAL} |`,
    `| 🟠 High | ${summary.bySeverity.HIGH} |`,
    `| 🟡 Medium | ${summary.bySeverity.MEDIUM} |`,
    `| ⚪ Low | ${summary.bySeverity.LOW} |`,
    ``,
  ];

  if (findings.length === 0) {
    lines.push(`## Findings`, ``, `✅ No findings. Clean bill of health.`, ``);
  } else {
    lines.push(`## Findings (${findings.length})`, ``);

    const sorted = findings
      .slice()
      .sort((a, b) => {
        const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return (ord[a.severity] ?? 9) - (ord[b.severity] ?? 9);
      });

    sorted.forEach((f, i) => {
      const sev = f.severity || 'MEDIUM';
      const sevIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '⚪' }[sev] || '⚪';
      const loc = f.type === 'DEPENDENCY'
        ? `\`${f.package}@${f.declaredVersion}\``
        : `\`${relPath(f.filePath) || ''}:${f.line || ''}\``;

      lines.push(
        `### ${i + 1}. ${sevIcon} ${sev} — ${f.ruleId || f.cve || 'Finding'}`,
        ``,
        `- **Location:** ${loc}`,
        `- **Description:** ${f.description || ''}`,
        `- **Remediation:** ${f.remediation || f.advisory || ''}`,
        ``
      );
    });
  }

  lines.push(`---`, `*Made with IBM Bob*`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Write helpers (used by CLI)
// ---------------------------------------------------------------------------

/**
 * Writes a report in the requested format to the given output path.
 * @param {'html'|'md'|'json'|'sarif'} format
 * @param {object} reportData
 * @param {string} outputPath  - absolute path
 * @param {object} [extraDeps] - { writeSarifReport } injected to avoid circular deps
 * @returns {string} output path
 */
function writeReport(format, reportData, outputPath, extraDeps = {}) {
  const fs = require('fs');

  if (format === 'html') {
    const html = generateHtmlReport(reportData);
    fs.writeFileSync(outputPath, html, 'utf8');
    return outputPath;
  }

  if (format === 'md') {
    const md = generateMarkdownReport(reportData);
    fs.writeFileSync(outputPath, md, 'utf8');
    return outputPath;
  }

  if (format === 'sarif') {
    const { writeSarifReport } = extraDeps;
    if (!writeSarifReport) throw new Error('writeSarifReport dep not provided for sarif format');
    const result = writeSarifReport(reportData.findings, outputPath, { repoRoot: reportData._resolvedTarget });
    return result.outputPath;
  }

  // json (default)
  const { _resolvedTarget, ...safeReport } = reportData;
  fs.writeFileSync(outputPath, JSON.stringify(safeReport, null, 2), 'utf8');
  return outputPath;
}

module.exports = {
  generateHtmlReport,
  generateMarkdownReport,
  writeReport
};
