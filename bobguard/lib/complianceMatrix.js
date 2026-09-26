'use strict';

/**
 * Enterprise Compliance Attestation Matrix for BobGuard.
 *
 * Maps triggered OWASP findings to regulatory controls across:
 *   - SOC 2 Type II  (AICPA TSC 2017)
 *   - PCI-DSS v4.0   (PCI Security Standards Council)
 *   - ISO/IEC 27001:2022 (Annex A controls)
 */

const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Control catalogue
// ---------------------------------------------------------------------------

/**
 * Full control catalogue.
 * Each entry: { framework, controlId, controlName, description }
 */
const CONTROLS = {
  // SOC 2 Type II
  'SOC2-CC6.1': {
    framework: 'SOC 2 Type II',
    controlId: 'CC6.1',
    controlName: 'Logical and Physical Access Controls',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.'
  },
  'SOC2-CC6.6': {
    framework: 'SOC 2 Type II',
    controlId: 'CC6.6',
    controlName: 'Boundary Protection',
    description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.'
  },
  'SOC2-CC6.8': {
    framework: 'SOC 2 Type II',
    controlId: 'CC6.8',
    controlName: 'Malicious Code Protection',
    description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.'
  },
  'SOC2-CC7.2': {
    framework: 'SOC 2 Type II',
    controlId: 'CC7.2',
    controlName: 'Security Monitoring',
    description: 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity\'s ability to meet its objectives.'
  },
  // PCI-DSS v4.0
  'PCI-6.2.4': {
    framework: 'PCI-DSS v4.0',
    controlId: '6.2.4',
    controlName: 'Injection Attack Prevention',
    description: 'Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks and related vulnerabilities in bespoke and custom software including injection attacks.'
  },
  'PCI-6.3.1': {
    framework: 'PCI-DSS v4.0',
    controlId: '6.3.1',
    controlName: 'Software Vulnerability Management',
    description: 'All security vulnerabilities are identified and addressed in accordance with a defined process.'
  },
  'PCI-3.4': {
    framework: 'PCI-DSS v4.0',
    controlId: '3.4',
    controlName: 'Cryptographic Protection of Account Data',
    description: 'Primary account numbers (PAN) are rendered unreadable anywhere they are stored by using strong cryptography.'
  },
  // ISO/IEC 27001:2022
  'ISO-A.8.28': {
    framework: 'ISO/IEC 27001:2022',
    controlId: 'A.8.28',
    controlName: 'Secure Coding',
    description: 'Secure coding principles shall be applied to software development.'
  },
  'ISO-A.8.24': {
    framework: 'ISO/IEC 27001:2022',
    controlId: 'A.8.24',
    controlName: 'Use of Cryptography',
    description: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.'
  },
  'ISO-A.8.9': {
    framework: 'ISO/IEC 27001:2022',
    controlId: 'A.8.9',
    controlName: 'Configuration Management',
    description: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.'
  }
};

// ---------------------------------------------------------------------------
// Rule → control mapping
// ---------------------------------------------------------------------------

/**
 * Maps a BobGuard ruleId to an array of control IDs it implicates.
 */
const RULE_TO_CONTROLS = {
  'TAINT-SQL-INJECTION':          ['SOC2-CC6.1', 'PCI-6.2.4', 'ISO-A.8.28'],
  'TAINT-COMMAND-INJECTION':      ['SOC2-CC6.1', 'SOC2-CC6.8', 'PCI-6.2.4', 'ISO-A.8.28'],
  'TAINT-CODE-EXECUTION':         ['SOC2-CC6.1', 'SOC2-CC6.8', 'PCI-6.2.4', 'ISO-A.8.28'],
  'TAINT-PATH-TRAVERSAL':         ['SOC2-CC6.1', 'PCI-6.2.4', 'ISO-A.8.28'],
  'TAINT-XSS':                    ['SOC2-CC6.6', 'PCI-6.2.4', 'ISO-A.8.28'],
  'OWASP-A08-MASS-ASSIGNMENT':    ['SOC2-CC6.1', 'PCI-6.2.4', 'ISO-A.8.28'],
  'OWASP-A04-UNVALIDATED-INPUT':  ['SOC2-CC6.1', 'PCI-6.2.4', 'ISO-A.8.28'],
  'OWASP-A02-HARDCODED-SECRET':   ['SOC2-CC6.1', 'PCI-3.4', 'ISO-A.8.24'],
  'OWASP-A09-VERBOSE-ERROR':      ['SOC2-CC7.2', 'PCI-6.3.1', 'ISO-A.8.28'],
  'OWASP-A02-WEAK-CRYPTO':        ['SOC2-CC6.1', 'PCI-3.4', 'ISO-A.8.24'],
  'OWASP-A03-INSECURE-TIMEOUT':   ['SOC2-CC6.8', 'PCI-6.2.4', 'ISO-A.8.28'],
  'OWASP-A02-HIGH-ENTROPY-SECRET':['SOC2-CC6.1', 'PCI-3.4', 'ISO-A.8.24'],
  'OWASP-A09-LOG-SENSITIVE':      ['SOC2-CC7.2', 'PCI-6.3.1', 'ISO-A.8.28'],
  'BOBGUARD-DEPENDENCY-ADVISORY': ['SOC2-CC6.1', 'PCI-6.3.1', 'ISO-A.8.9']
};

// ---------------------------------------------------------------------------
// Matrix builder
// ---------------------------------------------------------------------------

/**
 * Builds the compliance matrix for a given set of findings.
 *
 * Returns per-control status:
 *   FAIL  — at least one finding implicates this control
 *   PASS  — control is in scope but no findings implicate it
 *
 * @param {object[]} findings  - BobGuard findings (DEPENDENCY or STATIC_ANALYSIS)
 * @returns {object[]} array of control attestation rows
 */
function buildComplianceMatrix(findings) {
  // Collect which control IDs are implicated by at least one finding
  const implicated = new Map(); // controlId -> findings[]

  findings.forEach((f) => {
    const ruleId = f.ruleId || 'BOBGUARD-DEPENDENCY-ADVISORY';
    const controlIds = RULE_TO_CONTROLS[ruleId] || [];
    controlIds.forEach((cid) => {
      if (!implicated.has(cid)) implicated.set(cid, []);
      implicated.get(cid).push(f);
    });
  });

  return Object.entries(CONTROLS).map(([cid, ctrl]) => {
    const failingFindings = implicated.get(cid) || [];
    return {
      controlId: cid,
      framework: ctrl.framework,
      id: ctrl.controlId,
      name: ctrl.controlName,
      description: ctrl.description,
      status: failingFindings.length > 0 ? 'FAIL' : 'PASS',
      findingCount: failingFindings.length,
      findings: failingFindings.map((f) => ({
        ruleId: f.ruleId || 'BOBGUARD-DEPENDENCY-ADVISORY',
        severity: f.severity,
        location: f.filePath
          ? `${path.relative(process.cwd(), f.filePath).replace(/\\/g, '/')}:${f.line}`
          : (f.package ? `${f.package}@${f.declaredVersion}` : 'unknown')
      }))
    };
  });
}

// ---------------------------------------------------------------------------
// Markdown attestation document
// ---------------------------------------------------------------------------

const FRAMEWORK_ORDER = ['SOC 2 Type II', 'PCI-DSS v4.0', 'ISO/IEC 27001:2022'];

/**
 * Generates a Markdown compliance attestation document.
 * @param {object[]} matrix  - output of buildComplianceMatrix()
 * @param {{target: string, score: number, verdict: string, generatedAt: string, version: string}} meta
 * @returns {string}
 */
function generateAttestationMarkdown(matrix, meta) {
  const { target, score, verdict, generatedAt, version } = meta;
  const verdictBadge = verdict === 'BLOCK' ? '🔴 BLOCK' : verdict === 'WARN' ? '🟡 WARN' : '🟢 PASS';

  const totalControls = matrix.length;
  const failingControls = matrix.filter((r) => r.status === 'FAIL').length;
  const passingControls = totalControls - failingControls;

  const lines = [
    `# BobGuard Compliance Attestation`,
    ``,
    `> **This document is auto-generated by BobGuard. It provides an evidence-based`,
    `> mapping of security findings to regulatory controls. It is not a substitute for`,
    `> a formal third-party compliance audit.**`,
    ``,
    `## Audit Metadata`,
    ``,
    `| Field | Value |`,
    `|---|---|`,
    `| **Target** | \`${target}\` |`,
    `| **Release Score** | **${score}/100** |`,
    `| **Verdict** | ${verdictBadge} |`,
    `| **Controls Passing** | ${passingControls}/${totalControls} |`,
    `| **Controls Failing** | ${failingControls}/${totalControls} |`,
    `| **Generated** | ${generatedAt} |`,
    `| **BobGuard** | v${version} |`,
    ``
  ];

  // Group by framework
  for (const framework of FRAMEWORK_ORDER) {
    const rows = matrix.filter((r) => r.framework === framework);
    if (rows.length === 0) continue;

    lines.push(`## ${framework}`, ``);
    lines.push(`| Control | Name | Status | Findings |`);
    lines.push(`|---|---|:---:|:---:|`);

    rows.forEach((r) => {
      const statusIcon = r.status === 'PASS' ? '✅ PASS' : '❌ FAIL';
      lines.push(`| \`${r.id}\` | ${r.name} | ${statusIcon} | ${r.findingCount} |`);
    });
    lines.push(``);

    // Detail blocks for failing controls
    rows.filter((r) => r.status === 'FAIL').forEach((r) => {
      lines.push(
        `### ❌ ${r.id} — ${r.name}`,
        ``,
        `> ${r.description}`,
        ``,
        `**Implicated findings:**`,
        ``
      );
      r.findings.forEach((f) => {
        const sevIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '⚪' }[f.severity] || '⚪';
        lines.push(`- ${sevIcon} \`${f.ruleId}\` at \`${f.location}\``);
      });
      lines.push(``);
    });
  }

  lines.push(`---`, `*Made with IBM Bob*`);
  return lines.join('\n');
}

/**
 * Builds a compliance matrix from findings and writes a Markdown attestation doc.
 * @param {object[]} findings
 * @param {string} outputPath
 * @param {{target: string, score: number, verdict: string, generatedAt: string, version: string}} meta
 * @returns {{outputPath: string, matrix: object[], failingControls: number}}
 */
function writeAttestationReport(findings, outputPath, meta) {
  const matrix = buildComplianceMatrix(findings);
  const md = generateAttestationMarkdown(matrix, meta);
  const resolvedOut = path.resolve(outputPath);
  fs.writeFileSync(resolvedOut, md, 'utf8');
  const failingControls = matrix.filter((r) => r.status === 'FAIL').length;
  return { outputPath: resolvedOut, matrix, failingControls };
}

module.exports = {
  CONTROLS,
  RULE_TO_CONTROLS,
  buildComplianceMatrix,
  generateAttestationMarkdown,
  writeAttestationReport
};
