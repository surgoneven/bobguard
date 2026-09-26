'use strict';

const fs = require('fs');
const path = require('path');

const { RULES: STATIC_RULES } = require('./compliance');

const SARIF_SCHEMA_URI =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';

/**
 * Maps BobGuard's internal severity scale to SARIF result.level.
 * SARIF levels: "error" | "warning" | "note" | "none"
 * @param {string} severity
 * @returns {string}
 */
function severityToSarifLevel(severity) {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    default:
      return 'none';
  }
}

/** security-severity score (0.0-10.0) consumed by GitHub Advanced Security. */
function severityToSecurityScore(severity) {
  switch (severity) {
    case 'CRITICAL':
      return '9.5';
    case 'HIGH':
      return '7.5';
    case 'MEDIUM':
      return '5.0';
    case 'LOW':
      return '2.0';
    default:
      return '0.0';
  }
}

/**
 * Builds the SARIF `tool.driver.rules` array from BobGuard's static-analysis
 * rule table plus a synthetic rule for dependency advisories.
 * @returns {object[]}
 */
function buildRuleDescriptors() {
  const staticRuleDescriptors = STATIC_RULES.map((rule) => ({
    id: rule.id,
    name: rule.id.replace(/-/g, '_'),
    shortDescription: { text: rule.description },
    fullDescription: { text: `${rule.owaspCategory}: ${rule.description}` },
    helpUri: 'https://owasp.org/Top10/',
    help: { text: rule.remediation },
    defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
    properties: {
      tags: ['security', 'owasp-top-10', rule.owaspCategory],
      'security-severity': severityToSecurityScore(rule.severity),
      precision: 'medium'
    }
  }));

  const dependencyRuleDescriptor = {
    id: 'BOBGUARD-DEPENDENCY-ADVISORY',
    name: 'vulnerable_dependency',
    shortDescription: { text: 'Vulnerable or outdated dependency declared in package.json' },
    fullDescription: { text: 'Flags dependencies whose declared version is below the known-fixed version for a published advisory.' },
    helpUri: 'https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities',
    help: { text: 'Bump the dependency to the fixed version (or later) shown in the finding message.' },
    defaultConfiguration: { level: 'warning' },
    properties: {
      tags: ['security', 'supply-chain', 'dependencies'],
      precision: 'high'
    }
  };

  return [...staticRuleDescriptors, dependencyRuleDescriptor];
}

/**
 * Converts one BobGuard finding (as produced by compliance.js / analyzer.js)
 * into a SARIF `result` object.
 * @param {object} finding
 * @param {string} repoRoot - absolute path used to compute repo-relative URIs
 * @returns {object}
 */
function findingToSarifResult(finding, repoRoot) {
  const level = severityToSarifLevel(finding.severity);

  if (finding.type === 'STATIC_ANALYSIS') {
    const relativeUri = path.relative(repoRoot, finding.filePath).split(path.sep).join('/');
    return {
      ruleId: finding.ruleId,
      level,
      message: { text: `${finding.description} (${finding.owaspCategory})` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: relativeUri, uriBaseId: 'SRCROOT' },
            region: {
              startLine: finding.line,
              snippet: { text: finding.snippet }
            }
          }
        }
      ],
      properties: {
        severity: finding.severity,
        owaspCategory: finding.owaspCategory,
        remediation: finding.remediation
      }
    };
  }

  // DEPENDENCY finding: attach to package.json with no specific line region.
  return {
    ruleId: 'BOBGUARD-DEPENDENCY-ADVISORY',
    level,
    message: {
      text: `${finding.package}@${finding.declaredVersion} is vulnerable to ${finding.advisory}` +
        (finding.cve ? ` (${finding.cve})` : '') +
        `. Upgrade to >= ${finding.vulnerableBelow}.`
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: 'package.json', uriBaseId: 'SRCROOT' }
        }
      }
    ],
    properties: {
      severity: finding.severity,
      package: finding.package,
      declaredVersion: finding.declaredVersion,
      fixedVersion: finding.vulnerableBelow,
      cve: finding.cve
    }
  };
}

/**
 * Builds a full SARIF v2.1.0 log object from a list of BobGuard findings.
 * @param {object[]} findings - combined DEPENDENCY + STATIC_ANALYSIS findings
 * @param {object} [options]
 * @param {string} [options.repoRoot=process.cwd()] - root used for relative URIs
 * @param {string} [options.toolVersion='0.1.0']
 * @param {string} [options.informationUri]
 * @returns {object} SARIF log
 */
function buildSarifLog(findings, options = {}) {
  const repoRoot = options.repoRoot || process.cwd();
  const toolVersion = options.toolVersion || '0.2.0';
  const informationUri = options.informationUri || 'https://github.com/bobguard/bobguard';

  const results = findings.map((finding) => findingToSarifResult(finding, repoRoot));

  return {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'BobGuard',
            informationUri,
            version: toolVersion,
            organization: 'BobGuard',
            rules: buildRuleDescriptors()
          }
        },
        originalUriBaseIds: {
          SRCROOT: { uri: `file://${repoRoot.split(path.sep).join('/')}/` }
        },
        results,
        columnKind: 'utf16CodeUnits'
      }
    ]
  };
}

/**
 * Builds the SARIF log and writes it to disk as formatted JSON.
 * @param {object[]} findings
 * @param {string} outputPath - absolute or relative path to write
 * @param {object} [options] - forwarded to buildSarifLog
 * @returns {{outputPath: string, resultCount: number}}
 */
function writeSarifReport(findings, outputPath, options = {}) {
  const sarifLog = buildSarifLog(findings, options);
  const resolvedPath = path.resolve(outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(sarifLog, null, 2), 'utf8');
  return { outputPath: resolvedPath, resultCount: sarifLog.runs[0].results.length };
}

module.exports = {
  buildSarifLog,
  writeSarifReport,
  findingToSarifResult,
  severityToSarifLevel,
  severityToSecurityScore
};
