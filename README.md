# 🛡️ BobGuard

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Tests](https://img.shields.io/badge/tests-145%2F145%20passed-brightgreen)
![Audit Score](https://img.shields.io/badge/audit%20score-100%2F100-brightgreen)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20Coverage-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **Autonomous AST static security analysis engine & compliance CLI for Node.js microservices.**
> Real-time taint analysis, automated patch remediation, CycloneDX SBOM generation, SARIF export, and enterprise compliance attestation — wired directly into your development workflow.

---

## Summary

<img width="940" height="646" alt="bobguard-summary1" src="https://github.com/user-attachments/assets/e2b8bcc7-7fc2-4e3f-861f-09f70b2f93a2" />

<img width="933" height="116" alt="bobguard-summary2" src="https://github.com/user-attachments/assets/70c69aac-2a3f-42b8-8cf9-70b1c961351d" />


---

## Architecture

```
┌────────────────┐      ┌─────────────────┐      ┌──────────────────┐
│ Source Code    │ ───► │ ESTree AST       │ ───► │ Taint Analysis   │
│ (JavaScript)   │      │ Parser (Babel)   │      │ Engine           │
└────────────────┘      └─────────────────┘      └────────┬─────────┘
                                                           │
┌────────────────┐      ┌─────────────────┐               │
│ SARIF / HTML   │ ◄─── │ Auto-Fixer      │ ◄─────────────┘
│ Output Reports │      │ Engine          │
└────────────────┘      └─────────────────┘
```

The engine performs two sequential AST traversals per file. The first pre-pass builds a function-level taint-transfer summary (recognising sanitizer helpers), and the second performs a full source-to-[...]

---

## Features

| Capability | Detail |
|---|---|
| **AST Taint Engine** | Scope-aware, inter-procedural dataflow tracking via `@babel/traverse` |
| **OWASP Top 10 (2021)** | 13 rules covering A01–A09: SQLi, XSS, path traversal, command injection, hardcoded secrets, weak crypto, mass assignment, verbose errors, insecure timeouts, and more |
| **Auto-Fixer** | Targeted AST/string patches for SQLi, mass assignment, weak crypto, insecure timeouts, and sensitive log calls |
| **Interactive Fix Mode** | `bobguard fix --interactive`: diff preview + per-patch Y/n confirmation before writing |
| **Multi-format Reports** | JSON, HTML dashboard, Markdown (PR-ready), SARIF v2.1.0 |
| **CycloneDX SBOM** | v1.5 JSON with PURL identifiers, dependency graph, and transitive components from `package-lock.json` |
| **Compliance Attestation** | SOC 2 Type II, PCI-DSS v4.0, and ISO/IEC 27001:2022 control mapping from findings |
| **CI Integration** | GitHub Actions workflow with SARIF upload to GitHub Advanced Security |
| **Git Hook Installer** | `bobguard init` writes a pre-commit hook and VS Code `tasks.json` in one command |
| **Release Pipeline** | End-to-end `audit → fix → test → SARIF → verdict` with regression guard |

---

## Quick Start

### Prerequisites

- Node.js ≥ 16
- npm ≥ 8

### Install

```bash
cd bobguard
npm install
```

### Run your first audit

```bash
# Audit a target microservice (prints findings to stdout)
node bobguard/bin/bobguard.js audit ./demo-app

# Generate an HTML dashboard
node bobguard/bin/bobguard.js audit ./demo-app --format html --out audit-report.html

# Generate a Markdown summary (for PR comments)
node bobguard/bin/bobguard.js audit ./demo-app --format md --out SECURITY.md

# Generate a SARIF report (for GitHub Code Scanning)
node bobguard/bin/bobguard.js audit ./demo-app --format sarif --out results.sarif.json
```

---

## CLI Reference

### `bobguard audit <targetDir>`

Scans a directory for dependency advisories and OWASP Top 10 static findings.

| Option | Description |
|---|---|
| `-t, --target <dir>` | Target directory (alternative to positional argument) |
| `-f, --format <fmt>` | Output format: `json` \| `html` \| `md` \| `sarif` |
| `-o, --out <file>` | Output file path (default name derived from format) |
| `--sbom [file]` | Generate a CycloneDX v1.5 SBOM (default: `bom.json`) |
| `--attestation [file]` | Generate a compliance attestation document (default: `compliance-matrix.md`) |

**Example — full enterprise audit:**

```bash
node bobguard/bin/bobguard.js audit ./demo-app \
  --format html --out audit-report.html \
  --sbom bom.json \
  --attestation compliance-matrix.md
```

---

### `bobguard report <targetDir>`

Runs an audit and writes a compliance report to disk.

| Option | Description |
|---|---|
| `-f, --format <fmt>` | `json` \| `html` \| `md` \| `sarif` (default: `json`) |
| `-o, --output <file>` | Output file path |

---

### `bobguard fix <targetDir>`

Applies automated source patches and re-runs the test suite.

| Option | Description |
|---|---|
| `-i, --interactive` | Preview each diff and confirm before writing |

**Patchers included:**

- SQL injection → parameterised queries
- Mass assignment → server-side role assignment
- Weak crypto → `sha256` replacement for `md5`/`sha1`
- Insecure `setTimeout`/`setInterval` string args → arrow-function wrappers
- Sensitive console log arguments → `sanitize()` wrapper injection
- Outdated `package.json` dependency versions → patched to known-safe versions

---

### `bobguard release <targetDir>`

Full pipeline: `pre-fix audit → auto-fix → regression test → post-fix audit → SARIF export → release verdict`.

| Option | Description |
|---|---|
| `-o, --output <file>` | SARIF output path (default: `bobguard-results.sarif.json`) |

**Verdict logic:**

| Verdict | Condition |
|---|---|
| `PASS` | Score 100/100, no findings, tests green |
| `WARN` | HIGH findings present (no CRITICAL) — human sign-off required |
| `BLOCK` | CRITICAL findings present **or** post-fix test regression |

---

### `bobguard init`

Installs developer tooling into the workspace.

| Option | Description |
|---|---|
| `--workspace <dir>` | Workspace root (default: `.`) |
| `--target <dir>` | Microservice path used in generated commands (default: `./demo-app`) |

**What it creates:**

- `.git/hooks/pre-commit` — runs `bobguard audit` before every commit; blocks on findings
- `.vscode/tasks.json` — three tasks registered under `Ctrl+Shift+B`:
  - **BobGuard: Security Scan** (default build task)
  - **BobGuard: Generate SBOM**
  - **BobGuard: Compliance Attestation**

---

## OWASP Top 10 Coverage

| Rule ID | Category | Severity | Description |
|---|---|---|---|
| `TAINT-SQL-INJECTION` | A03 – Injection | 🔴 CRITICAL | User input flows into a SQL query without parameterisation |
| `TAINT-COMMAND-INJECTION` | A03 – Injection | 🔴 CRITICAL | Tainted data passed to `exec`/`spawn`/`execFile` |
| `TAINT-CODE-EXECUTION` | A03 – Injection | 🟠 HIGH | `eval()` or `new Function()` called with a non-literal argument |
| `TAINT-PATH-TRAVERSAL` | A01 – Broken Access Control | 🟠 HIGH | Tainted path used in `fs.*` calls |
| `TAINT-XSS` | A03 – Injection | 🟡 MEDIUM | Tainted data written to HTTP response without escaping |
| `OWASP-A08-MASS-ASSIGNMENT` | A08 – Integrity Failures | 🟠 HIGH | Privileged field read directly from request input |
| `OWASP-A04-UNVALIDATED-INPUT` | A04 – Insecure Design | 🟡 MEDIUM | Request input used without a validation guard |
| `OWASP-A02-HARDCODED-SECRET` | A02 – Cryptographic Failures | 🟠 HIGH | Credential or secret literal in source |
| `OWASP-A09-VERBOSE-ERROR` | A09 – Logging Failures | ⚪ LOW | Raw error details returned in HTTP response |
| `OWASP-A02-WEAK-CRYPTO` | A02 – Cryptographic Failures | 🟠 HIGH | MD5 / SHA-1 / `Math.random()` in security-sensitive context |
| `OWASP-A03-INSECURE-TIMEOUT` | A03 – Injection | 🟠 HIGH | `setTimeout`/`setInterval` called with a string argument (implicit eval) |
| `OWASP-A02-HIGH-ENTROPY-SECRET` | A02 – Cryptographic Failures | 🔴 CRITICAL | JWT, AWS AKIA key, Stripe key, or high-entropy base64 blob in source |
| `OWASP-A09-LOG-SENSITIVE` | A09 – Logging Failures | 🟡 MEDIUM | Raw `req.body`, password, or auth header passed to `console.*` |

---

## Compliance Frameworks

`bobguard audit --attestation` maps every triggered finding to its regulatory controls:

| Framework | Controls Covered |
|---|---|
| **SOC 2 Type II** | CC6.1 (Logical Access), CC6.6 (Boundary Protection), CC6.8 (Malicious Code), CC7.2 (Monitoring) |
| **PCI-DSS v4.0** | 6.2.4 (Injection Prevention), 6.3.1 (Vulnerability Management), 3.4 (Cryptographic Protection) |
| **ISO/IEC 27001:2022** | A.8.28 (Secure Coding), A.8.24 (Cryptography), A.8.9 (Configuration Management) |

The attestation document is a Markdown file suitable for inclusion in an audit evidence package.

---

## SBOM Generation

```bash
node bobguard/bin/bobguard.js audit ./demo-app --sbom bom.json
```

Produces a **CycloneDX v1.5 JSON** BOM containing:

- Root application component with PURL
- All direct runtime and dev dependencies with scope tags
- Full transitive dependency graph parsed from `package-lock.json`
- PURL identifiers (`pkg:npm/name@version`) for every component
- NPM registry external reference links

---

## Project Structure

```
bobguard-hackathon/
├── bobguard/
│   ├── bin/
│   │   └── bobguard.js          # CLI entry point (Commander.js)
│   ├── lib/
│   │   ├── analyzer.js          # Dependency advisory scanner
│   │   ├── compliance.js        # Rule evaluation & compliance summary
│   │   ├── complianceMatrix.js  # SOC2 / PCI-DSS / ISO 27001 attestation
│   │   ├── fixer.js             # Auto-patch engine (AST + string fixers)
│   │   ├── parser.js            # Babel AST wrapper with error recovery
│   │   ├── reporter.js          # HTML dashboard & Markdown report generators
│   │   ├── runner.js            # Jest test suite runner & regression detector
│   │   ├── sarif.js             # SARIF v2.1.0 report builder
│   │   ├── sbom.js              # CycloneDX v1.5 SBOM generator
│   │   ├── scanUtils.js         # .bobignore / .gitignore pattern matching
│   │   └── taintEngine.js       # AST taint analysis engine
│   ├── test/
│   │   ├── stressTest.test.js   # 63 taint engine + rule regression tests
│   │   ├── fixer.test.js        # 19 auto-fixer correctness tests
│   │   └── enterprise.test.js   # 45 SBOM, compliance matrix, and init tests
│   └── package.json
├── demo-app/
│   ├── server.js                # Target Express microservice
│   ├── server.test.js           # 14 functional API tests
│   └── test/
│       └── api.test.js          # 4 integration tests
├── .github/
│   └── workflows/
│       └── bobguard-audit.yml   # CI: test → audit → SARIF upload (Node 18 + 20)
├── .gitignore
├── AGENTS.md                    # Persona definitions (SecurityAuditor, ReleaseManager)
└── README.md
```

---

## Running Tests

```bash
# BobGuard engine tests (127 tests across 3 suites)
cd bobguard && npm test

# demo-app integration tests (18 tests)
cd demo-app && npm test
```

---

## CI/CD

The included [GitHub Actions workflow](.github/workflows/bobguard-audit.yml) runs on every push and pull request to `main`, `master`, and `develop`:

1. Install dependencies for both `bobguard/` and `demo-app/`
2. Run the full BobGuard test suite
3. Run the demo-app test suite
4. Execute `bobguard audit` and export a SARIF report
5. Upload SARIF to GitHub Advanced Security / Code Scanning
6. Upload HTML and Markdown audit reports as workflow artifacts

The matrix runs against **Node.js 18 and 20** in parallel.

---

## License

MIT — see [`bobguard/package.json`](bobguard/package.json).

---

*Made with IBM Bob*
