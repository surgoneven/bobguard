'use strict';

/**
 * CycloneDX v1.5 SBOM generator for BobGuard.
 *
 * Reads package.json (and optionally package-lock.json) from a target
 * directory and produces a spec-compliant CycloneDX JSON bill of materials.
 *
 * Spec reference: https://cyclonedx.org/specification/overview/
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// PURL builder
// ---------------------------------------------------------------------------

/**
 * Builds a Package URL (purl) for an npm package.
 * Format: pkg:npm/<name>@<version>
 * Scoped packages: pkg:npm/%40scope/name@version
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
function buildPurl(name, version) {
  // PURL spec for npm: scoped packages encode only the leading @.
  // The slash separating scope from package name stays unencoded.
  // e.g. @babel/parser -> pkg:npm/%40babel/parser@version
  const encodedName = name.startsWith('@')
    ? '%40' + name.slice(1)   // replaces only the @; keeps / as-is
    : name;
  const cleanVersion = (version || '').replace(/^[\^~>=<]/, '');
  return `pkg:npm/${encodedName}@${cleanVersion}`;
}

// ---------------------------------------------------------------------------
// License extraction
// ---------------------------------------------------------------------------

/**
 * Normalises a license field from package.json (string or object).
 * @param {string|object|undefined} licenseField
 * @returns {string}
 */
function normalizeLicense(licenseField) {
  if (!licenseField) return 'NOASSERTION';
  if (typeof licenseField === 'string') return licenseField;
  if (typeof licenseField === 'object' && licenseField.type) return licenseField.type;
  return 'NOASSERTION';
}

// ---------------------------------------------------------------------------
// Component builder
// ---------------------------------------------------------------------------

/**
 * Builds a single CycloneDX component object for an npm package.
 * @param {string} name
 * @param {string} version  - raw version string (may have ^ ~ prefix)
 * @param {string} [license]
 * @param {string} [description]
 * @param {string} [scope] - 'required' | 'optional' | 'excluded'
 * @returns {object}
 */
function buildComponent(name, version, license, description, scope) {
  const cleanVersion = (version || '').replace(/^[\^~>=<*]/, '').trim();
  return {
    type: 'library',
    'bom-ref': `pkg:npm/${name}@${cleanVersion}`,
    name,
    version: cleanVersion,
    description: description || '',
    scope: scope || 'required',
    licenses: [{ license: { id: normalizeLicense(license) } }],
    purl: buildPurl(name, cleanVersion),
    externalReferences: [
      {
        type: 'website',
        url: `https://www.npmjs.com/package/${encodeURIComponent(name)}`
      }
    ]
  };
}

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------

/**
 * Builds the CycloneDX `dependencies` array from package-lock.json (v2/v3)
 * or falls back to a shallow list from package.json.
 * @param {object} pkg        - parsed package.json
 * @param {object|null} lock  - parsed package-lock.json, or null
 * @param {object[]} components
 * @returns {object[]}
 */
function buildDependencyGraph(pkg, lock, components) {
  const rootRef = `pkg:npm/${pkg.name}@${pkg.version || '0.0.0'}`;

  // All direct dep names
  const directDeps = [
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {})
  ];

  // If we have a lockfile with packages, build a transitive map
  const depMap = new Map(); // bom-ref -> dependsOn bom-refs[]

  if (lock && lock.packages) {
    // lockfile v2/v3 — packages keyed by "node_modules/name"
    for (const [pkgPath, pkgData] of Object.entries(lock.packages)) {
      if (!pkgPath) continue; // root entry
      const pkgName = pkgPath.replace(/^node_modules\//, '');
      const pkgVer = pkgData.version || '';
      const ref = buildPurl(pkgName, pkgVer);
      const transitiveDeps = [
        ...Object.keys(pkgData.dependencies || {}),
        ...Object.keys(pkgData.optionalDependencies || {})
      ].map((dep) => {
        const depEntry = lock.packages[`node_modules/${dep}`];
        return depEntry ? buildPurl(dep, depEntry.version || '') : buildPurl(dep, '');
      });
      depMap.set(ref, transitiveDeps);
    }
  }

  const result = [
    {
      ref: rootRef,
      dependsOn: directDeps.map((d) => {
        const comp = components.find((c) => c.name === d);
        return comp ? comp.purl : buildPurl(d, '');
      })
    }
  ];

  depMap.forEach((deps, ref) => {
    result.push({ ref, dependsOn: deps });
  });

  return result;
}

// ---------------------------------------------------------------------------
// Main SBOM builder
// ---------------------------------------------------------------------------

/**
 * Generates a CycloneDX v1.5 JSON SBOM for the given target directory.
 * @param {string} targetDir - absolute or relative path to the microservice
 * @returns {{bom: object, componentCount: number, warnings: string[]}}
 */
function generateSbom(targetDir) {
  const resolvedDir = path.resolve(targetDir);
  const warnings = [];

  // -- Read package.json -------------------------------------------------------
  const pkgPath = path.join(resolvedDir, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`package.json not found in ${resolvedDir}`);
  }
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

  // -- Read package-lock.json (optional) ---------------------------------------
  const lockPath = path.join(resolvedDir, 'package-lock.json');
  let lock = null;
  if (fs.existsSync(lockPath)) {
    try {
      lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    } catch (e) {
      warnings.push(`Could not parse package-lock.json: ${e.message}`);
    }
  } else {
    warnings.push('package-lock.json not found; SBOM will only include direct declared dependencies.');
  }

  // -- Build components --------------------------------------------------------
  const components = [];

  // Direct runtime deps
  for (const [name, version] of Object.entries(pkg.dependencies || {})) {
    components.push(buildComponent(name, version, undefined, undefined, 'required'));
  }

  // Dev deps (scope = optional in CycloneDX)
  for (const [name, version] of Object.entries(pkg.devDependencies || {})) {
    components.push(buildComponent(name, version, undefined, undefined, 'optional'));
  }

  // Transitive deps from lockfile (v2/v3 packages map)
  if (lock && lock.packages) {
    const directNames = new Set([
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.devDependencies || {})
    ]);
    for (const [pkgPath, pkgData] of Object.entries(lock.packages)) {
      if (!pkgPath) continue; // root
      const name = pkgPath.replace(/^node_modules\//, '');
      if (directNames.has(name)) continue; // already added
      const version = pkgData.version || '';
      const license = pkgData.license;
      components.push(buildComponent(name, version, license, pkgData.description, 'required'));
    }
  }

  // -- Unique-ify by purl -------------------------------------------------------
  const seen = new Set();
  const uniqueComponents = components.filter((c) => {
    if (seen.has(c.purl)) return false;
    seen.add(c.purl);
    return true;
  });

  // -- Dependency graph --------------------------------------------------------
  const dependencies = buildDependencyGraph(pkg, lock, uniqueComponents);

  // -- Assemble BOM -----------------------------------------------------------
  const serialNumber = `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : require('crypto').randomBytes(16).toString('hex')}`;

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'BobGuard',
          name: 'BobGuard',
          version: '0.2.0'
        }
      ],
      component: {
        type: 'application',
        'bom-ref': `pkg:npm/${pkg.name}@${pkg.version || '0.0.0'}`,
        name: pkg.name || path.basename(resolvedDir),
        version: pkg.version || '0.0.0',
        description: pkg.description || '',
        licenses: [{ license: { id: normalizeLicense(pkg.license) } }],
        purl: buildPurl(pkg.name || path.basename(resolvedDir), pkg.version || '0.0.0')
      }
    },
    components: uniqueComponents,
    dependencies
  };

  return { bom, componentCount: uniqueComponents.length, warnings };
}

/**
 * Generates the SBOM and writes it to disk as formatted JSON.
 * @param {string} targetDir
 * @param {string} outputPath - absolute or relative file path
 * @returns {{outputPath: string, componentCount: number, warnings: string[]}}
 */
function writeSbom(targetDir, outputPath) {
  const { bom, componentCount, warnings } = generateSbom(targetDir);
  const resolvedOut = path.resolve(outputPath);
  fs.writeFileSync(resolvedOut, JSON.stringify(bom, null, 2), 'utf8');
  return { outputPath: resolvedOut, componentCount, warnings };
}

module.exports = {
  generateSbom,
  writeSbom,
  buildPurl,
  buildComponent,
  normalizeLicense
};
