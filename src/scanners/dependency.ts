import { readFileSync, existsSync } from 'fs';
import type { ScanResult, ScanTarget, Vulnerability, Scanner } from '../types/index.js';

// Known vulnerable packages database (simplified — in production this would query OSV/NVD)
const KNOWN_VULNERABLE: Record<string, { versions: string; cve: string; severity: 'critical' | 'high' | 'medium' | 'low'; title: string; description: string }[]> = {
  'lodash': [
    { versions: '<4.17.21', cve: 'CVE-2021-23337', severity: 'high', title: 'Prototype Pollution in lodash', description: 'lodash versions before 4.17.21 are vulnerable to Command Injection via template' },
    { versions: '<4.17.19', cve: 'CVE-2020-28500', severity: 'medium', title: 'ReDoS in lodash', description: 'lodash versions before 4.17.19 are vulnerable to Regular Expression Denial of Service' },
  ],
  'minimist': [
    { versions: '<1.2.6', cve: 'CVE-2021-44906', severity: 'critical', title: 'Prototype Pollution in minimist', description: 'minimist versions before 1.2.6 are vulnerable to Prototype Pollution' },
  ],
  'semver': [
    { versions: '<7.5.2', cve: 'CVE-2022-25883', severity: 'medium', title: 'ReDoS in semver', description: 'semver versions before 7.5.2 are vulnerable to Regular Expression Denial of Service' },
  ],
  'json5': [
    { versions: '<2.2.2', cve: 'CVE-2022-46175', severity: 'high', title: 'Prototype Pollution in json5', description: 'json5 versions before 2.2.2 are vulnerable to Prototype Pollution via parse' },
  ],
  'node-fetch': [
    { versions: '<2.6.7', cve: 'CVE-2022-0235', severity: 'high', title: 'Information Exposure in node-fetch', description: 'node-fetch versions before 2.6.7 are vulnerable to Exposure of Sensitive Information' },
  ],
  'express': [
    { versions: '<4.19.2', cve: 'CVE-2024-29041', severity: 'medium', title: 'Open Redirect in express', description: 'express versions before 4.19.2 are vulnerable to Open Redirect' },
  ],
  'axios': [
    { versions: '<1.6.0', cve: 'CVE-2023-45857', severity: 'medium', title: 'CSRF in axios', description: 'axios versions before 1.6.0 are vulnerable to Cross-Site Request Forgery' },
    { versions: '<0.28.0', cve: 'CVE-2024-39338', severity: 'high', title: 'SSRF in axios', description: 'axios versions before 0.28.0 are vulnerable to Server-Side Request Forgery' },
  ],
  'tar': [
    { versions: '<6.1.9', cve: 'CVE-2021-32803', severity: 'high', title: 'Arbitrary File Creation in tar', description: 'tar versions before 6.1.9 are vulnerable to Arbitrary File Creation via insufficient symlink protection' },
  ],
  'glob-parent': [
    { versions: '<5.1.2', cve: 'CVE-2020-28469', severity: 'medium', title: 'ReDoS in glob-parent', description: 'glob-parent versions before 5.1.2 are vulnerable to Regular Expression Denial of Service' },
  ],
  'trim-newlines': [
    { versions: '<3.0.1', cve: 'CVE-2021-33623', severity: 'high', title: 'ReDoS in trim-newlines', description: 'trim-newlines versions before 3.0.1 are vulnerable to Regular Expression Denial of Service' },
  ],
};

// Simple semver comparison
function satisfies(version: string, range: string): boolean {
  const clean = version.replace(/^[>=^~]+/, '').trim();

  if (range.startsWith('<')) {
    const max = range.slice(1).trim();
    return compareVersions(clean, max) < 0;
  }
  if (range.startsWith('>=')) {
    const min = range.slice(2).trim();
    return compareVersions(clean, min) >= 0;
  }
  if (range.startsWith('^')) {
    const min = range.slice(1).trim();
    const parts = min.split('.');
    const max = `${parseInt(parts[0]) + 1}.0.0`;
    return compareVersions(clean, min) >= 0 && compareVersions(clean, max) < 0;
  }
  if (range.startsWith('~')) {
    const min = range.slice(1).trim();
    const parts = min.split('.');
    const max = `${parts[0]}.${parseInt(parts[1]) + 1}.0`;
    return compareVersions(clean, min) >= 0 && compareVersions(clean, max) < 0;
  }
  return clean === range;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

export class DependencyScanner implements Scanner {
  name = 'Dependency';
  description = 'Scan package.json for known vulnerable dependencies';

  async scan(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const vulnerabilities: Vulnerability[] = [];
    const pkgPath = target.packageJson || (target.path ? `${target.path}/package.json` : 'package.json');

    if (!existsSync(pkgPath)) {
      return {
        scanner: this.name,
        target: pkgPath,
        startedAt,
        finishedAt: new Date(),
        vulnerabilities: [{
          id: 'DEP-NO-PACKAGE-JSON',
          title: 'No package.json found',
          description: `Could not find package.json at ${pkgPath}`,
          severity: 'info',
          category: 'dependencies',
          target: pkgPath,
          remediation: 'Ensure package.json exists in the target directory',
          discoveredAt: new Date(),
        }],
        summary: { total: 1, critical: 0, high: 0, medium: 0, low: 0, info: 1 },
      };
    }

    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    try {
      pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    } catch {
      return {
        scanner: this.name,
        target: pkgPath,
        startedAt,
        finishedAt: new Date(),
        vulnerabilities: [{
          id: 'DEP-PARSE-ERROR',
          title: 'Could not parse package.json',
          description: `Failed to parse ${pkgPath}`,
          severity: 'info',
          category: 'dependencies',
          target: pkgPath,
          discoveredAt: new Date(),
        }],
        summary: { total: 1, critical: 0, high: 0, medium: 0, low: 0, info: 1 },
      };
    }

    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const vulns = KNOWN_VULNERABLE[name];
      if (!vulns) continue;

      for (const vuln of vulns) {
        if (satisfies(version, vuln.versions)) {
          vulnerabilities.push({
            id: `DEP-${name}-${vuln.cve}`,
            title: `[${name}] ${vuln.title}`,
            description: `${name}@${version}: ${vuln.description}`,
            severity: vuln.severity,
            category: 'dependencies',
            target: pkgPath,
            evidence: `"${name}": "${version}" (affected: ${vuln.versions})`,
            remediation: `Upgrade ${name} to a version outside the affected range (${vuln.versions})`,
            cve: vuln.cve,
            discoveredAt: new Date(),
          });
        }
      }
    }

    const finishedAt = new Date();
    return {
      scanner: this.name,
      target: pkgPath,
      startedAt,
      finishedAt,
      vulnerabilities,
      summary: this.summarize(vulnerabilities),
    };
  }

  private summarize(vulns: Vulnerability[]) {
    return {
      total: vulns.length,
      critical: vulns.filter(v => v.severity === 'critical').length,
      high: vulns.filter(v => v.severity === 'high').length,
      medium: vulns.filter(v => v.severity === 'medium').length,
      low: vulns.filter(v => v.severity === 'low').length,
      info: vulns.filter(v => v.severity === 'info').length,
    };
  }
}
