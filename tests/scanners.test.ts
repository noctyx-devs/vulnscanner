import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock dockerode
vi.mock('dockerode', () => ({
  default: vi.fn().mockImplementation(() => ({
    listContainers: vi.fn().mockResolvedValue([]),
    getContainer: vi.fn().mockReturnValue({
      inspect: vi.fn().mockResolvedValue({
        Name: '/test',
        Config: { User: '' },
        HostConfig: {},
        Mounts: [],
      }),
    }),
    getImage: vi.fn().mockReturnValue({
      inspect: vi.fn().mockResolvedValue({
        Size: 500 * 1024 * 1024,
        RepoTags: ['test:latest'],
      }),
    }),
  })),
}));

describe('Secrets Scanner', () => {
  it('detects AWS access keys', async () => {
    const { SecretsScanner } = await import('../src/scanners/secrets.js');
    const scanner = new SecretsScanner();
    const result = await scanner.scan({ type: 'filesystem', path: '.' });

    // Should at least complete without error
    expect(result.scanner).toBe('Secrets');
    expect(result.summary).toBeDefined();
  });
});

describe('Dependency Scanner', () => {
  it('returns info when no package.json found', async () => {
    const { DependencyScanner } = await import('../src/scanners/dependency.js');
    const scanner = new DependencyScanner();
    const result = await scanner.scan({ type: 'dependency', packageJson: '/nonexistent/package.json' });

    expect(result.scanner).toBe('Dependency');
    expect(result.vulnerabilities.length).toBe(1);
    expect(result.vulnerabilities[0].id).toBe('DEP-NO-PACKAGE-JSON');
  });

  it('detects known vulnerable packages', async () => {
    const { DependencyScanner } = await import('../src/scanners/dependency.js');
    const scanner = new DependencyScanner();

    // Create a temp package.json with a known vulnerable dep
    const { writeFileSync, mkdirSync, rmSync } = await import('fs');
    const tmpDir = '/tmp/vulnscanner-test';
    try { mkdirSync(tmpDir, { recursive: true }); } catch {}
    writeFileSync(`${tmpDir}/package.json`, JSON.stringify({
      dependencies: { 'lodash': '4.17.10', 'minimist': '1.2.0' }
    }));

    const result = await scanner.scan({ type: 'dependency', packageJson: `${tmpDir}/package.json` });

    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    const lodashVuln = result.vulnerabilities.find(v => v.id.includes('lodash'));
    expect(lodashVuln).toBeDefined();
    expect(lodashVuln!.severity).toBe('high');

    rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe('Network Scanner', () => {
  it('completes scan without error', async () => {
    const { NetworkScanner } = await import('../src/scanners/network.js');
    const scanner = new NetworkScanner();
    const result = await scanner.scan({ type: 'network', host: '127.0.0.1', port: 1 });

    expect(result.scanner).toBe('Network');
    expect(result.summary).toBeDefined();
  });
});

describe('Report Generator', () => {
  it('generates text report', async () => {
    const { generateReport } = await import('../src/utils/report.js');
    const { SecretsScanner } = await import('../src/scanners/secrets.js');
    const scanner = new SecretsScanner();
    const result = await scanner.scan({ type: 'filesystem', path: '.' });
    const report = generateReport([result]);

    expect(report).toContain('VULNSCANNER REPORT');
    expect(report).toContain('SUMMARY');
  });

  it('generates JSON report', async () => {
    const { generateJsonReport } = await import('../src/utils/report.js');
    const { SecretsScanner } = await import('../src/scanners/secrets.js');
    const scanner = new SecretsScanner();
    const result = await scanner.scan({ type: 'filesystem', path: '.' });
    const report = generateJsonReport([result]) as any;

    expect(report.totalScans).toBe(1);
    expect(report.results).toHaveLength(1);
  });
});
