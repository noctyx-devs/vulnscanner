#!/usr/bin/env node
import { Command } from 'commander';
import { NetworkScanner } from './scanners/network.js';
import { WebScanner } from './scanners/web.js';
import { SecretsScanner } from './scanners/secrets.js';
import { DependencyScanner } from './scanners/dependency.js';
import { DockerScanner } from './scanners/docker.js';
import { generateReport, generateJsonReport } from './utils/report.js';
const program = new Command();
program
    .name('vulnscanner')
    .description('Security vulnerability scanner — network, web, dependencies, Docker, secrets')
    .version('0.1.0');
const ALL_SCANNERS = {
    network: NetworkScanner,
    web: WebScanner,
    secrets: SecretsScanner,
    dependency: DependencyScanner,
    docker: DockerScanner,
};
program
    .command('scan')
    .description('Run vulnerability scans')
    .option('-t, --target <target>', 'Target to scan (host, URL, path, or image)')
    .option('-p, --port <port>', 'Port to scan (network)', '0')
    .option('-s, --scanners <scanners>', 'Comma-separated list of scanners (default: all)', '')
    .option('-o, --output <format>', 'Output format: text, json', 'text')
    .option('--timeout <ms>', 'Scanner timeout in milliseconds', '30000')
    .action(async (options) => {
    const target = options.target || '127.0.0.1';
    const selectedScanners = options.scanners
        ? options.scanners.split(',').map((s) => s.trim().toLowerCase())
        : Object.keys(ALL_SCANNERS);
    console.log(`\n🔍 VulnScanner v0.1.0 — Scanning: ${target}\n`);
    const results = [];
    for (const name of selectedScanners) {
        const ScannerClass = ALL_SCANNERS[name];
        if (!ScannerClass) {
            console.log(`  ⚠ Unknown scanner: ${name}`);
            continue;
        }
        const scanner = new ScannerClass();
        const scanTarget = {
            type: name,
            host: target,
            port: parseInt(options.port, 10) || undefined,
            path: target,
            url: target.startsWith('http') ? target : undefined,
            image: target.includes(':') && !target.startsWith('http') ? target : undefined,
            packageJson: target,
        };
        if (name === 'web' && !scanTarget.url) {
            scanTarget.url = `http://${target}`;
        }
        process.stdout.write(`  Running ${scanner.name} scanner... `);
        try {
            const result = await scanner.scan(scanTarget);
            results.push(result);
            console.log(`✓ (${result.vulnerabilities.length} findings)`);
        }
        catch (err) {
            console.log(`✗ (${err instanceof Error ? err.message : 'failed'})`);
        }
    }
    console.log('');
    if (options.output === 'json') {
        console.log(JSON.stringify(generateJsonReport(results), null, 2));
    }
    else {
        console.log(generateReport(results));
    }
    // Exit with error code if critical/high vulns found
    const criticalCount = results.reduce((s, r) => s + r.summary.critical + r.summary.high, 0);
    if (criticalCount > 0) {
        process.exit(1);
    }
});
program
    .command('list-scanners')
    .description('List available scanners')
    .action(() => {
    console.log('\nAvailable scanners:\n');
    for (const [key, cls] of Object.entries(ALL_SCANNERS)) {
        const s = new cls();
        console.log(`  ${key.padEnd(12)} ${s.name} — ${s.description}`);
    }
    console.log('');
});
program.parse();
