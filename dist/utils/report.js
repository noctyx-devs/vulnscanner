const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export function generateReport(results) {
    const lines = [];
    lines.push('═'.repeat(70));
    lines.push('  VULNSCANNER REPORT');
    lines.push('═'.repeat(70));
    lines.push('');
    const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    const allVulns = results.flatMap(r => r.vulnerabilities);
    const bySeverity = countBySeverity(allVulns);
    // Summary
    lines.push('  SUMMARY');
    lines.push('  ' + '─'.repeat(40));
    lines.push(`  Total scans:     ${results.length}`);
    lines.push(`  Total findings:  ${totalVulns}`);
    lines.push(`  Critical:        ${bySeverity.critical}`);
    lines.push(`  High:            ${bySeverity.high}`);
    lines.push(`  Medium:          ${bySeverity.medium}`);
    lines.push(`  Low:             ${bySeverity.low}`);
    lines.push(`  Info:            ${bySeverity.info}`);
    lines.push('');
    // Per-scanner results
    for (const result of results) {
        if (result.vulnerabilities.length === 0)
            continue;
        lines.push(`  [${result.scanner}] → ${result.target}`);
        lines.push('  ' + '─'.repeat(50));
        const sorted = [...result.vulnerabilities].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
        for (const vuln of sorted) {
            const sevIcon = severityIcon(vuln.severity);
            lines.push(`  ${sevIcon} [${vuln.severity.toUpperCase()}] ${vuln.title}`);
            lines.push(`    ID: ${vuln.id}`);
            lines.push(`    ${vuln.description}`);
            if (vuln.evidence)
                lines.push(`    Evidence: ${vuln.evidence}`);
            if (vuln.cve)
                lines.push(`    CVE: ${vuln.cve}`);
            if (vuln.remediation)
                lines.push(`    Fix: ${vuln.remediation}`);
            lines.push('');
        }
    }
    if (totalVulns === 0) {
        lines.push('  ✓ No vulnerabilities found.');
        lines.push('');
    }
    lines.push('═'.repeat(70));
    return lines.join('\n');
}
function countBySeverity(vulns) {
    return {
        critical: vulns.filter(v => v.severity === 'critical').length,
        high: vulns.filter(v => v.severity === 'high').length,
        medium: vulns.filter(v => v.severity === 'medium').length,
        low: vulns.filter(v => v.severity === 'low').length,
        info: vulns.filter(v => v.severity === 'info').length,
    };
}
function severityIcon(s) {
    switch (s) {
        case 'critical': return '🔴';
        case 'high': return '🟠';
        case 'medium': return '🟡';
        case 'low': return '🔵';
        case 'info': return '⚪';
    }
}
export function generateJsonReport(results) {
    return {
        generatedAt: new Date().toISOString(),
        totalScans: results.length,
        totalVulnerabilities: results.reduce((s, r) => s + r.vulnerabilities.length, 0),
        results: results.map(r => ({
            ...r,
            startedAt: r.startedAt.toISOString(),
            finishedAt: r.finishedAt.toISOString(),
            vulnerabilities: r.vulnerabilities.map(v => ({
                ...v,
                discoveredAt: v.discoveredAt.toISOString(),
            })),
        })),
    };
}
