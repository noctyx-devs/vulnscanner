import { readdirSync, statSync, readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
const SECRET_PATTERNS = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', description: 'AWS access key ID detected in source code' },
    { name: 'AWS Secret Key', pattern: /['"][0-9a-zA-Z/+]{40}['"]/g, severity: 'critical', description: 'Potential AWS secret access key in source code' },
    { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical', description: 'Private key found in repository' },
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical', description: 'GitHub personal access token detected' },
    { name: 'Slack Token', pattern: /xox[bprs]-[0-9a-zA-Z-]{10,}/g, severity: 'critical', description: 'Slack API token detected' },
    { name: 'Generic API Key', pattern: /['"]?[aA][pP][iI][_-]?[kK][eE][yY]['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/g, severity: 'high', description: 'Generic API key pattern detected' },
    { name: 'Generic Secret', pattern: /['"]?[sS][eE][cC][rR][eE][tT]['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/g, severity: 'high', description: 'Generic secret pattern detected' },
    { name: 'Password Assignment', pattern: /['"]?[pP][aA][sS][sS][wW][oO][rR][dD]['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]/g, severity: 'high', description: 'Hardcoded password detected' },
    { name: 'Database URL', pattern: /(mongodb|mysql|postgresql|postgres|redis):\/\/[^:\s]+:[^@\s]+@[^/\s]+/g, severity: 'critical', description: 'Database connection string with credentials detected' },
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, severity: 'high', description: 'JWT token found in source code' },
    { name: 'NPM Token', pattern: /npm_[A-Za-z0-9]{36}/g, severity: 'critical', description: 'NPM authentication token detected' },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high', description: 'Google API key detected' },
];
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '__pycache__', '.venv', 'vendor']);
const IGNORE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.zip', '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.lock']);
export class SecretsScanner {
    name = 'Secrets';
    description = 'Scan filesystem for hardcoded secrets and credentials';
    async scan(target) {
        const startedAt = new Date();
        const vulnerabilities = [];
        const scanPath = target.path || '.';
        if (!existsSync(scanPath)) {
            return {
                scanner: this.name,
                target: scanPath,
                startedAt,
                finishedAt: new Date(),
                vulnerabilities: [{
                        id: 'SECRETS-PATH-NOT-FOUND',
                        title: 'Scan path not found',
                        description: `Path "${scanPath}" does not exist`,
                        severity: 'info',
                        category: 'filesystem',
                        target: scanPath,
                        discoveredAt: new Date(),
                    }],
                summary: { total: 1, critical: 0, high: 0, medium: 0, low: 0, info: 1 },
            };
        }
        this.walkDir(scanPath, vulnerabilities);
        const finishedAt = new Date();
        return {
            scanner: this.name,
            target: scanPath,
            startedAt,
            finishedAt,
            vulnerabilities,
            summary: this.summarize(vulnerabilities),
        };
    }
    walkDir(dir, vulnerabilities) {
        let entries;
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (IGNORE_DIRS.has(entry))
                continue;
            const fullPath = join(dir, entry);
            let stats;
            try {
                stats = statSync(fullPath);
            }
            catch {
                continue;
            }
            if (stats.isDirectory()) {
                this.walkDir(fullPath, vulnerabilities);
            }
            else if (stats.isFile()) {
                if (IGNORE_EXTS.has(extname(entry)))
                    continue;
                if (stats.size > 1024 * 1024)
                    continue; // skip files > 1MB
                this.scanFile(fullPath, vulnerabilities);
            }
        }
    }
    scanFile(filePath, vulnerabilities) {
        let content;
        try {
            content = readFileSync(filePath, 'utf-8');
        }
        catch {
            return;
        }
        for (const secret of SECRET_PATTERNS) {
            const matches = content.matchAll(secret.pattern);
            for (const match of matches) {
                const lineNum = content.substring(0, match.index).split('\n').length;
                vulnerabilities.push({
                    id: `SECRET-${secret.name.replace(/\s/g, '-')}-${filePath}-${lineNum}`,
                    title: `Exposed ${secret.name}`,
                    description: secret.description,
                    severity: secret.severity,
                    category: 'secrets',
                    target: filePath,
                    evidence: `${filePath}:${lineNum} — ${match[0].slice(0, 60)}${match[0].length > 60 ? '...' : ''}`,
                    remediation: `Remove the ${secret.name} from ${filePath} and rotate the credential immediately. Use environment variables or a secrets manager.`,
                    discoveredAt: new Date(),
                });
            }
        }
    }
    summarize(vulns) {
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
