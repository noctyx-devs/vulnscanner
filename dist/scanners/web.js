const SECURITY_HEADERS = [
    { name: 'strict-transport-security', required: true, severity: 'high', description: 'HSTS header missing — traffic can be downgraded to HTTP', remediation: 'Add Strict-Transport-Security header with max-age >= 31536000' },
    { name: 'content-security-policy', required: true, severity: 'high', description: 'CSP header missing — XSS attacks are more likely', remediation: 'Implement a Content-Security-Policy header' },
    { name: 'x-content-type-options', required: true, severity: 'medium', description: 'X-Content-Type-Options missing — MIME sniffing attacks possible', remediation: 'Add X-Content-Type-Options: nosniff' },
    { name: 'x-frame-options', required: true, severity: 'medium', description: 'X-Frame-Options missing — clickjacking attacks possible', remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN' },
    { name: 'x-xss-protection', required: false, severity: 'low', description: 'X-XSS-Protection header missing', remediation: 'Add X-XSS-Protection: 1; mode=block' },
    { name: 'referrer-policy', required: false, severity: 'low', description: 'Referrer-Policy missing — referrer leakage possible', remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
    { name: 'permissions-policy', required: false, severity: 'low', description: 'Permissions-Policy missing — browser features unrestricted', remediation: 'Add Permissions-Policy to restrict browser features' },
];
const DANGEROUS_HEADERS = [
    { name: 'x-powered-by', severity: 'low', description: 'X-Powered-by header exposes server technology' },
    { name: 'server', severity: 'low', description: 'Server header exposes server version information' },
];
export class WebScanner {
    name = 'Web';
    description = 'Web application security header and SSL/TLS analysis';
    async scan(target) {
        const startedAt = new Date();
        const url = target.url || `http://${target.host}:${target.port || 80}`;
        const vulnerabilities = [];
        try {
            const response = await fetch(url, {
                method: 'GET',
                signal: AbortSignal.timeout(10000),
                redirect: 'follow',
            });
            const headers = response.headers;
            // Check security headers
            for (const header of SECURITY_HEADERS) {
                if (!headers.get(header.name)) {
                    vulnerabilities.push({
                        id: `WEB-HEADER-${header.name}`,
                        title: `Missing security header: ${header.name}`,
                        description: header.description,
                        severity: header.severity,
                        category: 'web-headers',
                        target: url,
                        evidence: `Response did not include ${header.name} header`,
                        remediation: header.remediation,
                        discoveredAt: new Date(),
                    });
                }
            }
            // Check for information-disclosing headers
            for (const header of DANGEROUS_HEADERS) {
                const val = headers.get(header.name);
                if (val) {
                    vulnerabilities.push({
                        id: `WEB-DISCLOSE-${header.name}`,
                        title: `Information disclosure: ${header.name}`,
                        description: `${header.description}. Value: "${val}"`,
                        severity: header.severity,
                        category: 'web-disclosure',
                        target: url,
                        evidence: `${header.name}: ${val}`,
                        remediation: `Remove or obfuscate the ${header.name} header`,
                        discoveredAt: new Date(),
                    });
                }
            }
            // Check for HTTPS
            if (!url.startsWith('https://')) {
                vulnerabilities.push({
                    id: 'WEB-NO-HTTPS',
                    title: 'Site not served over HTTPS',
                    description: 'The website is accessible over unencrypted HTTP',
                    severity: 'high',
                    category: 'web-ssl',
                    target: url,
                    evidence: `URL scheme is HTTP: ${url}`,
                    remediation: 'Enable HTTPS and redirect all HTTP traffic to HTTPS',
                    discoveredAt: new Date(),
                });
            }
            // Check for cookie security flags
            const setCookie = headers.get('set-cookie');
            if (setCookie) {
                if (!setCookie.toLowerCase().includes('httponly')) {
                    vulnerabilities.push({
                        id: 'WEB-COOKIE-NO-HTTPSONLY',
                        title: 'Cookie missing HttpOnly flag',
                        description: 'Cookies without HttpOnly can be accessed via JavaScript (XSS risk)',
                        severity: 'medium',
                        category: 'web-cookies',
                        target: url,
                        evidence: `Set-Cookie: ${setCookie}`,
                        remediation: 'Add the HttpOnly flag to all session cookies',
                        discoveredAt: new Date(),
                    });
                }
                if (!setCookie.toLowerCase().includes('secure')) {
                    vulnerabilities.push({
                        id: 'WEB-COOKIE-NO-SECURE',
                        title: 'Cookie missing Secure flag',
                        description: 'Cookies without Secure flag can be transmitted over HTTP',
                        severity: 'medium',
                        category: 'web-cookies',
                        target: url,
                        evidence: `Set-Cookie: ${setCookie}`,
                        remediation: 'Add the Secure flag to all cookies',
                        discoveredAt: new Date(),
                    });
                }
                if (!setCookie.toLowerCase().includes('samesite')) {
                    vulnerabilities.push({
                        id: 'WEB-COOKIE-NO-SAMESITE',
                        title: 'Cookie missing SameSite attribute',
                        description: 'Cookies without SameSite are vulnerable to CSRF attacks',
                        severity: 'medium',
                        category: 'web-cookies',
                        target: url,
                        evidence: `Set-Cookie: ${setCookie}`,
                        remediation: 'Add SameSite=Strict or SameSite=Lax to cookies',
                        discoveredAt: new Date(),
                    });
                }
            }
            // Check for CORS misconfiguration
            const acao = headers.get('access-control-allow-origin');
            if (acao === '*') {
                vulnerabilities.push({
                    id: 'WEB-CORS-WILDCARD',
                    title: 'CORS allows all origins (*)',
                    description: 'Access-Control-Allow-Origin is set to wildcard, allowing any site to make cross-origin requests',
                    severity: 'high',
                    category: 'web-cors',
                    target: url,
                    evidence: 'Access-Control-Allow-Origin: *',
                    remediation: 'Set Access-Control-Allow-Origin to specific trusted origins',
                    discoveredAt: new Date(),
                });
            }
        }
        catch (err) {
            vulnerabilities.push({
                id: 'WEB-CONN-ERROR',
                title: 'Could not connect to target',
                description: `Failed to fetch ${url}: ${err instanceof Error ? err.message : 'Unknown error'}`,
                severity: 'info',
                category: 'web-connectivity',
                target: url,
                evidence: err instanceof Error ? err.message : undefined,
                remediation: 'Verify the target is reachable and the URL is correct',
                discoveredAt: new Date(),
            });
        }
        const finishedAt = new Date();
        return {
            scanner: this.name,
            target: url,
            startedAt,
            finishedAt,
            vulnerabilities,
            summary: this.summarize(vulnerabilities),
        };
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
