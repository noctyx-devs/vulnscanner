import { createConnection } from 'net';
import type { ScanResult, ScanTarget, Vulnerability, Scanner } from '../types/index.js';

const COMMON_PORTS: Record<number, { service: string; risks: string[] }> = {
  21: { service: 'FTP', risks: ['Plaintext credentials', 'Anonymous access'] },
  22: { service: 'SSH', risks: ['Brute force', 'Weak ciphers'] },
  23: { service: 'Telnet', risks: ['Plaintext protocol', 'No encryption'] },
  25: { service: 'SMTP', risks: ['Open relay', 'Spam'] },
  53: { service: 'DNS', risks: ['Amplification attacks', 'Cache poisoning'] },
  80: { service: 'HTTP', risks: ['Unencrypted traffic', 'Web vulnerabilities'] },
  110: { service: 'POP3', risks: ['Plaintext credentials'] },
  135: { service: 'MS-RPC', risks: ['Windows exploitation surface'] },
  139: { service: 'NetBIOS', risks: ['SMB vulnerabilities', 'Information disclosure'] },
  143: { service: 'IMAP', risks: ['Plaintext credentials'] },
  443: { service: 'HTTPS', risks: ['SSL/TLS misconfiguration', 'Certificate issues'] },
  445: { service: 'SMB', risks: ['EternalBlue', 'Ransomware vector'] },
  993: { service: 'IMAPS', risks: ['SSL/TLS misconfiguration'] },
  995: { service: 'POP3S', risks: ['SSL/TLS misconfiguration'] },
  3306: { service: 'MySQL', risks: ['Brute force', 'SQL injection surface'] },
  3389: { service: 'RDP', risks: ['BlueKeep', 'Brute force', 'Ransomware vector'] },
  5432: { service: 'PostgreSQL', risks: ['Brute force', 'SQL injection surface'] },
  5900: { service: 'VNC', risks: ['Weak authentication', 'No encryption'] },
  6379: { service: 'Redis', risks: ['No authentication by default', 'Remote code execution'] },
  8080: { service: 'HTTP-Alt', risks: ['Management interfaces', 'Unencrypted'] },
  8443: { service: 'HTTPS-Alt', risks: ['Management interfaces'] },
  9200: { service: 'Elasticsearch', risks: ['No authentication by default', 'Data exposure'] },
  27017: { service: 'MongoDB', risks: ['No authentication by default', 'Data exposure'] },
};

export class NetworkScanner implements Scanner {
  name = 'Network';
  description = 'Port scanning and service detection';

  async scan(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const host = target.host || '127.0.0.1';
    const vulnerabilities: Vulnerability[] = [];
    const ports = target.port ? [target.port] : Object.keys(COMMON_PORTS).map(Number);

    const openPorts = await this.probePorts(host, ports);

    for (const port of openPorts) {
      const info = COMMON_PORTS[port];
      if (info) {
        for (const risk of info.risks) {
          vulnerabilities.push({
            id: `NET-${port}-${risk.toLowerCase().replace(/\s+/g, '-')}`,
            title: `${info.service} (${port}): ${risk}`,
            description: `Port ${port} (${info.service}) is open. Risk: ${risk}`,
            severity: this.assessSeverity(port, risk),
            category: 'network',
            target: `${host}:${port}`,
            evidence: `Port ${port}/tcp is open and accepting connections`,
            remediation: `Restrict access to port ${port} using firewall rules. Consider disabling ${info.service} if not needed.`,
            discoveredAt: new Date(),
          });
        }
      } else {
        vulnerabilities.push({
          id: `NET-${port}-unknown`,
          title: `Unknown service on port ${port}`,
          description: `Port ${port} is open but the service is not in the known database`,
          severity: 'low',
          category: 'network',
          target: `${host}:${port}`,
          evidence: `Port ${port}/tcp is open`,
          remediation: `Investigate the service running on port ${port} and restrict access if not needed.`,
          discoveredAt: new Date(),
        });
      }
    }

    const finishedAt = new Date();
    return {
      scanner: this.name,
      target: host,
      startedAt,
      finishedAt,
      vulnerabilities,
      summary: this.summarize(vulnerabilities),
    };
  }

  private async probePorts(host: string, ports: number[]): Promise<number[]> {
    const open: number[] = [];
    const batchSize = 50;

    for (let i = 0; i < ports.length; i += batchSize) {
      const batch = ports.slice(i, i + batchSize);
      const results = await Promise.all(batch.map(p => this.probePort(host, p)));
      for (let j = 0; j < results.length; j++) {
        if (results[j]) open.push(batch[j]);
      }
    }

    return open;
  }

  private probePort(host: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = createConnection({ host, port, timeout: 3000 });
      socket.on('connect', () => { socket.destroy(); resolve(true); });
      socket.on('error', () => resolve(false));
      socket.on('timeout', () => { socket.destroy(); resolve(false); });
    });
  }

  private assessSeverity(port: number, risk: string): 'critical' | 'high' | 'medium' | 'low' {
    if (risk.includes('ransomware') || risk.includes('EternalBlue') || risk.includes('BlueKeep') || risk.includes('Remote code execution')) return 'critical';
    if (risk.includes('No authentication') || risk.includes('Plaintext') || risk.includes('Brute force')) return 'high';
    if (risk.includes('misconfiguration') || risk.includes('exposure')) return 'medium';
    return 'low';
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
