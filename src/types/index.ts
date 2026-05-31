export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  target: string;
  evidence?: string;
  remediation?: string;
  cve?: string;
  cvss?: number;
  discoveredAt: Date;
}

export interface ScanResult {
  scanner: string;
  target: string;
  startedAt: Date;
  finishedAt: Date;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface ScanTarget {
  type: 'network' | 'web' | 'dependency' | 'docker' | 'filesystem';
  host?: string;
  port?: number;
  path?: string;
  url?: string;
  image?: string;
  packageJson?: string;
}

export interface Scanner {
  name: string;
  description: string;
  scan(target: ScanTarget): Promise<ScanResult>;
}

export interface ScannerConfig {
  timeout: number;
  concurrency: number;
  userAgent: string;
  verifySsl: boolean;
}
