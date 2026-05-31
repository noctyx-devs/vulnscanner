import type { ScanResult, ScanTarget, Scanner } from '../types/index.js';
export declare class NetworkScanner implements Scanner {
    name: string;
    description: string;
    scan(target: ScanTarget): Promise<ScanResult>;
    private probePorts;
    private probePort;
    private assessSeverity;
    private summarize;
}
