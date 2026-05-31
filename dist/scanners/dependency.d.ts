import type { ScanResult, ScanTarget, Scanner } from '../types/index.js';
export declare class DependencyScanner implements Scanner {
    name: string;
    description: string;
    scan(target: ScanTarget): Promise<ScanResult>;
    private summarize;
}
