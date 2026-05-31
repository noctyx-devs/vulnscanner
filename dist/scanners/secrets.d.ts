import type { ScanResult, ScanTarget, Scanner } from '../types/index.js';
export declare class SecretsScanner implements Scanner {
    name: string;
    description: string;
    scan(target: ScanTarget): Promise<ScanResult>;
    private walkDir;
    private scanFile;
    private summarize;
}
