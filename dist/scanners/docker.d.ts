import type { ScanResult, ScanTarget, Scanner } from '../types/index.js';
export declare class DockerScanner implements Scanner {
    name: string;
    description: string;
    scan(target: ScanTarget): Promise<ScanResult>;
    private scanContainer;
    private scanImage;
    private summarize;
}
