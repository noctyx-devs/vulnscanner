import Docker from 'dockerode';
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
export class DockerScanner {
    name = 'Docker';
    description = 'Scan Docker containers and images for security misconfigurations';
    async scan(target) {
        const startedAt = new Date();
        const vulnerabilities = [];
        try {
            if (target.image) {
                // Scan a specific image
                await this.scanImage(target.image, vulnerabilities);
            }
            else {
                // Scan all running containers
                const containers = await docker.listContainers({ all: true });
                for (const c of containers) {
                    await this.scanContainer(c.Id, vulnerabilities);
                }
            }
        }
        catch (err) {
            vulnerabilities.push({
                id: 'DOCKER-CONN-ERROR',
                title: 'Docker connection failed',
                description: `Could not connect to Docker daemon: ${err instanceof Error ? err.message : 'Unknown error'}`,
                severity: 'info',
                category: 'docker',
                target: 'docker.sock',
                remediation: 'Ensure Docker is running and the socket is accessible',
                discoveredAt: new Date(),
            });
        }
        const finishedAt = new Date();
        return {
            scanner: this.name,
            target: target.image || 'all-containers',
            startedAt,
            finishedAt,
            vulnerabilities,
            summary: this.summarize(vulnerabilities),
        };
    }
    async scanContainer(id, vulns) {
        const container = docker.getContainer(id);
        let info;
        try {
            info = await container.inspect();
        }
        catch {
            return;
        }
        const name = info.Name.replace('/', '');
        // Running as root
        if (info.Config.User === '' || info.Config.User === 'root' || info.Config.User === '0') {
            vulns.push({
                id: `DOCKER-ROOT-${id.slice(0, 12)}`,
                title: `Container "${name}" running as root`,
                description: 'Container processes run as root user, increasing impact of container escape',
                severity: 'high',
                category: 'docker',
                target: name,
                evidence: `Config.User: "${info.Config.User || '(empty)'}"`,
                remediation: 'Set a non-root USER in your Dockerfile',
                discoveredAt: new Date(),
            });
        }
        // Privileged mode
        if (info.HostConfig?.Privileged) {
            vulns.push({
                id: `DOCKER-PRIV-${id.slice(0, 12)}`,
                title: `Container "${name}" running in privileged mode`,
                description: 'Privileged containers have full access to host resources and can escape isolation',
                severity: 'critical',
                category: 'docker',
                target: name,
                evidence: 'HostConfig.Privileged: true',
                remediation: 'Remove --privileged flag. Use specific --cap-add flags instead.',
                discoveredAt: new Date(),
            });
        }
        // Host network mode
        if (info.HostConfig?.NetworkMode === 'host') {
            vulns.push({
                id: `DOCKER-NET-HOST-${id.slice(0, 12)}`,
                title: `Container "${name}" using host network`,
                description: 'Host network mode removes network isolation between container and host',
                severity: 'high',
                category: 'docker',
                target: name,
                evidence: 'HostConfig.NetworkMode: "host"',
                remediation: 'Use bridge network mode or a custom network',
                discoveredAt: new Date(),
            });
        }
        // Host PID namespace
        if (info.HostConfig?.PidMode === 'host') {
            vulns.push({
                id: `DOCKER-PID-HOST-${id.slice(0, 12)}`,
                title: `Container "${name}" sharing host PID namespace`,
                description: 'Host PID mode allows the container to see and interact with host processes',
                severity: 'high',
                category: 'docker',
                target: name,
                evidence: 'HostConfig.PidMode: "host"',
                remediation: 'Remove --pid=host flag unless absolutely necessary',
                discoveredAt: new Date(),
            });
        }
        // No memory limits
        if (!info.HostConfig?.Memory || info.HostConfig.Memory === 0) {
            vulns.push({
                id: `DOCKER-NO-MEM-${id.slice(0, 12)}`,
                title: `Container "${name}" has no memory limit`,
                description: 'Unlimited memory allows DoS via memory exhaustion',
                severity: 'medium',
                category: 'docker',
                target: name,
                evidence: `HostConfig.Memory: ${info.HostConfig?.Memory || 0}`,
                remediation: 'Set --memory flag to limit container memory usage',
                discoveredAt: new Date(),
            });
        }
        // No CPU limits
        if (!info.HostConfig?.CpuQuota || info.HostConfig.CpuQuota === 0) {
            vulns.push({
                id: `DOCKER-NO-CPU-${id.slice(0, 12)}`,
                title: `Container "${name}" has no CPU limit`,
                description: 'Unlimited CPU allows DoS via CPU exhaustion',
                severity: 'low',
                category: 'docker',
                target: name,
                evidence: `HostConfig.CpuQuota: ${info.HostConfig?.CpuQuota || 0}`,
                remediation: 'Set --cpus or --cpu-quota to limit container CPU usage',
                discoveredAt: new Date(),
            });
        }
        // Docker socket mounted
        const mounts = info.Mounts || [];
        for (const mount of mounts) {
            if (typeof mount === 'object' && 'Source' in mount && mount.Source === '/var/run/docker.sock') {
                vulns.push({
                    id: `DOCKER-SOCK-${id.slice(0, 12)}`,
                    title: `Container "${name}" has Docker socket mounted`,
                    description: 'Mounting the Docker socket gives the container full control over the Docker daemon',
                    severity: 'critical',
                    category: 'docker',
                    target: name,
                    evidence: `Mount: ${mount.Source} → ${mount.Destination}`,
                    remediation: 'Remove the Docker socket mount. Use the Docker API over TCP with TLS if needed.',
                    discoveredAt: new Date(),
                });
            }
        }
        // Read-only root filesystem not set
        if (!info.HostConfig?.ReadonlyRootfs) {
            vulns.push({
                id: `DOCKER-RW-${id.slice(0, 12)}`,
                title: `Container "${name}" has writable root filesystem`,
                description: 'A writable root filesystem allows attackers to modify container files',
                severity: 'medium',
                category: 'docker',
                target: name,
                evidence: 'HostConfig.ReadonlyRootfs: false',
                remediation: 'Add --read-only flag and use tmpfs mounts for writable directories',
                discoveredAt: new Date(),
            });
        }
    }
    async scanImage(imageName, vulns) {
        // Check for common image issues
        try {
            const image = docker.getImage(imageName);
            const info = await image.inspect();
            // Check image size (very large images may contain unnecessary packages)
            const sizeMB = (info.Size / 1024 / 1024).toFixed(0);
            if (info.Size > 1024 * 1024 * 1024) {
                vulns.push({
                    id: `DOCKER-IMG-SIZE-${imageName}`,
                    title: `Image "${imageName}" is very large (${sizeMB} MB)`,
                    description: 'Large images have a bigger attack surface and take longer to scan and deploy',
                    severity: 'low',
                    category: 'docker',
                    target: imageName,
                    evidence: `Size: ${sizeMB} MB`,
                    remediation: 'Use multi-stage builds and minimal base images (alpine, distroless)',
                    discoveredAt: new Date(),
                });
            }
            // Check for latest tag
            const tags = info.RepoTags || [];
            if (tags.some((t) => t.endsWith(':latest'))) {
                vulns.push({
                    id: `DOCKER-IMG-LATEST-${imageName}`,
                    title: `Image "${imageName}" uses "latest" tag`,
                    description: 'The "latest" tag is mutable and can introduce unexpected changes',
                    severity: 'low',
                    category: 'docker',
                    target: imageName,
                    evidence: `Tags: ${tags.join(', ')}`,
                    remediation: 'Pin to a specific version tag for reproducible builds',
                    discoveredAt: new Date(),
                });
            }
        }
        catch {
            vulns.push({
                id: `DOCKER-IMG-NOT-FOUND-${imageName}`,
                title: `Image "${imageName}" not found locally`,
                description: `Could not inspect image ${imageName}`,
                severity: 'info',
                category: 'docker',
                target: imageName,
                remediation: 'Pull the image first with docker pull',
                discoveredAt: new Date(),
            });
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
