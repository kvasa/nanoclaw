/**
 * Container runtime abstraction for NanoClaw.
 * All runtime-specific logic lives here so swapping runtimes means changing one file.
 */
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

const envConfig = readEnvFile(['CREDENTIAL_PROXY_HOST']);

/** The container runtime binary name. */
export const CONTAINER_RUNTIME_BIN = 'docker';

/** Hostname containers use to reach the host machine. */
export const CONTAINER_HOST_GATEWAY = 'host.docker.internal';

/**
 * Address the credential proxy binds to.
 * Docker Desktop (macOS): 127.0.0.1 — the VM routes host.docker.internal to loopback.
 * Docker (Linux): bind to the docker0 bridge IP so only containers can reach it,
 *   falling back to 0.0.0.0 if the interface isn't found.
 */
export const PROXY_BIND_HOST =
  process.env.CREDENTIAL_PROXY_HOST ||
  envConfig.CREDENTIAL_PROXY_HOST ||
  detectProxyBindHost();

/** Returns true when the Docker socket points to a rootless daemon. */
export function isRootlessDocker(): boolean {
  return (process.env.DOCKER_HOST ?? '').includes('/run/user/');
}

/**
 * For rootless Docker, find the host's first external (non-loopback, non-docker) IPv4.
 * Containers reach the host via slirp4netns NAT on this interface.
 */
function detectHostExternalIP(): string | null {
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    if (name === 'lo' || name.startsWith('docker') || name.startsWith('veth'))
      continue;
    const ipv4 = addrs.find((a) => a.family === 'IPv4' && !a.internal);
    if (ipv4) return ipv4.address;
  }
  return null;
}

function detectProxyBindHost(): string {
  if (os.platform() === 'darwin') return '127.0.0.1';

  // WSL uses Docker Desktop (same VM routing as macOS) — loopback is correct.
  // Check /proc filesystem, not env vars — WSL_DISTRO_NAME isn't set under systemd.
  if (fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop')) return '127.0.0.1';

  if (isRootlessDocker()) {
    // Rootless Docker runs in a separate network namespace (slirp4netns).
    // Containers can only reach the host via its external interface, not docker0.
    const hostIP = detectHostExternalIP();
    if (hostIP) return hostIP;
    console.warn(
      '[nanoclaw] WARNING: Could not detect host external IP for rootless Docker. ' +
        'Set CREDENTIAL_PROXY_HOST to your external IP, e.g.: CREDENTIAL_PROXY_HOST=203.0.113.1',
    );
    return '0.0.0.0';
  }

  // Root Docker: bind to the docker0 bridge IP instead of 0.0.0.0
  const ifaces = os.networkInterfaces();
  const docker0 = ifaces['docker0'];
  if (docker0) {
    const ipv4 = docker0.find((a) => a.family === 'IPv4');
    if (ipv4) return ipv4.address;
  }
  console.warn(
    '[nanoclaw] WARNING: docker0 interface not found. Credential proxy will bind to 127.0.0.1 ' +
      '(loopback only) — containers will NOT be able to reach it. ' +
      'Set CREDENTIAL_PROXY_HOST to your Docker bridge IP, e.g.: ' +
      'CREDENTIAL_PROXY_HOST=172.17.0.1\n' +
      'Find it with: docker network inspect bridge --format "{{range .IPAM.Config}}{{.Gateway}}{{end}}"',
  );
  return '127.0.0.1';
}

/** CLI args needed for the container to resolve the host gateway. */
export function hostGatewayArgs(): string[] {
  // On Linux, host.docker.internal isn't built-in — add it explicitly.
  if (os.platform() === 'linux') {
    if (isRootlessDocker()) {
      // In rootless Docker, `host-gateway` resolves to the rootlesskit bridge (172.17.0.1),
      // not the actual host. Use PROXY_BIND_HOST directly so containers can reach the host
      // via slirp4netns through the external interface.
      return [`--add-host=host.docker.internal:${PROXY_BIND_HOST}`];
    }
    return ['--add-host=host.docker.internal:host-gateway'];
  }
  return [];
}

/** Returns CLI args for a readonly bind mount. */
export function readonlyMountArgs(
  hostPath: string,
  containerPath: string,
): string[] {
  return ['-v', `${hostPath}:${containerPath}:ro`];
}

/** Returns the args to stop a container by name (safe, no shell interpolation). */
export function stopContainerArgs(name: string): string[] {
  return [CONTAINER_RUNTIME_BIN, 'stop', name];
}

/** Ensure the container runtime is running, starting it if needed. */
export function ensureContainerRuntimeRunning(): void {
  try {
    execFileSync(CONTAINER_RUNTIME_BIN, ['info'], {
      stdio: 'pipe',
      timeout: 10000,
    });
    logger.debug('Container runtime already running');
  } catch (err) {
    logger.error({ err }, 'Failed to reach container runtime');
    console.error(
      '\n╔════════════════════════════════════════════════════════════════╗',
    );
    console.error(
      '║  FATAL: Container runtime failed to start                      ║',
    );
    console.error(
      '║                                                                ║',
    );
    console.error(
      '║  Agents cannot run without a container runtime. To fix:        ║',
    );
    console.error(
      '║  1. Ensure Docker is installed and running                     ║',
    );
    console.error(
      '║  2. Run: docker info                                           ║',
    );
    console.error(
      '║  3. Restart NanoClaw                                           ║',
    );
    console.error(
      '╚════════════════════════════════════════════════════════════════╝\n',
    );
    throw new Error('Container runtime is required but failed to start', {
      cause: err,
    });
  }
}

/** Kill orphaned NanoClaw containers from previous runs. */
export function cleanupOrphans(): void {
  try {
    const output = execFileSync(
      CONTAINER_RUNTIME_BIN,
      ['ps', '--filter', 'name=nanoclaw-', '--format', '{{.Names}}'],
      { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' },
    );
    const orphans = output.trim().split('\n').filter(Boolean);
    for (const name of orphans) {
      try {
        const [bin, ...args] = stopContainerArgs(name);
        execFileSync(bin, args, { stdio: 'pipe' });
      } catch {
        /* already stopped */
      }
    }
    if (orphans.length > 0) {
      logger.info(
        { count: orphans.length, names: orphans },
        'Stopped orphaned containers',
      );
    }
  } catch (err) {
    logger.warn({ err }, 'Failed to clean up orphaned containers');
  }
}
