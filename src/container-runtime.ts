/**
 * Container runtime abstraction for NanoClaw.
 * All runtime-specific logic lives here so swapping runtimes means changing one file.
 */
import { execFileSync, execSync } from 'child_process';
import fs from 'fs';
import os from 'os';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

const envConfig = readEnvFile(['CREDENTIAL_PROXY_HOST', 'CONTAINER_NETWORK']);

/** The container runtime binary name. */
export const CONTAINER_RUNTIME_BIN = 'docker';

/** Hostname containers use to reach the host machine. */
export const CONTAINER_HOST_GATEWAY = 'host.docker.internal';

/**
 * Dedicated Docker network NanoClaw containers run on. Overridable via
 * CONTAINER_NETWORK (env / .env), following the CREDENTIAL_PROXY_HOST
 * pattern. Isolates NanoClaw containers from unrelated containers on the
 * host's default bridge — the credential proxy binds to this network's
 * gateway (bare-metal Linux) instead of the shared docker0 bridge.
 */
export const CONTAINER_NETWORK =
  process.env.CONTAINER_NETWORK || envConfig.CONTAINER_NETWORK || 'nanoclaw';

/**
 * True on platforms where Docker runs inside a VM and routes
 * host.docker.internal to loopback automatically (Docker Desktop): macOS,
 * and WSL (which also uses Docker Desktop under the hood).
 */
function isDockerDesktopLoopbackPlatform(): boolean {
  if (os.platform() === 'darwin') return true;
  // Check /proc filesystem, not env vars — WSL_DISTRO_NAME isn't set under systemd.
  if (fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop')) return true;
  return false;
}

/**
 * Ensure the dedicated NanoClaw Docker network exists, creating it if
 * necessary. Docker-only — Apple Container has no equivalent concept, so
 * this is a no-op there (mirrors the --pids-limit Docker-only pattern in
 * resourceLimitArgs).
 */
export function ensureContainerNetwork(): void {
  if (CONTAINER_RUNTIME_BIN !== 'docker') {
    logger.debug('Skipping container network setup on non-docker runtime');
    return;
  }
  try {
    execFileSync('docker', ['network', 'inspect', CONTAINER_NETWORK], {
      stdio: 'pipe',
    });
  } catch {
    try {
      execFileSync('docker', ['network', 'create', CONTAINER_NETWORK], {
        stdio: 'pipe',
      });
      logger.info(
        { network: CONTAINER_NETWORK },
        'Created dedicated container network',
      );
    } catch (err) {
      logger.warn(
        { err, network: CONTAINER_NETWORK },
        'Failed to create dedicated container network',
      );
    }
  }
}

/**
 * Returns the gateway IP of the dedicated container network, or undefined
 * if it can't be determined (network missing, docker unavailable, etc).
 */
export function containerNetworkGateway(): string | undefined {
  try {
    const output = execFileSync(
      'docker',
      [
        'network',
        'inspect',
        CONTAINER_NETWORK,
        '--format',
        '{{(index .IPAM.Config 0).Gateway}}',
      ],
      { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' },
    );
    const gateway = output.trim();
    return gateway || undefined;
  } catch (err) {
    logger.warn(
      { err, network: CONTAINER_NETWORK },
      'Failed to determine dedicated container network gateway',
    );
    return undefined;
  }
}

interface ProxyBindResolution {
  host: string;
  /**
   * true  => hostGatewayArgs() must use `host` explicitly, because Docker's
   *          `host-gateway` magic value would NOT resolve to it (it resolves
   *          to the daemon's host-gateway-ip, which defaults to docker0).
   * false => `host` already coincides with what `host-gateway` resolves to
   *          (docker0), or Docker Desktop routing is in play — prefer the
   *          magic value for extra robustness (unchanged from prior behavior).
   */
  explicit: boolean;
}

let memoizedResolution: ProxyBindResolution | undefined;

/**
 * Resolves (once, memoized) both the address the credential proxy binds to
 * AND whether hostGatewayArgs() needs to spell that address out explicitly.
 * Single source of truth so the proxy bind IP and the container's
 * host.docker.internal add-host entry can never drift apart — see plan 023.
 */
function resolveProxyBind(): ProxyBindResolution {
  if (memoizedResolution) return memoizedResolution;

  const override =
    process.env.CREDENTIAL_PROXY_HOST || envConfig.CREDENTIAL_PROXY_HOST;
  if (override) {
    memoizedResolution = { host: override, explicit: true };
    return memoizedResolution;
  }

  if (isDockerDesktopLoopbackPlatform()) {
    memoizedResolution = { host: '127.0.0.1', explicit: false };
    return memoizedResolution;
  }

  // Bare-metal Linux: prefer the dedicated network's gateway so the proxy
  // is reachable only by NanoClaw containers, not every container on the
  // host's default bridge.
  ensureContainerNetwork();
  const networkGateway = containerNetworkGateway();
  if (networkGateway) {
    memoizedResolution = { host: networkGateway, explicit: true };
    return memoizedResolution;
  }

  // Fall back to the docker0 bridge IP instead of 0.0.0.0
  const ifaces = os.networkInterfaces();
  const docker0 = ifaces['docker0'];
  if (docker0) {
    const ipv4 = docker0.find((a) => a.family === 'IPv4');
    if (ipv4) {
      memoizedResolution = { host: ipv4.address, explicit: false };
      return memoizedResolution;
    }
  }

  console.warn(
    '[nanoclaw] WARNING: docker0 interface not found. Credential proxy will bind to 127.0.0.1 ' +
      '(loopback only) — containers will NOT be able to reach it. ' +
      'Set CREDENTIAL_PROXY_HOST to your Docker bridge IP, e.g.: ' +
      'CREDENTIAL_PROXY_HOST=172.17.0.1\n' +
      'Find it with: docker network inspect bridge --format "{{range .IPAM.Config}}{{.Gateway}}{{end}}"',
  );
  memoizedResolution = { host: '127.0.0.1', explicit: false };
  return memoizedResolution;
}

/**
 * Address the credential proxy binds to.
 * Docker Desktop (macOS/WSL): 127.0.0.1 — the VM routes host.docker.internal to loopback.
 * Docker (Linux): bind to the dedicated container network's gateway so only
 *   NanoClaw containers can reach it, falling back to the docker0 bridge IP,
 *   then loopback (with a warning), if the network gateway can't be found.
 * Computed lazily (not at module load) and memoized — see resolveProxyBind().
 */
export function proxyBindHost(): string {
  return resolveProxyBind().host;
}

/** CLI args needed for the container to resolve the host gateway. */
export function hostGatewayArgs(): string[] {
  // On Linux, host.docker.internal isn't built-in — add it explicitly
  if (os.platform() !== 'linux') return [];

  if (isDockerDesktopLoopbackPlatform()) {
    return ['--add-host=host.docker.internal:host-gateway'];
  }

  const { host, explicit } = resolveProxyBind();
  if (explicit) {
    return [`--add-host=host.docker.internal:${host}`];
  }
  return ['--add-host=host.docker.internal:host-gateway'];
}

/** Returns CLI args for a readonly bind mount. */
export function readonlyMountArgs(
  hostPath: string,
  containerPath: string,
): string[] {
  return ['-v', `${hostPath}:${containerPath}:ro`];
}

/**
 * Returns CLI args capping a container's resources. Empty values disable the
 * corresponding limit. `--pids-limit` is Docker-only — Apple Container has no
 * equivalent flag, so it is omitted on that runtime.
 */
export function resourceLimitArgs(limits: {
  memory?: string;
  cpus?: string;
  pidsLimit?: string;
}): string[] {
  const args: string[] = [];
  if (limits.memory) args.push('--memory', limits.memory);
  if (limits.cpus) args.push('--cpus', limits.cpus);
  if (limits.pidsLimit && CONTAINER_RUNTIME_BIN === 'docker') {
    args.push('--pids-limit', limits.pidsLimit);
  }
  return args;
}

/** Returns the args to stop a container by name (safe, no shell interpolation). */
export function stopContainerArgs(name: string): string[] {
  return [CONTAINER_RUNTIME_BIN, 'stop', name];
}

/** Returns the shell command to stop a container by name. */
export function stopContainer(name: string): string {
  return `${CONTAINER_RUNTIME_BIN} stop "${name}"`;
}

/** Ensure the container runtime is running, starting it if needed. */
export function ensureContainerRuntimeRunning(): void {
  try {
    execSync(`${CONTAINER_RUNTIME_BIN} info`, {
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
    throw new Error('Container runtime is required but failed to start');
  }
}

/** Kill orphaned NanoClaw containers from previous runs. */
export function cleanupOrphans(): void {
  try {
    const output = execSync(
      `${CONTAINER_RUNTIME_BIN} ps --filter name=nanoclaw- --format '{{.Names}}'`,
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
