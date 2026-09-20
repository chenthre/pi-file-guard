/**
 * sandbox-process.ts — unified sandboxed subprocess execution (v2 Gate 2).
 *
 * bash, find (fd) and grep (rg) all execute through the same primitive:
 *
 *   PermissionSnapshot
 *         │
 *         ▼
 *   compileSandboxArgs(snapshot)   (bwrap.ts — the single filesystem policy)
 *         │
 *         ▼
 *   spawn(bwrap) ──┐
 *                  ├── command tree inside one mount namespace
 *                  ├── kill() → namespace init death → whole tree dies
 *                  └── exitCode promise
 *
 * Consumers never construct their own filesystem policy — only their own
 * argv/stdio/limits/timeout wrapper around this module.
 */

import { type ChildProcess, spawn } from "node:child_process";
import type { Readable } from "node:stream";
import { BWRAP_BIN, BwrapError, compileSandboxArgs } from "./bwrap.ts";
import type { PermissionSnapshot } from "./state.ts";

const PERMISSION_NOISE =
	/permission denied|eacces|not permitted|operation not permitted|read-only file system|i\/o error/i;
const SANDBOX_FAILURE =
	/bwrap:|failed to (spawn|mount|create)|cannot create|error creating sandbox|no such file or directory while (mounting|creating)/i;

/**
 * Classify search stderr: permission noise (expected for DENY subtrees) is
 * benign; anything that smells like a sandbox construction failure makes the
 * whole stderr non-benign — sandbox failures are never swallowed (v2 §5.11).
 */
export function stderrIsBenignSearchNoise(stderr: string): boolean {
	const lines = stderr
		.split("\n")
		.map((l) => l.trim())
		.filter(Boolean);
	if (lines.length === 0) return true;
	return lines.every((line) => !SANDBOX_FAILURE.test(line) && PERMISSION_NOISE.test(line));
}

/** Extract a bwrap construction-failure message from stderr, or null. */
export function sandboxFailureMarker(stderr: string): string | null {
	const line = stderr
		.split("\n")
		.map((l) => l.trim())
		.find((l) => SANDBOX_FAILURE.test(l));
	return line ?? null;
}

export interface SandboxLaunchOptions {
	/** bwrap mount arguments (before `--`), from compileSandboxArgs(). */
	sandboxArgs: string[];
	/** Executable + arguments to run after `--` inside the sandbox. */
	commandArgv: string[];
	cwd: string;
	env?: NodeJS.ProcessEnv;
	detached?: boolean;
}

export interface SandboxedProcess {
	readonly pid: number | undefined;
	readonly stdout: Readable;
	readonly stderr: Readable;
	/** Kill the whole namespace (bwrap is PID 1 of it; SIGKILL is instant teardown). */
	kill(signal?: NodeJS.Signals): void;
	/** Resolves with the exit code after close (null when killed). */
	readonly exitCode: Promise<number | null>;
	/** Set when the process already exited. */
	readonly exited: boolean;
}

/**
 * Start one bwrap sandbox. Streams are exposed so adapters can readline
 * stdout (fd/rg) and classify stderr; kill() tears down the namespace.
 */
export function startSandboxedProcess(options: SandboxLaunchOptions): SandboxedProcess {
	const argv = [...options.sandboxArgs, "--", ...options.commandArgv];
	let exitResolve!: (code: number | null) => void;
	const exitCode = new Promise<number | null>((resolve) => {
		exitResolve = resolve;
	});
	let exited = false;

	let child: ChildProcess;
	try {
		child = spawn(BWRAP_BIN, argv, {
			cwd: options.cwd,
			env: options.env ?? process.env,
			stdio: ["ignore", "pipe", "pipe"],
			detached: options.detached ?? true,
			windowsHide: true,
		});
	} catch (err) {
		throw new BwrapError(`Failed to spawn bubblewrap: ${(err as Error).message}`);
	}

	child.on("error", (err) => {
		// Resolve instead of reject: consumers treat a failed spawn like a
		// sandbox construction failure and read stderr/exitCode to decide
		// (fail closed). An 'error' event is always followed by 'close'.
		exited = true;
		exitResolve(-2);
		void err;
	});
	child.on("close", (code) => {
		exited = true;
		exitResolve(code);
	});

	return {
		pid: child.pid,
		stdout: child.stdout as Readable,
		stderr: child.stderr as Readable,
		kill: (signal: NodeJS.Signals = "SIGKILL") => {
			if (!child.pid) return;
			try {
				process.kill(child.pid, signal);
			} catch {
				// already gone
			}
		},
		exitCode,
		get exited() {
			return exited;
		},
	};
}

export interface RunSandboxedOptions {
	sandboxArgs: string[];
	commandArgv: string[];
	cwd: string;
	env?: NodeJS.ProcessEnv;
	/** Combined stdout+stderr stream (bash-style). */
	onData?: (chunk: Buffer) => void;
	signal?: AbortSignal;
	timeoutMs?: number;
}

/**
 * Run a sandboxed command to completion with timeouts/abort handled for the
 * caller. Rejects with Error("aborted") / Error("timeout") mirroring the
 * built-in bash operations contract.
 */
export async function runSandboxedProcess(options: RunSandboxedOptions): Promise<{ exitCode: number | null }> {
	const proc = startSandboxedProcess({
		sandboxArgs: options.sandboxArgs,
		commandArgv: options.commandArgv,
		cwd: options.cwd,
		env: options.env,
	});

	proc.stdout.on("data", options.onData ?? (() => {}));
	proc.stderr.on("data", options.onData ?? (() => {}));

	let timedOut = false;
	let timeoutHandle: NodeJS.Timeout | undefined;
	if (options.timeoutMs !== undefined && options.timeoutMs > 0) {
		timeoutHandle = setTimeout(() => {
			timedOut = true;
			proc.kill("SIGKILL");
		}, options.timeoutMs);
	}
	const onAbort = () => proc.kill("SIGKILL");
	if (options.signal) {
		if (options.signal.aborted) onAbort();
		else options.signal.addEventListener("abort", onAbort, { once: true });
	}

	try {
		const code = await proc.exitCode;
		if (options.signal?.aborted) throw new Error("aborted");
		if (timedOut) throw new Error("timeout");
		if (code === -2) {
			throw new BwrapError("bubblewrap failed to start (spawn error)");
		}
		return { exitCode: code };
	} finally {
		if (timeoutHandle) clearTimeout(timeoutHandle);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

/**
 * Bash backend for the overridden bash tool: compile the current policy
 * snapshot and run /bin/bash -c COMMAND inside it. Bash operations contract:
 * rejects with "aborted" or `timeout:${seconds}` like the built-in backend.
 */
export async function runGuardedBash(options: {
	command: string;
	cwd: string;
	env?: NodeJS.ProcessEnv;
	onData: (chunk: Buffer) => void;
	signal?: AbortSignal;
	timeout?: number; // seconds
	snapshot: PermissionSnapshot;
}): Promise<{ exitCode: number | null }> {
	// Fail closed if the sandbox cannot even be compiled (missing bwrap,
	// unmaskable targets, ...) — never fall back to an unsandboxed shell.
	const { sandboxArgs } = await compileSandboxArgs(options.snapshot);
	const timeoutSeconds = options.timeout;
	try {
		const result = await runSandboxedProcess({
			sandboxArgs,
			commandArgv: ["/bin/bash", "-c", options.command],
			cwd: options.cwd,
			env: options.env,
			onData: options.onData,
			signal: options.signal,
			timeoutMs: timeoutSeconds !== undefined && timeoutSeconds > 0 ? timeoutSeconds * 1000 : undefined,
		});
		return result;
	} catch (err) {
		if (err instanceof Error && err.message === "timeout") {
			throw new Error(`timeout:${timeoutSeconds ?? 0}`);
		}
		throw err;
	}
}
